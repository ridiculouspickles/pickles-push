package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ridiculouspickles/pickles-push/internal/apns"
	"github.com/ridiculouspickles/pickles-push/internal/store"
)

// fakeTimers is a clock and a scheduler that move only when a test says so, so a thirty
// second window costs no thirty seconds and no test depends on how busy the machine is.
type fakeTimers struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped bool
	fired   bool
}

func newFakeTimers() *fakeTimers {
	return &fakeTimers{now: time.Unix(1_700_000_000, 0)}
}

func (c *fakeTimers) clock() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeTimers) after(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, timer)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if timer.fired || timer.stopped {
			return false
		}
		timer.stopped = true
		return true
	}
}

// advance moves the clock and runs every timer that falls due, in order, including any
// a firing timer schedules within the span.
func (c *fakeTimers) advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	for {
		var next *fakeTimer
		for _, timer := range c.timers {
			if timer.fired || timer.stopped || timer.at.After(target) {
				continue
			}
			if next == nil || timer.at.Before(next.at) {
				next = timer
			}
		}
		if next == nil {
			break
		}
		next.fired = true
		c.now = next.at
		c.mu.Unlock()
		next.f()
		c.mu.Lock()
	}
	c.now = target
	c.mu.Unlock()
}

func (c *fakeTimers) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, timer := range c.timers {
		if !timer.fired && !timer.stopped {
			n++
		}
	}
	return n
}

const testWindow = 30 * time.Second

func newCoalescingRelay(t *testing.T) (*Relay, *recordingPusher, *fakeTimers) {
	t.Helper()
	r, pusher := newRelay(t)
	timers := newFakeTimers()
	r.Now = timers.clock
	r.after = timers.after
	r.SilentWindow = testWindow
	return r, pusher, timers
}

func registerDevice(t *testing.T, r *Relay, device, mode string) string {
	t.Helper()
	return register(t, r, `{"deviceToken":"`+device+`","topic":"net.pickles.mail.dev",`+
		`"sandbox":true,"mode":"`+mode+`"}`).Token
}

const (
	deviceA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	deviceB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func jmapPush(t *testing.T, r *Relay, token, body string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/push/"+token, strings.NewReader(body))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		// Held or not, the provider is told 200: holding is not refusing.
		t.Fatalf("push returned %d", recorder.Code)
	}
}

// opened is the provider's payload out of an APNs body.
func opened(t *testing.T, n apns.Notification) string {
	t.Helper()
	var body struct {
		P string `json:"p"`
	}
	if err := json.Unmarshal(n.Payload, &body); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.P)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// past the window in which a JMAP push is never held, so the coalescer is what is tested.
func settleRegistration(timers *fakeTimers) { timers.advance(freshRegistration + time.Second) }

func TestALoneSilentPushGoesOutAtOnce(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "background")
	settleRegistration(timers)

	jmapPush(t, r, token, "s1")
	settle(t, r)
	sent := pusher.all()
	if len(sent) != 1 || !sent[0].Background || opened(t, sent[0]) != "s1" {
		t.Fatalf("the leading push must go at once, and silently: %+v", sent)
	}

	// Nothing held, so the window closes on nothing and forgets the slot — no timer
	// outlives a registration that has gone quiet.
	timers.advance(testWindow)
	settle(t, r)
	if n := len(pusher.all()); n != 1 {
		t.Fatalf("a window with nothing held sent %d pushes, want 1", n)
	}
	if r.silent.open() != 0 || timers.pending() != 0 {
		t.Fatalf("a quiet registration still holds %d slots and %d timers",
			r.silent.open(), timers.pending())
	}
}

func TestABurstIsTheFirstAndTheNewest(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "background")
	settleRegistration(timers)

	for _, state := range []string{"s1", "s2", "s3", "s4", "s5"} {
		jmapPush(t, r, token, state)
		timers.advance(time.Second)
	}
	settle(t, r)
	if sent := pusher.all(); len(sent) != 1 || opened(t, sent[0]) != "s1" {
		t.Fatalf("inside the window only the leading push goes: %+v", sent)
	}

	timers.advance(testWindow)
	settle(t, r)
	sent := pusher.all()
	if len(sent) != 2 {
		t.Fatalf("a burst of five sent %d pushes, want the first and one trailing", len(sent))
	}
	if got := opened(t, sent[1]); got != "s5" {
		t.Fatalf("the trailing push carried %q, want the newest, s5", got)
	}
	if !sent[1].Background || sent[1].DeviceToken != deviceA {
		t.Fatalf("the trailing push went somewhere else: %+v", sent[1])
	}

	// The trailing push opened a window of its own; it closes on nothing.
	timers.advance(testWindow)
	settle(t, r)
	if n := len(pusher.all()); n != 2 {
		t.Fatalf("sent %d pushes after the burst had ended, want 2", n)
	}
	if r.silent.open() != 0 || timers.pending() != 0 {
		t.Fatal("the slot outlived the burst")
	}
}

// The trailing push opens the next window, so a change arriving just after it is held
// in turn rather than sent back to back.
func TestTheTrailingPushOpensTheNextWindow(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "background")
	settleRegistration(timers)

	jmapPush(t, r, token, "s1")
	jmapPush(t, r, token, "s2")
	timers.advance(testWindow)
	jmapPush(t, r, token, "s3")
	settle(t, r)
	if n := len(pusher.all()); n != 2 {
		t.Fatalf("sent %d, want s1 and s2 with s3 held", n)
	}
	timers.advance(testWindow)
	settle(t, r)
	sent := pusher.all()
	if len(sent) != 3 || opened(t, sent[2]) != "s3" {
		t.Fatalf("s3 was lost: %+v", sent)
	}
}

func TestAnAlertPushIsNeverHeld(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "alert")
	settleRegistration(timers)

	for _, state := range []string{"s1", "s2", "s3", "s4", "s5"} {
		jmapPush(t, r, token, state)
	}
	settle(t, r)
	sent := pusher.all()
	if len(sent) != 5 {
		t.Fatalf("five alert pushes sent %d at once; news must not wait", len(sent))
	}
	for _, n := range sent {
		if n.Background {
			t.Fatal("an alert push went out silently")
		}
	}
	if r.silent.open() != 0 {
		t.Fatal("an alert push opened a window")
	}
}

func TestRegistrationsAreCoalescedApart(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	first := registerDevice(t, r, deviceA, "background")
	second := registerDevice(t, r, deviceB, "background")
	settleRegistration(timers)

	jmapPush(t, r, first, "a1")
	jmapPush(t, r, second, "b1")
	jmapPush(t, r, first, "a2")
	jmapPush(t, r, second, "b2")
	settle(t, r)
	if n := len(pusher.all()); n != 2 {
		t.Fatalf("one device's window held another's leading push: sent %d, want 2", n)
	}

	timers.advance(testWindow)
	settle(t, r)
	got := map[string][]string{}
	for _, n := range pusher.all() {
		got[n.DeviceToken] = append(got[n.DeviceToken], opened(t, n))
	}
	for device, want := range map[string][]string{
		deviceA: {"a1", "a2"}, deviceB: {"b1", "b2"},
	} {
		if strings.Join(got[device], ",") != strings.Join(want, ",") {
			t.Fatalf("device %s… got %v, want %v", device[:4], got[device], want)
		}
	}
}

// One registration, two Gmail mailboxes: each is its own slot, because the device syncs
// only the account a push names, and one account's historyId standing in for the
// other's would leave that one unsynced.
func TestGmailMailboxesOnOneRegistrationAreCoalescedApart(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "alert")
	held, err := r.Store.Get(token)
	if err != nil {
		t.Fatal(err)
	}
	work, personal := "gmail\x00work@gmail.com", "gmail\x00personal@gmail.com"

	// A Gmail push is silent even on an alert registration, and so it is coalesced —
	// and a fresh registration does not exempt it: verifications are JMAP's alone.
	r.enqueueSilently(held, []byte("w1"), true, work)
	r.enqueueSilently(held, []byte("p1"), true, personal)
	r.enqueueSilently(held, []byte("w2"), true, work)
	r.enqueueSilently(held, []byte("w3"), true, work)
	settle(t, r)
	if n := len(pusher.all()); n != 2 {
		t.Fatalf("sent %d, want each mailbox's leading push", n)
	}
	timers.advance(testWindow)
	settle(t, r)
	var got []string
	for _, n := range pusher.all() {
		if !n.Background {
			t.Fatal("a Gmail push raised a banner")
		}
		got = append(got, opened(t, n))
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "p1,w1,w3" {
		t.Fatalf("got %v, want p1 and w1 at once and w3 trailing", got)
	}
}

// PushVerification comes down the JMAP path, one per account, seconds after the device
// registers. The relay cannot tell one from a StateChange, and newest-wins would keep
// one code and lose the rest — so nothing is held that soon after a registration.
func TestJMAPPushesJustAfterRegistrationAreNotHeld(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "background")
	timers.advance(time.Second)

	for _, code := range []string{"v1", "v2", "v3"} {
		jmapPush(t, r, token, code)
	}
	settle(t, r)
	if n := len(pusher.all()); n != 3 {
		t.Fatalf("verification codes were coalesced: sent %d of 3", n)
	}
}

// Shutdown flushes: a held push is the newest state for its slot and the provider was
// told 200 for it.
func TestCloseFlushesWhatIsHeld(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "background")
	settleRegistration(timers)

	jmapPush(t, r, token, "s1")
	jmapPush(t, r, token, "s2")
	r.Close()
	r.WaitForDeliveries()
	sent := pusher.all()
	if len(sent) != 2 || opened(t, sent[1]) != "s2" {
		t.Fatalf("the held push was not flushed at shutdown: %+v", sent)
	}
	if timers.pending() != 0 {
		t.Fatal("a window's timer survived shutdown")
	}
	// And a timer that fires after the flush sends nothing twice.
	timers.advance(testWindow)
	if n := len(pusher.all()); n != 2 {
		t.Fatalf("sent %d after shutdown, want 2", n)
	}
}

// A trailing push is up to a window old. If Apple reported the device gone meanwhile,
// the row is gone, and the push goes nowhere.
func TestAHeldPushForAGoneRegistrationIsDropped(t *testing.T) {
	r, pusher, timers := newCoalescingRelay(t)
	token := registerDevice(t, r, deviceA, "background")
	settleRegistration(timers)

	jmapPush(t, r, token, "s1")
	jmapPush(t, r, token, "s2")
	settle(t, r)
	if err := r.Store.Delete(token); err != nil {
		t.Fatal(err)
	}
	timers.advance(testWindow)
	settle(t, r)
	if n := len(pusher.all()); n != 1 {
		t.Fatalf("pushed %d times to a registration that had gone, want only the first", n)
	}
	timers.advance(testWindow)
	if r.silent.open() != 0 || timers.pending() != 0 {
		t.Fatal("a gone registration kept its slot")
	}
}

// Real timers, many goroutines: what the race detector is for. The count is exact
// because every push lands well inside one window.
func TestCoalescingUnderConcurrency(t *testing.T) {
	r, pusher := newRelay(t)
	r.SilentWindow = 300 * time.Millisecond
	registration := store.Registration{
		Token: "concurrent-token", DeviceToken: deviceA, Topic: "net.pickles.mail.dev",
		Mode: store.Background,
	}
	if err := r.Store.Put(registration); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.enqueueSilently(registration, []byte("x"), true, "gmail\x00a@gmail.com")
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for r.silent.open() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	settle(t, r)
	if r.silent.open() != 0 {
		t.Fatal("the slot never closed")
	}
	if n := len(pusher.all()); n != 2 {
		t.Fatalf("fifty concurrent pushes sent %d, want the leading one and one trailing", n)
	}
}

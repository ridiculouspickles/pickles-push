package relay

import (
	"sync"
	"time"

	"github.com/ridiculouspickles/pickles-push/internal/store"
)

// Coalescing silent pushes, and why a relay that forwards opaque bytes may do it.
//
// **iOS rations background pushes.** A `content-available` push is throttled per app per
// hour, and the budget is not ours to see. The background site hears Fastmail's `Email`
// StateChange, which fires on every read, flag and move — ten messages read in Fastmail's
// web client is ten pushes — and every Gmail Pub/Sub message is sent silently
// (pickles-email#581), where a read is a push too. A burst spends the budget on wake-ups
// that each say "sync again", and the one that says something new can be the one iOS
// declines.
//
// So a background push is held when another went to the same place moments ago:
//
//   - the **leading edge** goes out at once, so a lone change costs no latency;
//   - anything arriving in the next window is held, and each arrival **replaces** what
//     was held;
//   - when the window closes, the held push — the newest — goes out, and opens a window
//     of its own. A window that closes with nothing held forgets the slot.
//
// A burst of N becomes at most one push per window, plus the first, and the last change
// always arrives. Sending the newest is correct because the payload carries state (a JMAP
// StateChange's state strings, Gmail's historyId) and the device syncs *to now*, not *to
// the payload*: a wake-up that names a state it has already reached is one it skips.
//
// **An alert push is never held.** It is news, and news that waits thirty seconds is
// late news. Only a push that goes out as `content-available` passes through here.
//
// **What a slot is keyed by matters, because the device syncs only what a push names**
// (pickles-email#668). On Gmail the relay knows the address, so each mailbox on a
// registration is its own slot, and one account's newer historyId cannot supersede
// another's. On JMAP it knows nothing — the body is ciphertext and one delivery token
// serves every JMAP account on the device — so the slot is the registration. Two
// accounts changing inside one window therefore lose the earlier account's wake-up; it
// is synced at the next push that names it, the next foreground, or the next scheduled
// refresh, and the alert site, which is not coalesced, still raises its banner. See
// freshRegistration for the one JMAP payload that must not be lost.

// DefaultSilentWindow is how long a background push to one place holds the next one.
//
// Thirty seconds covers a burst of reads in a web client, and is short against the
// hour Apple keeps a background push for.
const DefaultSilentWindow = 30 * time.Second

// freshRegistration is how long after a (re-)registration a JMAP push bypasses the
// coalescer.
//
// **Because PushVerification comes down the same path, and is not state.** The device
// registers, then creates a subscription per JMAP account, and each server POSTs a
// verification code to the same delivery token within a second or two. The relay cannot
// tell a verification from a StateChange, and the newest-wins rule that is right for
// state would throw all but one code away — leaving the other accounts' subscriptions
// unconfirmed, and silent, for good. A device re-registers on every foreground and when
// it makes subscriptions, so pushes this soon after one are the verifications, or
// arrive while the app is in use; neither is what the budget needs protecting from.
const freshRegistration = 2 * time.Minute

// scheduler runs f after d, and returns a stop that reports whether it prevented the run.
// time.AfterFunc in production; the tests' fake clock otherwise.
type scheduler func(d time.Duration, f func()) (stop func() bool)

func realScheduler(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// heldPush is what waits for its window to close.
type heldPush struct {
	registration store.Registration
	payload      []byte
}

// silentSlot is one open window.
type silentSlot struct {
	held *heldPush
	stop func() bool
}

type coalescer struct {
	window time.Duration
	after  scheduler
	// send is where a push goes when it is not held: the delivery queue, eventually.
	// Called without mu held — it takes the queue's lock, and a held lock across it
	// would order the two locks for no reason.
	send func(key string, push heldPush)

	mu     sync.Mutex
	slots  map[string]*silentSlot
	closed bool
}

func newCoalescer(window time.Duration, after scheduler, send func(string, heldPush)) *coalescer {
	if after == nil {
		after = realScheduler
	}
	return &coalescer{window: window, after: after, send: send, slots: map[string]*silentSlot{}}
}

// offer sends a push now if its slot is quiet, and holds it — replacing whatever was
// held — if the slot's window is open. It reports whether the push was held.
func (c *coalescer) offer(key string, push heldPush) bool {
	c.mu.Lock()
	if c.closed {
		// Shutting down: nothing may be held past the flush. Send it and let the queue,
		// which is closed too, say it was dropped.
		c.mu.Unlock()
		c.send(key, push)
		return false
	}
	if slot, open := c.slots[key]; open {
		slot.held = &push
		c.mu.Unlock()
		return true
	}
	c.slots[key] = &silentSlot{stop: c.after(c.window, func() { c.expire(key) })}
	c.mu.Unlock()
	c.send(key, push)
	return false
}

// expire closes a window. What was held goes out and opens the next one; a window with
// nothing held forgets its slot, which is what keeps a registration that has gone quiet
// — or gone altogether — from holding a timer.
func (c *coalescer) expire(key string) {
	c.mu.Lock()
	slot, open := c.slots[key]
	if c.closed || !open {
		// Flushed already; the flush sent whatever this would have.
		c.mu.Unlock()
		return
	}
	if slot.held == nil {
		delete(c.slots, key)
		c.mu.Unlock()
		return
	}
	push := *slot.held
	slot.held = nil
	slot.stop = c.after(c.window, func() { c.expire(key) })
	c.mu.Unlock()
	c.send(key, push)
}

// flush stops every window and sends what was held, now.
//
// **Flushed, not dropped.** The provider was answered 200 for each of these, and a held
// push is by construction the newest state for its slot — the one a device would
// otherwise never be told about until something else changed. Sending it a few seconds
// early costs one wake-up; dropping it costs the last change of the burst. Call it
// before the delivery queue closes, so what it sends is still accepted.
func (c *coalescer) flush() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	type pending struct {
		key  string
		push heldPush
	}
	var out []pending
	for key, slot := range c.slots {
		slot.stop()
		if slot.held != nil {
			out = append(out, pending{key, *slot.held})
		}
	}
	c.slots = map[string]*silentSlot{}
	c.mu.Unlock()
	for _, p := range out {
		c.send(p.key, p.push)
	}
}

// open reports how many slots have a window open. For tests: it is the number that
// must come back to zero once everything has gone quiet.
func (c *coalescer) open() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.slots)
}

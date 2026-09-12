package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The device token is derived from the delivery token so that two fixtures are two
// *devices*. They used to share one, which stopped being expressible when Put began
// keeping a single registration per device per app: a second Put simply replaced the
// first, and a test about pruning found nothing left to prune.
func newRegistration(token string) Registration {
	return Registration{
		Token:       token,
		DeviceToken: fmt.Sprintf("%064x", sha256.Sum256([]byte(token)))[:64],
		Topic:       "net.pickles.mail.dev",
		Mode:        Alert,
		SeenAt:      time.Now(),
	}
}

func TestOpenMissingFileIsNotAnError(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "nothing-here.json"))
	if err != nil {
		t.Fatalf("a new site has no file yet, and that is normal: %v", err)
	}
	if s.Count() != 0 {
		t.Fatalf("expected an empty store, got %d", s.Count())
	}
}

func TestOpenCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registrations.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Starting empty here would look exactly like a healthy start while silently
	// dropping every device, which is the one failure the operator would not see.
	if _, err := Open(path); err == nil {
		t.Fatal("expected a corrupt store to refuse to open")
	}
}

func TestPutGetSurvivesReopening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registrations.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(newRegistration("tok-one")); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get("tok-one")
	if err != nil {
		t.Fatalf("registration did not survive a restart: %v", err)
	}
	if got.Topic != "net.pickles.mail.dev" {
		t.Fatalf("topic came back as %q", got.Topic)
	}
}

func TestPutKeepsCreatedAtAcrossReregistration(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	first := newRegistration("tok-one")
	first.CreatedAt = time.Now().Add(-72 * time.Hour)
	first.SeenAt = first.CreatedAt
	if err := s.Put(first); err != nil {
		t.Fatal(err)
	}
	// A device re-registers every foreground; that must refresh SeenAt without making
	// the registration look brand new, or Prune could never distinguish anything.
	again := newRegistration("tok-one")
	again.SeenAt = time.Now()
	if err := s.Put(again); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("tok-one")
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("CreatedAt was overwritten: %v", got.CreatedAt)
	}
	if !got.SeenAt.After(first.CreatedAt) {
		t.Fatal("SeenAt was not refreshed")
	}
}

func TestPutRejectsIncompleteAndUnknownMode(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	missing := newRegistration("tok-one")
	missing.DeviceToken = ""
	if err := s.Put(missing); err == nil {
		t.Fatal("expected a registration with no device token to be refused")
	}
	unknown := newRegistration("tok-two")
	unknown.Mode = "shout"
	if err := s.Put(unknown); err == nil {
		t.Fatal("expected an unknown mode to be refused")
	}
}

func TestByGmailFindsEveryDeviceAndIsCaseInsensitive(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	for _, token := range []string{"tok-phone", "tok-ipad", "tok-mac"} {
		r := newRegistration(token)
		r.GmailAddress = "Someone@Gmail.com"
		if err := s.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	other := newRegistration("tok-other")
	other.GmailAddress = "different@gmail.com"
	if err := s.Put(other); err != nil {
		t.Fatal(err)
	}
	// One address is read on three devices, and every one of them has to be woken.
	found := s.ByGmail("someone@gmail.com")
	if len(found) != 3 {
		t.Fatalf("expected all three devices, got %d", len(found))
	}
	if len(s.ByGmail("")) != 0 {
		t.Fatal("an empty address must match nothing at all")
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	_ = s.Put(newRegistration("tok-one"))
	if err := s.Delete("tok-one"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("tok-one"); err != nil {
		t.Fatalf("deleting what is already gone is not a failure: %v", err)
	}
	if _, err := s.Get("tok-one"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPruneDropsOnlyTheStale(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	now := time.Now()
	stale := newRegistration("tok-stale")
	stale.SeenAt = now.Add(-8 * 24 * time.Hour)
	_ = s.Put(stale)
	_ = s.Put(newRegistration("tok-fresh"))

	removed, err := s.Prune(now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("expected one removal, got %d", removed)
	}
	if _, err := s.Get("tok-fresh"); err != nil {
		t.Fatal("pruning took a live registration with it")
	}
}

// A row whose proof has run out is never delivered to again, so keeping it is storage
// with no purpose — and on the Gmail path that storage is an email address
// (pickles-email#520).
func TestPruneDropsAnExpiredProofEvenIfSeenToday(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	now := time.Now()
	lapsed := newRegistration("tok-lapsed")
	lapsed.SeenAt = now
	lapsed.ExpiresAt = now.Add(-time.Minute)
	_ = s.Put(lapsed)

	removed, err := s.Prune(now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("expected the lapsed registration to go, got %d removals", removed)
	}
}

// Zero means the proof does not expire — a self-hoster's secret, or an open relay — and
// must never be read as "expired at the zero time".
func TestPruneKeepsARegistrationWhoseProofDoesNotExpire(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	now := time.Now()
	forever := newRegistration("tok-secret")
	forever.SeenAt = now
	forever.ExpiresAt = time.Time{}
	_ = s.Put(forever)

	removed, err := s.Prune(now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("pruned a registration whose proof never expires")
	}
	if _, err := s.Get("tok-secret"); err != nil {
		t.Fatal("the registration is gone")
	}
}

// A proof that is still good keeps the row, which is the ordinary case for a subscriber.
func TestPruneKeepsALiveProof(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	now := time.Now()
	live := newRegistration("tok-live")
	live.SeenAt = now
	live.ExpiresAt = now.Add(24 * time.Hour)
	_ = s.Put(live)

	removed, _ := s.Prune(now.Add(-7*24*time.Hour), now)
	if removed != 0 {
		t.Fatalf("pruned a registration whose proof is still good")
	}
}

func TestConcurrentWritesDoNotCorruptTheFile(t *testing.T) {
	// The whole premise of a JSON file as the store is that it is written under one
	// lock and renamed into place. If that is wrong, it is wrong here.
	path := filepath.Join(t.TempDir(), "r.json")
	s, _ := Open(path)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := newRegistration(string(rune('a'+i%26)) + string(rune('a'+i/26)))
			_ = s.Put(r)
			_, _ = s.Get(r.Token)
			_ = s.ByGmail("someone@gmail.com")
		}(i)
	}
	wg.Wait()
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("the file did not survive concurrent writers: %v", err)
	}
	if reopened.Count() != s.Count() {
		t.Fatalf("in memory %d, on disk %d", s.Count(), reopened.Count())
	}
}

func TestFileIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	s, _ := Open(path)
	_ = s.Put(newRegistration("tok-one"))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Device tokens are not secrets exactly, but they are a list of who to wake and
	// there is no reason for anything else on the box to read it.
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("expected 0600, got %o", mode)
	}
}

// A device that registers again under a new delivery token has replaced the old one,
// not acquired a second. The old row still holds a working APNs token, so leaving it
// there wakes the same device twice for one message — which is exactly what a client
// bug produced: three rows on each site for one phone, and three identical banners.
func TestRegisteringAgainReplacesTheDevicesOtherRegistrations(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "registrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := Registration{DeviceToken: "aaaa", Topic: "net.pickles.mail.dev", Mode: Alert, SeenAt: time.Now()}

	first := base
	first.Token = "tok-one"
	if err := s.Put(first); err != nil {
		t.Fatal(err)
	}
	second := base
	second.Token = "tok-two"
	if err := s.Put(second); err != nil {
		t.Fatal(err)
	}

	if got := s.Count(); got != 1 {
		t.Fatalf("one device should hold one registration, got %d", got)
	}
	if _, err := s.Get("tok-two"); err != nil {
		t.Fatal("the newest registration must be the one kept")
	}
	if _, err := s.Get("tok-one"); err == nil {
		t.Fatal("the superseded registration must be gone")
	}
}

// Another device, and the same device under another app, are not duplicates.
func TestOtherDevicesAndOtherAppsAreLeftAlone(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "registrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	rows := []Registration{
		{Token: "a", DeviceToken: "aaaa", Topic: "net.pickles.mail.dev", Mode: Alert, SeenAt: time.Now()},
		{Token: "b", DeviceToken: "bbbb", Topic: "net.pickles.mail.dev", Mode: Alert, SeenAt: time.Now()},
		{Token: "c", DeviceToken: "aaaa", Topic: "com.evilforbeginners.Pickles", Mode: Alert, SeenAt: time.Now()},
	}
	for _, r := range rows {
		if err := s.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Count(); got != 3 {
		t.Fatalf("three distinct registrations, got %d", got)
	}
}

// The file is rewritten whole, fsynced and renamed on every write, so its size is the
// cost of every Put, Delete and Prune — not just storage. A registration with no token
// mints one, and a StoreKit JWS is replayable, so one valid proof could grow the file at
// disk speed until each write was rewriting hundreds of megabytes (pickles-email#464).
func TestASiteWillNotHoldMoreRegistrationsThanItsLimit(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	s.MaxRegistrations = 3
	for i := range 3 {
		if err := s.Put(newRegistration(fmt.Sprintf("tok-%d", i))); err != nil {
			t.Fatalf("registration %d was refused below the limit: %v", i, err)
		}
	}
	if err := s.Put(newRegistration("tok-one-too-many")); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	if s.Count() != 3 {
		t.Fatalf("the store grew to %d anyway", s.Count())
	}
	// A device already here is never turned away: refreshing an existing row is not
	// growth, and neither is a device coming back with a new delivery token, because
	// the row it supersedes is leaving in the same Put.
	refresh := newRegistration("tok-1")
	refresh.SeenAt = time.Now()
	if err := s.Put(refresh); err != nil {
		t.Fatalf("a device already registered was refused by a full site: %v", err)
	}
	returning := newRegistration("tok-1")
	returning.Token = "tok-1-renewed"
	if err := s.Put(returning); err != nil {
		t.Fatalf("a device with a new delivery token was refused by a full site: %v", err)
	}
	if s.Count() != 3 {
		t.Fatalf("superseding a row changed the count to %d", s.Count())
	}
}

// A Gmail address is accepted on trust: Pub/Sub names the mailbox and nothing on this
// path proves the registering device reads it. The cap is what bounds both how much one
// unverified claim can cost and how far one published message fans out
// (pickles-email#464).
func TestOneAddressHoldsOnlySoManyDevices(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "r.json"))
	s.MaxPerAddress = 2
	for i := range 2 {
		r := newRegistration(fmt.Sprintf("tok-%d", i))
		r.GmailAddress = "someone@gmail.com"
		if err := s.Put(r); err != nil {
			t.Fatalf("device %d was refused below the limit: %v", i, err)
		}
	}
	third := newRegistration("tok-third")
	third.GmailAddress = "Someone@Gmail.com" // the same address, differently typed
	if err := s.Put(third); !errors.Is(err, ErrTooManyForAddress) {
		t.Fatalf("expected ErrTooManyForAddress, got %v", err)
	}
	// Another address is another matter, and so is the JMAP path, which has no address
	// at all.
	other := newRegistration("tok-other")
	other.GmailAddress = "different@gmail.com"
	if err := s.Put(other); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(newRegistration("tok-jmap")); err != nil {
		t.Fatal(err)
	}
	if len(s.ByGmail("someone@gmail.com")) != 2 {
		t.Fatalf("the address ended up with %d devices", len(s.ByGmail("someone@gmail.com")))
	}
}

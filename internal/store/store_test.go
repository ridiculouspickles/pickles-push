package store

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newRegistration(token string) Registration {
	return Registration{
		Token:       token,
		DeviceToken: "abcdef0123456789abcdef0123456789",
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
	stale := newRegistration("tok-stale")
	stale.SeenAt = time.Now().Add(-40 * 24 * time.Hour)
	_ = s.Put(stale)
	_ = s.Put(newRegistration("tok-fresh"))

	removed, err := s.Prune(time.Now().Add(-30 * 24 * time.Hour))
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

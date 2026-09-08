// Package store keeps the relay's only durable state: which delivery token belongs to
// which device.
//
// It is a JSON file rewritten whole, under one mutex, with an atomic rename. That is a
// deliberate choice and not a placeholder. The registrations are small, they are written
// only by the devices that own them, and — the part that matters — **the device is the
// source of truth, not this file**. Devices re-register on every foreground and at least
// daily, so losing this file entirely costs at most a day of push and repairs itself with
// no operator action. A database would be machinery guarding a cache.
//
// See ADR-0017 in the pickles-email repository.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mode is what the relay does when a change arrives for this registration.
//
// The relay does not choose. The device does, at registration, because which site is
// allowed to raise a banner is a client-side topology decision and this binary should
// not have an opinion that has to be redeployed when the topology changes.
type Mode string

const (
	// Alert raises a user-visible notification. The payload is opaque to us; a
	// notification service extension on the device replaces the placeholder text with
	// the real sender and subject, locally, before it is shown.
	Alert Mode = "alert"
	// Background wakes the app to sync and shows nothing. Used by a secondary site, so
	// that two sites can both deliver without two banners.
	Background Mode = "background"
)

func (m Mode) valid() bool { return m == Alert || m == Background }

// A Registration is one device, reachable one way.
//
// There is deliberately no account identifier, no address and no display name on the
// JMAP path: the relay is told where to deliver and nothing about who is being served.
// GmailAddress is the exception, and it is an unavoidable one — Cloud Pub/Sub names the
// mailbox in the clear, so a Gmail registration has to be findable by address.
type Registration struct {
	// Token is the unguessable path segment the provider posts to. It is the primary
	// key and it is a bearer capability: whoever holds it can cause a push to this
	// device and nothing else.
	Token string `json:"token"`

	// DeviceToken is the APNs device token, hex, as Apple gives it.
	DeviceToken string `json:"deviceToken"`

	// Topic is the bundle identifier the push is addressed to, so one relay can serve
	// the dev build and the release build without a second deployment.
	Topic string `json:"topic"`

	// Sandbox selects Apple's development push host. A development build's token is
	// meaningless to the production host and vice versa; getting this wrong is the
	// single most common cause of "the push went nowhere and nothing said why".
	Sandbox bool `json:"sandbox"`

	Mode Mode `json:"mode"`

	// GmailAddress is set only for a Gmail registration, because Pub/Sub identifies the
	// mailbox by address and there is no other way to route the message. Empty on the
	// JMAP path, which is the whole point of the JMAP path.
	GmailAddress string `json:"gmailAddress,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	// SeenAt is refreshed by re-registration. It is what Prune reads.
	SeenAt time.Time `json:"seenAt"`
}

// ErrNotFound is returned for an unknown token. Callers must not distinguish it from a
// malformed one in anything they send back over the network.
var ErrNotFound = errors.New("registration not found")

// Store is safe for concurrent use.
type Store struct {
	path string

	mu sync.RWMutex
	// by token
	registrations map[string]Registration
}

// Open reads the file if it is there, and starts empty if it is not.
//
// A missing file is the normal state of a new site and not an error; so is an empty one.
// A *corrupt* one is an error, because silently starting empty would look identical to a
// successful start and would quietly stop delivering to every device until each came
// back to re-register.
func Open(path string) (*Store, error) {
	s := &Store{path: path, registrations: map[string]Registration{}}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return s, nil
	}
	var list []Registration
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, r := range list {
		s.registrations[r.Token] = r
	}
	return s, nil
}

// Count is for the health endpoint and the tests. It is a number, not a listing.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.registrations)
}

// Put inserts or refreshes a registration and flushes to disk.
//
// Re-registering an existing token is the common case, not the rare one: devices do it
// on every foreground. It updates SeenAt and whatever else changed, which is how a device
// that was reinstalled — new APNs token, same relay token — keeps working.
func (s *Store) Put(r Registration) error {
	if r.Token == "" || r.DeviceToken == "" || r.Topic == "" {
		return errors.New("token, deviceToken and topic are required")
	}
	if !r.Mode.valid() {
		return fmt.Errorf("unknown mode %q", r.Mode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.registrations[r.Token]; ok {
		r.CreatedAt = existing.CreatedAt
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = r.SeenAt
	}
	r.GmailAddress = strings.ToLower(r.GmailAddress)
	s.registrations[r.Token] = r
	return s.flushLocked()
}

// Get returns one registration by delivery token.
func (s *Store) Get(token string) (Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.registrations[token]
	if !ok {
		return Registration{}, ErrNotFound
	}
	return r, nil
}

// ByGmail returns every registration for an address.
//
// Plural because one address is read on a phone, an iPad and a Mac, and each of those is
// its own registration with its own device token.
func (s *Store) ByGmail(address string) []Registration {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found []Registration
	for _, r := range s.registrations {
		if r.GmailAddress == address {
			found = append(found, r)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Token < found[j].Token })
	return found
}

// Delete removes a registration. Deleting one that is not there is not an error: the
// caller wanted it gone, and it is gone.
func (s *Store) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.registrations[token]; !ok {
		return nil
	}
	delete(s.registrations, token)
	return s.flushLocked()
}

// Prune drops registrations not seen since the cutoff.
//
// A device that has stopped re-registering has been deleted, wiped, or had push turned
// off, and Apple will not tell us about most of those. Returns how many went.
func (s *Store) Prune(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for token, r := range s.registrations {
		if r.SeenAt.Before(before) {
			delete(s.registrations, token)
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, s.flushLocked()
}

// flushLocked writes the whole file and renames it into place. The caller holds the lock.
//
// Whole-file rewrite because the data is tiny and partial writes are the only way a file
// like this gets corrupted. Rename because a half-written file that replaced a good one
// would be the one failure this design is not allowed to have.
func (s *Store) flushLocked() error {
	list := make([]Registration, 0, len(s.registrations))
	for _, r := range s.registrations {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Token < list[j].Token })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".registrations-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

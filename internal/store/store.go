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

// Valid reports whether this is a mode the relay knows.
//
// Exported so the HTTP layer can refuse an unknown one *before* calling Put, and so log
// a fixed reason rather than Put's error — which quotes the value it was given, and the
// value came from a client (pickles-email#475).
func (m Mode) Valid() bool { return m == Alert || m == Background }

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

	// ExpiresAt is when the proof this device registered with runs out — a
	// subscription's expiry plus the grace — after which nothing is delivered to it.
	// Zero when the proof does not expire (a self-hoster's secret, or an open relay).
	// The device moves it by re-registering with a renewed transaction.
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
}

// ErrNotFound is returned for an unknown token. Callers must not distinguish it from a
// malformed one in anything they send back over the network.
var ErrNotFound = errors.New("registration not found")

// ErrFull means this site will not hold another registration.
//
// The file is rewritten whole, fsynced and renamed on every write, so its size is not
// only storage: it is the cost of every Put, Delete and Prune. A registration with no
// token mints a new one, and a StoreKit JWS is replayable, so one valid proof could
// create rows at disk speed until each write was rewriting hundreds of megabytes
// (pickles-email#464). A device already here is always allowed to re-register; what is
// capped is growth.
var ErrFull = errors.New("this site is not accepting more registrations")

// ErrTooManyForAddress means one Gmail address already has as many devices as we will
// hold for it.
//
// The address is accepted on trust — Pub/Sub names the mailbox and there is nothing on
// this path to prove the registering device reads it — so the cap is also what bounds
// how far one published message fans out, and how much one unverified claim can cost.
var ErrTooManyForAddress = errors.New("too many registrations for that address")

// What a site will hold. Both are generous: the phone, the iPad and the Mac of every
// subscriber we are likely to have, and then some.
const (
	DefaultMaxRegistrations = 5000
	DefaultMaxPerAddress    = 16
)

// Store is safe for concurrent use.
type Store struct {
	path string

	// MaxRegistrations and MaxPerAddress bound the file. Zero means no limit, which is
	// what a test that does not care sets. Open fills in the defaults.
	MaxRegistrations int
	MaxPerAddress    int

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
	s := &Store{
		path:             path,
		registrations:    map[string]Registration{},
		MaxRegistrations: DefaultMaxRegistrations,
		MaxPerAddress:    DefaultMaxPerAddress,
	}
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
	if !r.Mode.Valid() {
		return fmt.Errorf("unknown mode %q", r.Mode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, replacing := s.registrations[r.Token]
	if replacing {
		r.CreatedAt = existing.CreatedAt
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = r.SeenAt
	}
	r.GmailAddress = strings.ToLower(strings.TrimSpace(r.GmailAddress))

	// Counted before anything is written, and counted net: the rows this Put is about
	// to supersede are leaving, so a device coming back with a new delivery token is
	// not growth and must not be refused by a full site.
	superseded := 0
	for token, other := range s.registrations {
		if token != r.Token && other.DeviceToken == r.DeviceToken && other.Topic == r.Topic {
			superseded++
		}
	}
	after := len(s.registrations) + 1 - superseded
	if replacing {
		after--
	}
	if s.MaxRegistrations > 0 && after > s.MaxRegistrations {
		return ErrFull
	}
	if r.GmailAddress != "" && s.MaxPerAddress > 0 {
		forAddress := 1
		for token, other := range s.registrations {
			switch {
			case token == r.Token:
			case other.DeviceToken == r.DeviceToken && other.Topic == r.Topic:
			case other.GmailAddress == r.GmailAddress:
				forAddress++
			}
		}
		if forAddress > s.MaxPerAddress {
			return ErrTooManyForAddress
		}
	}

	s.registrations[r.Token] = r

	// **One registration per device per app, on this site.** A device that registers
	// again under a new delivery token has replaced the old one, not acquired a second:
	// the old row still holds a working APNs token, so a provider pushing to both URLs
	// wakes the same device twice and the reader gets two identical banners.
	//
	// This is not hypothetical. A client bug minted a fresh token on every launch —
	// registrations were written to UserDefaults and never read back — and one phone
	// accumulated three rows on each site before anybody noticed the duplicates. The
	// client is fixed; this is what makes the relay robust to the next one, and to a
	// device restored from a backup, which arrives looking exactly the same.
	//
	// Keyed on the device token and the topic rather than the mode: a site that starts
	// sending a device alerts instead of silent wakes has changed the same registration,
	// not added one.
	for token, other := range s.registrations {
		if token == r.Token {
			continue
		}
		if other.DeviceToken == r.DeviceToken && other.Topic == r.Topic {
			delete(s.registrations, token)
		}
	}
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

// Prune drops registrations that are no longer any use to the device that made them.
//
// Two reasons a row goes, and they are different questions:
//
//   - **Not seen since seenBefore.** A device that has stopped re-registering has been
//     deleted, wiped, or had push turned off, and Apple will not tell us about most of
//     those. Registration is refreshed daily and on every foreground, so a row that has
//     missed a week of those belongs to a device that is gone rather than merely asleep
//     — a phone that is only offline costs nothing here, because Apple expires its push
//     after an hour and the row is refreshed the moment it comes back.
//
//   - **Proof expired before expiredBefore.** `ExpiresAt` is a subscription's expiry
//     plus the grace, after which nothing is delivered to this row at all. Keeping it
//     then is storage with no purpose. Zero means the proof does not expire — a
//     self-hoster's secret, or an open relay — and never prunes on this rule.
//
// The second matters because a row holds a device token, a delivery token and, on the
// Gmail path, an email address: the one personal thing this relay keeps, for a device
// that may no longer exist.
//
// Returns how many went.
func (s *Store) Prune(seenBefore, expiredBefore time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for token, r := range s.registrations {
		expired := !r.ExpiresAt.IsZero() && r.ExpiresAt.Before(expiredBefore)
		if r.SeenAt.Before(seenBefore) || expired {
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

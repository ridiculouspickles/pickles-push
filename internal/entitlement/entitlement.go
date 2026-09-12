// Package entitlement decides whether a registration may be accepted.
//
// There are three ways to run a relay (ADR-0018 in the pickles-email repository):
//
//   - Hosted, ours. A device proves it pays by presenting StoreKit's signed transaction
//     at registration. The relay verifies Apple's signature against Apple's root,
//     offline, and checks the bundle, the product and the expiry. No account, no login,
//     no call to Apple, and nothing stored about who paid — a capability, not an
//     identity.
//   - Self-hosted. The operator sets a secret and types it into the app beside the
//     relay's URL. The device sends it as a bearer token.
//   - Open. Neither is configured. Anyone may register. Fine on a laptop; the binary
//     warns about it at start.
//
// When both are configured either proof admits the request, so one binary can serve a
// household that pays for one device and shares its secret with another.
package entitlement

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrRefused wraps every refusal. The text after it is safe to send to the client: it
// names what was missing, never what was presented.
var ErrRefused = errors.New("registration refused")

// Policy is what the operator configured.
type Policy struct {
	// Secret admits any request bearing it. Empty disables the secret.
	Secret string
	// Apple admits a request carrying a signed transaction it accepts. Nil disables it.
	Apple *AppleVerifier
}

// Open reports whether anyone may register.
func (p Policy) Open() bool { return p.Secret == "" && p.Apple == nil }

// Admission is what a successful check hands back.
type Admission struct {
	// ExpiresAt is when the proof stops being good, or zero for one that does not
	// expire. The relay stops delivering after it; a re-registration with a renewed
	// transaction moves it.
	ExpiresAt time.Time
	// Signed is when Apple signed the transaction, or zero when the proof was not one.
	// Nothing is decided on it yet — it is reported so the log can say how old the
	// transactions real devices present actually are, which is what AppleVerifier's
	// MaxSignedAge needs before it can be turned on.
	Signed time.Time
}

// Admit checks a registration.
//
// authorization is the request's Authorization header, transaction the signed
// transaction from the body (empty when none was sent), bundleID the topic the device
// registered for, sandbox whether it is a development build.
func (p Policy) Admit(authorization, transaction, bundleID string, sandbox bool, now time.Time) (Admission, error) {
	if p.Open() {
		return Admission{}, nil
	}
	if p.Secret != "" {
		if presented, ok := strings.CutPrefix(authorization, "Bearer "); ok {
			if sameSecret(presented, p.Secret) {
				return Admission{}, nil
			}
			// A wrong secret is refused outright even if a transaction was also sent:
			// the device meant to use the secret, and the two proofs should not be
			// tried in turn against a relay that only expected one.
			return Admission{}, fmt.Errorf("%w: wrong secret", ErrRefused)
		}
	}
	if p.Apple != nil && transaction != "" {
		tx, err := p.Apple.Verify(transaction, bundleID, sandbox, now)
		if err != nil {
			return Admission{}, fmt.Errorf("%w: %v", ErrRefused, err)
		}
		return Admission{ExpiresAt: tx.Expires.Add(p.Apple.Grace), Signed: tx.Signed}, nil
	}
	switch {
	case p.Apple != nil && p.Secret != "":
		return Admission{}, fmt.Errorf("%w: a subscription or this relay's secret is required", ErrRefused)
	case p.Apple != nil:
		return Admission{}, fmt.Errorf("%w: a subscription is required", ErrRefused)
	default:
		return Admission{}, fmt.Errorf("%w: this relay's secret is required", ErrRefused)
	}
}

// sameSecret compares two secrets without answering faster for the wrong length.
//
// subtle.ConstantTimeCompare returns 0 immediately when the lengths differ, so it is
// constant-time only across equal-length inputs — and the presented value's length is
// the caller's to choose. Hashing both sides first makes every comparison 32 bytes
// against 32 bytes.
func sameSecret(presented, expected string) bool {
	a := sha256.Sum256([]byte(presented))
	b := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

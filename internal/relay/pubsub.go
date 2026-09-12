package relay

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verifying the token Cloud Pub/Sub sends with a push.
//
// Without this the Gmail endpoint is an open door: anyone who guesses the URL could
// claim any address has new mail and wake somebody's phone all night. Google signs an
// OIDC token with its own keys; we check the signature, the audience, the expiry, and
// the account Google minted it for.
//
// The last is the one that matters. A signature says Google minted the token, not that
// our subscription asked it to: `gcloud auth print-identity-token --audiences=<url>`
// mints one for any audience from any project, and the audience is a URL.
//
// Hand-rolled, like the APNs JWT, because pulling in a JWT library and a Google SDK to
// verify one RS256 token would be a supply chain several times the size of the program.

const googleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

var googleIssuers = []string{"accounts.google.com", "https://accounts.google.com"}

type jwks struct {
	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
	// fetched is the last *successful* fetch, and is what staleness is measured from.
	fetched time.Time
	// attempted is the last fetch begun, successful or not. Separating the two is the
	// whole of pickles-email#476 item 2: a failed refresh used to leave `fetched`
	// where it was, so every subsequent push retried the fetch, and a Google or DNS
	// blip meant a ten-second stall and a 403 for each of them.
	attempted time.Time
	client    *http.Client
	url       string
}

func newJWKS() *jwks {
	return &jwks{
		keys:   map[string]*rsa.PublicKey{},
		client: &http.Client{Timeout: 10 * time.Second},
		url:    googleCertsURL,
	}
}

const (
	// How long a successful fetch is trusted without asking again.
	jwksLifetime = time.Hour
	// How often we are willing to ask. One attempt per window across all goroutines,
	// which is both the backoff after a failure and the cap on a rotation stampede.
	jwksRetry = 10 * time.Minute
)

// key returns the signing key for a kid.
//
// Google rotates these, and an unknown kid is the normal way a rotation announces
// itself — so an unknown kid may force a refresh rather than a rejection.
//
// Two rules, and the second is why this function is longer than it looks:
//
//   - **A refresh failure never costs us a key we already have.** The old code dropped
//     the cached key on any error and left the retry clock untouched, so one DNS blip
//     turned every Gmail push into a 403 with a ten-second stall in front of it, for as
//     long as the blip lasted. A key that verified a minute ago verifies now; Google's
//     keys are valid for days.
//   - **The fetch happens outside the lock.** It used to run under the write lock, so
//     the one slow request held up every other push behind it. What is claimed under
//     the lock is the *right to attempt*, which is what keeps a stampede to one fetch.
func (j *jwks) key(kid string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	cached, known := j.keys[kid]
	fresh := time.Since(j.fetched) <= jwksLifetime
	j.mu.RUnlock()
	if known && fresh {
		return cached, nil
	}

	j.mu.Lock()
	// Re-read under the lock: another goroutine may have refreshed while we waited.
	cached, known = j.keys[kid]
	if known && time.Since(j.fetched) <= jwksLifetime {
		j.mu.Unlock()
		return cached, nil
	}
	if time.Since(j.attempted) < jwksRetry {
		// Somebody asked recently. Whatever we have is what we have.
		j.mu.Unlock()
		if known {
			return cached, nil
		}
		return nil, fmt.Errorf("unknown signing key %q", clip(kid))
	}
	j.attempted = time.Now()
	j.mu.Unlock()

	loaded, err := j.load()
	if err != nil {
		if known {
			// The cached key is still a real Google key. Refusing pushes because we
			// could not confirm that is the failure this returns instead of.
			return cached, nil
		}
		return nil, err
	}
	j.mu.Lock()
	j.keys, j.fetched = loaded, time.Now()
	found, ok := j.keys[kid]
	j.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown signing key %q", clip(kid))
	}
	return found, nil
}

// load fetches and parses the JWKS. It holds no lock.
func (j *jwks) load() (map[string]*rsa.PublicKey, error) {
	response, err := j.client.Get(j.url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var document struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Kty string `json:"kty"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&document); err != nil {
		return nil, err
	}
	loaded := map[string]*rsa.PublicKey{}
	for _, k := range document.Keys {
		if k.Kty != "RSA" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		exponent, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		loaded[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(bigEndianUint(exponent)),
		}
	}
	if len(loaded) == 0 {
		return nil, errors.New("no usable keys in the JWKS")
	}
	return loaded, nil
}

// claimIsTrue reads a boolean claim that some issuers write as the string "true".
func claimIsTrue(raw json.RawMessage) bool {
	var asBool bool
	if json.Unmarshal(raw, &asBool) == nil {
		return asBool
	}
	var asString string
	return json.Unmarshal(raw, &asString) == nil && asString == "true"
}

// clip bounds a value quoted into an error the relay logs.
//
// `alg` and `kid` are read out of the JWT header *before* the signature is checked —
// they have to be, since `kid` is what selects the key — so an unauthenticated caller
// chooses them, and `relay.go` logs the error. A refusal is worth one line, not a line
// of whatever length the caller felt like (pickles-email#475).
func clip(value string) string {
	const most = 64
	if len(value) <= most {
		return value
	}
	return value[:most] + "…"
}

func bigEndianUint(b []byte) uint64 {
	padded := make([]byte, 8)
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	copy(padded[8-len(b):], b)
	return binary.BigEndian.Uint64(padded)
}

var sharedJWKS = newJWKS()

// verifyPubSub checks the OIDC token on a Pub/Sub push request.
func (r *Relay) verifyPubSub(request *http.Request) error {
	header := request.Header.Get("authorization")
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		raw, ok = strings.CutPrefix(header, "bearer ")
	}
	if !ok || raw == "" {
		return errors.New("no bearer token")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return errors.New("token is not a JWT")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &head); err != nil {
		return err
	}
	if head.Alg != "RS256" {
		// Refusing anything else by name is what stops an "alg: none" token, which is
		// the oldest hole in JWT verification and still worth closing explicitly.
		return fmt.Errorf("unexpected algorithm %q", clip(head.Alg))
	}
	key, err := sharedJWKS.key(head.Kid)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return errors.New("signature does not verify")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var claims struct {
		Aud           string          `json:"aud"`
		Iss           string          `json:"iss"`
		Exp           int64           `json:"exp"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return err
	}
	if claims.Aud != r.GmailAudience {
		return errors.New("wrong audience")
	}
	// Google's documented check for an authenticated push endpoint. Never the claimed
	// address in the error: it was written by whoever minted the token.
	if r.GmailServiceAccount == "" ||
		!strings.EqualFold(claims.Email, r.GmailServiceAccount) ||
		!claimIsTrue(claims.EmailVerified) {
		return errors.New("token was not minted for this relay's service account")
	}
	issuerOK := false
	for _, issuer := range googleIssuers {
		if claims.Iss == issuer {
			issuerOK = true
		}
	}
	if !issuerOK {
		return fmt.Errorf("unexpected issuer %q", clip(claims.Iss))
	}
	if time.Unix(claims.Exp, 0).Before(r.now()) {
		return errors.New("token expired")
	}
	return nil
}

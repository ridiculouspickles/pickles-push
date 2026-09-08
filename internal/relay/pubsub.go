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
// OIDC token with its own keys; we check the signature, the audience and the expiry.
//
// Hand-rolled, like the APNs JWT, because pulling in a JWT library and a Google SDK to
// verify one RS256 token would be a supply chain several times the size of the program.

const googleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

var googleIssuers = []string{"accounts.google.com", "https://accounts.google.com"}

type jwks struct {
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	client  *http.Client
	url     string
}

func newJWKS() *jwks {
	return &jwks{
		keys:   map[string]*rsa.PublicKey{},
		client: &http.Client{Timeout: 10 * time.Second},
		url:    googleCertsURL,
	}
}

// key returns the signing key for a kid, refreshing at most every ten minutes.
//
// Google rotates these, and an unknown kid is the normal way a rotation announces
// itself — so an unknown kid forces one refresh rather than a rejection.
func (j *jwks) key(kid string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	found, ok := j.keys[kid]
	stale := time.Since(j.fetched) > time.Hour
	j.mu.RUnlock()
	if ok && !stale {
		return found, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if time.Since(j.fetched) < 10*time.Minute {
		if found, ok := j.keys[kid]; ok {
			return found, nil
		}
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
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
	fresh := map[string]*rsa.PublicKey{}
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
		fresh[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(modulus),
			E: int(bigEndianUint(exponent)),
		}
	}
	if len(fresh) == 0 {
		return nil, errors.New("no usable keys in the JWKS")
	}
	j.keys, j.fetched = fresh, time.Now()
	if found, ok := j.keys[kid]; ok {
		return found, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
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
		return fmt.Errorf("unexpected algorithm %q", head.Alg)
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
		Aud string `json:"aud"`
		Iss string `json:"iss"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return err
	}
	if claims.Aud != r.GmailAudience {
		return errors.New("wrong audience")
	}
	issuerOK := false
	for _, issuer := range googleIssuers {
		if claims.Iss == issuer {
			issuerOK = true
		}
	}
	if !issuerOK {
		return fmt.Errorf("unexpected issuer %q", claims.Iss)
	}
	if time.Unix(claims.Exp, 0).Before(r.now()) {
		return errors.New("token expired")
	}
	return nil
}

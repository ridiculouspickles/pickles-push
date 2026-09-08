package apns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *Key {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Key{PrivateKey: private, KeyID: "ABCDE12345", TeamID: "SA2SS4242K"}
}

func TestParseKeyAcceptsAPKCS8P8(t *testing.T) {
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	key, err := ParseKey(encoded, "ABCDE12345", "SA2SS4242K")
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyID != "ABCDE12345" {
		t.Fatalf("key id came back as %q", key.KeyID)
	}
}

func TestParseKeyRejectsNonsenseAndMissingIDs(t *testing.T) {
	if _, err := ParseKey([]byte("this is not a pem file"), "A", "B"); err == nil {
		t.Fatal("expected a parse failure")
	}
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParseKey(encoded, "", "SA2SS4242K"); err == nil {
		t.Fatal("a key with no key id cannot sign anything Apple will accept")
	}
}

func TestSignProducesAVerifiableES256JWT(t *testing.T) {
	key := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	token, err := sign(key, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three parts, got %d", len(parts))
	}

	var header struct{ Alg, Kid string }
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != "ES256" || header.Kid != "ABCDE12345" {
		t.Fatalf("header was %+v", header)
	}

	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
	}
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "SA2SS4242K" || claims.Iat != now.Unix() {
		t.Fatalf("claims were %+v", claims)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	// The fixed-width r||s encoding is the part Apple is strict about, and an ASN.1
	// signature here would be accepted by nothing and explained by no error message.
	if len(signature) != 64 {
		t.Fatalf("expected 64 bytes of r||s, got %d", len(signature))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&key.PrivateKey.PublicKey, digest[:], r, s) {
		t.Fatal("the signature does not verify against its own key")
	}
}

func TestSignLeftPadsAShortComponent(t *testing.T) {
	// A signature component shorter than 32 bytes happens roughly one time in 256 and
	// must be left-padded. Signing repeatedly is the cheapest way to hit one.
	key := testKey(t)
	for i := range 600 {
		token, err := sign(key, time.Unix(int64(1_700_000_000+i), 0))
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[2])
		if err != nil {
			t.Fatal(err)
		}
		if len(signature) != 64 {
			t.Fatalf("signature %d was %d bytes", i, len(signature))
		}
	}
}

func TestBearerIsCachedThenRefreshed(t *testing.T) {
	key := testKey(t)
	now := time.Unix(1_700_000_000, 0)
	client := &Client{Key: key, Now: func() time.Time { return now }}

	first, err := client.bearer()
	if err != nil {
		t.Fatal(err)
	}
	// Apple rate-limits token creation separately from pushes, so a relay that minted
	// one per notification would throttle itself.
	second, err := client.bearer()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("the token was not cached")
	}

	now = now.Add(tokenLifetime + time.Minute)
	third, err := client.bearer()
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("the token was never refreshed, and Apple rejects one over an hour old")
	}
}

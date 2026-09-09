package entitlement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A chain shaped like Apple's — root, WWDR-marked intermediate, App Store-marked
// leaf — but signed by keys made here, so the tests trust a root of their own.
type fakeApple struct {
	roots *x509.CertPool
	leaf  *x509.Certificate
	chain []string
	key   *ecdsa.PrivateKey
}

func newFakeApple(t *testing.T, now time.Time) *fakeApple {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	issue := func(template, parent *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootKey, intermediateKey, leafKey := newKey(), newKey(), newKey()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake Apple Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root := issue(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fake WWDR"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtraExtensions: []pkix.Extension{{Id: oidWWDRIntermediate, Value: []byte{0x05, 0x00}}},
	}
	intermediate := issue(intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Fake App Store signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidAppStoreSigning, Value: []byte{0x05, 0x00}}},
	}
	leaf := issue(leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	encode := func(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }
	return &fakeApple{
		roots: roots, leaf: leaf, key: leafKey,
		chain: []string{encode(leaf), encode(intermediate), encode(root)},
	}
}

// sign produces a JWS the way StoreKit does: ES256, the chain in x5c, r||s signature.
func (f *fakeApple) sign(t *testing.T, payload map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "x5c": f.chain})
	body, _ := json.Marshal(payload)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

var now = time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

func goodPayload(expires time.Time) map[string]any {
	return map[string]any{
		"bundleId":    "com.evilforbeginners.Pickles",
		"productId":   "com.evilforbeginners.Pickles.push.yearly",
		"type":        autoRenewable,
		"environment": "Production",
		"expiresDate": expires.UnixMilli(),
	}
}

func verifier(f *fakeApple) *AppleVerifier {
	return &AppleVerifier{
		ProductIDs: []string{"com.evilforbeginners.Pickles.push.yearly"},
		Roots:      f.roots,
		Grace:      72 * time.Hour,
	}
}

func TestALiveSubscriptionVerifies(t *testing.T) {
	apple := newFakeApple(t, now)
	expires := now.Add(300 * 24 * time.Hour)
	tx, err := verifier(apple).Verify(apple.sign(t, goodPayload(expires)), "com.evilforbeginners.Pickles", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Expires.Equal(expires) {
		t.Fatalf("expiry was %v, wanted %v", tx.Expires, expires)
	}
}

func TestTheGraceKeepsARenewalAlive(t *testing.T) {
	apple := newFakeApple(t, now)
	expiredYesterday := now.Add(-24 * time.Hour)
	if _, err := verifier(apple).Verify(apple.sign(t, goodPayload(expiredYesterday)), "com.evilforbeginners.Pickles", false, now); err != nil {
		t.Fatalf("a day past expiry should be inside the grace: %v", err)
	}
	longGone := now.Add(-4 * 24 * time.Hour)
	if _, err := verifier(apple).Verify(apple.sign(t, goodPayload(longGone)), "com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("four days past expiry is past the grace and should be refused")
	}
}

func TestClaimsAreChecked(t *testing.T) {
	apple := newFakeApple(t, now)
	expires := now.Add(300 * 24 * time.Hour)
	cases := map[string]func(map[string]any){
		"another app":           func(p map[string]any) { p["bundleId"] = "com.example.other" },
		"another product":       func(p map[string]any) { p["productId"] = "com.evilforbeginners.Pickles.v1" },
		"not a subscription":    func(p map[string]any) { p["type"] = "Non-Consumable" },
		"revoked":               func(p map[string]any) { p["revocationDate"] = now.UnixMilli() },
		"no expiry":             func(p map[string]any) { delete(p, "expiresDate") },
		"sandbox on production": func(p map[string]any) { p["environment"] = "Sandbox" },
	}
	for name, mutate := range cases {
		payload := goodPayload(expires)
		mutate(payload)
		if _, err := verifier(apple).Verify(apple.sign(t, payload), "com.evilforbeginners.Pickles", false, now); err == nil {
			t.Errorf("%s: should have been refused", name)
		}
	}
}

func TestASandboxBuildNeedsASandboxTransaction(t *testing.T) {
	apple := newFakeApple(t, now)
	payload := goodPayload(now.Add(24 * time.Hour))
	payload["environment"] = "Sandbox"
	if _, err := verifier(apple).Verify(apple.sign(t, payload), "com.evilforbeginners.Pickles", true, now); err != nil {
		t.Fatal(err)
	}
}

func TestATamperedPayloadFailsTheSignature(t *testing.T) {
	apple := newFakeApple(t, now)
	jws := apple.sign(t, goodPayload(now.Add(24*time.Hour)))
	parts := strings.Split(jws, ".")
	forged := goodPayload(now.Add(10 * 365 * 24 * time.Hour))
	body, _ := json.Marshal(forged)
	parts[1] = base64.RawURLEncoding.EncodeToString(body)
	if _, err := verifier(apple).Verify(strings.Join(parts, "."), "com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("a re-written payload must not verify")
	}
}

func TestAChainToTheWrongRootIsRefused(t *testing.T) {
	apple := newFakeApple(t, now)
	other := newFakeApple(t, now)
	v := verifier(apple)
	v.Roots = other.roots
	if _, err := v.Verify(apple.sign(t, goodPayload(now.Add(24*time.Hour))), "com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("a chain that does not reach the trusted root must not verify")
	}
	// And against Apple's real root, a chain made here is nothing.
	v.Roots = nil
	if _, err := v.Verify(apple.sign(t, goodPayload(now.Add(24*time.Hour))), "com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("a home-made chain must not verify against Apple's root")
	}
}

func TestTheEmbeddedAppleRootParses(t *testing.T) {
	if AppleRoots() == nil {
		t.Fatal("no roots")
	}
}

func TestPolicy(t *testing.T) {
	apple := newFakeApple(t, now)
	jws := apple.sign(t, goodPayload(now.Add(24*time.Hour)))
	bundle := "com.evilforbeginners.Pickles"

	open := Policy{}
	if _, err := open.Admit("", "", bundle, false, now); err != nil {
		t.Fatalf("an open relay admits anyone: %v", err)
	}

	secret := Policy{Secret: "hunter2"}
	if _, err := secret.Admit("Bearer hunter2", "", bundle, false, now); err != nil {
		t.Fatalf("the right secret: %v", err)
	}
	if _, err := secret.Admit("Bearer hunter3", "", bundle, false, now); !errors.Is(err, ErrRefused) {
		t.Fatalf("the wrong secret: %v", err)
	}
	if _, err := secret.Admit("", jws, bundle, false, now); !errors.Is(err, ErrRefused) {
		t.Fatalf("a secret-only relay does not take a subscription: %v", err)
	}

	paid := Policy{Apple: verifier(apple)}
	admission, err := paid.Admit("", jws, bundle, false, now)
	if err != nil {
		t.Fatalf("a live subscription: %v", err)
	}
	if want := now.Add(24 * time.Hour).Add(72 * time.Hour); !admission.ExpiresAt.Equal(want) {
		t.Fatalf("expiry was %v, wanted expiry plus grace %v", admission.ExpiresAt, want)
	}
	if _, err := paid.Admit("", "", bundle, false, now); !errors.Is(err, ErrRefused) {
		t.Fatalf("no proof at all: %v", err)
	}
	if _, err := paid.Admit("Bearer hunter2", "", bundle, false, now); !errors.Is(err, ErrRefused) {
		t.Fatalf("a secret means nothing to a relay without one: %v", err)
	}

	both := Policy{Secret: "hunter2", Apple: verifier(apple)}
	if _, err := both.Admit("Bearer hunter2", "", bundle, false, now); err != nil {
		t.Fatalf("either proof will do: %v", err)
	}
	if _, err := both.Admit("", jws, bundle, false, now); err != nil {
		t.Fatalf("either proof will do: %v", err)
	}
	if _, err := both.Admit("Bearer wrong", jws, bundle, false, now); !errors.Is(err, ErrRefused) {
		t.Fatal("a wrong secret is not rescued by a transaction")
	}
}

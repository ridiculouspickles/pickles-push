package entitlement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	now   time.Time
}

func newFakeApple(t *testing.T, now time.Time) *fakeApple {
	return newFakeAppleMarking(t, now, true)
}

// markIntermediate is false for the one test that needs a chain whose real intermediate
// does *not* carry Apple's WWDR marker, so that a marked decoy in x5c can be told apart
// from the certificate that actually signed the leaf.
func newFakeAppleMarking(t *testing.T, now time.Time, markIntermediate bool) *fakeApple {
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
	}
	if markIntermediate {
		intermediateTemplate.ExtraExtensions = []pkix.Extension{
			{Id: oidWWDRIntermediate, Value: []byte{0x05, 0x00}},
		}
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
		now:   now,
	}
}

// insertAfterLeaf puts a certificate where the intermediate goes in x5c. It changes
// what the client claims the chain is, and nothing about who signed what.
func (f *fakeApple) insertAfterLeaf(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString(cert.Raw)
	f.chain = append([]string{f.chain[0], encoded}, f.chain[1:]...)
}

// selfSignedCarrying is a certificate with a marker on it and nothing else to recommend
// it: it signs nothing, chains to nothing, and exists only to be looked at.
func selfSignedCarrying(t *testing.T, oid asn1.ObjectIdentifier, now time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "Decoy"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtraExtensions: []pkix.Extension{{Id: oid, Value: []byte{0x05, 0x00}}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
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

// A TestFlight build is a Release build: it registers for production APNs, and every
// purchase made in it is a Sandbox one. Tying the two together refuses the first tester
// who ever subscribes, and the symptom is push that took a subscription and stayed
// silent.
func TestSandboxTransactionIsRefusedFromProductionUnlessAllowed(t *testing.T) {
	apple := newFakeApple(t, now)
	payload := goodPayload(now.Add(24 * time.Hour))
	payload["environment"] = "Sandbox"
	signed := apple.sign(t, payload)

	strict := verifier(apple)
	if _, err := strict.Verify(signed, "com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("a sandbox transaction must not be admitted by default")
	}

	lenient := verifier(apple)
	lenient.AllowSandbox = true
	if _, err := lenient.Verify(signed, "com.evilforbeginners.Pickles", false, now); err != nil {
		t.Fatalf("with AllowSandbox a TestFlight purchase must be admitted: %v", err)
	}
}

// The exception runs one way only. A production transaction offered by a development
// build is not a beta, it is a mistake.
func TestProductionTransactionIsStillRefusedFromSandbox(t *testing.T) {
	apple := newFakeApple(t, now)
	signed := apple.sign(t, goodPayload(now.Add(24*time.Hour)))
	lenient := verifier(apple)
	lenient.AllowSandbox = true
	if _, err := lenient.Verify(signed, "com.evilforbeginners.Pickles", true, now); err == nil {
		t.Fatal("a production transaction must not be admitted to a sandbox registration")
	}
}

// The WWDR marker has to be read off the chain Go built, not the one the client sent.
//
// `leaf.Verify` returns the chains it actually assembled; checking `chain[1]` instead
// checked whichever certificate the caller put second in x5c, which is a claim and not a
// finding. Here the certificate that really signed the leaf carries no marker and a
// self-signed decoy that carries one sits in its place — so reading the submitted chain
// admits it and reading the verified chain does not (pickles-email#476 item 3).
func TestTheIntermediateIsCheckedOnTheChainGoBuilt(t *testing.T) {
	apple := newFakeAppleMarking(t, now, false)
	// Unmarked to begin with, so the refusal is about the marker and not something else.
	if _, err := verifier(apple).Verify(
		apple.sign(t, goodPayload(now.Add(300*24*time.Hour))),
		"com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("an intermediate with no WWDR marker must be refused")
	}
	apple.insertAfterLeaf(t, selfSignedCarrying(t, oidWWDRIntermediate, now))
	_, err := verifier(apple).Verify(
		apple.sign(t, goodPayload(now.Add(300*24*time.Hour))),
		"com.evilforbeginners.Pickles", false, now)
	if err == nil {
		t.Fatal("a decoy in x5c satisfied the WWDR check")
	}
	if !strings.Contains(err.Error(), "Worldwide Developer Relations") {
		t.Fatalf("refused, but for the wrong reason: %v", err)
	}
}

// revocationDate is only in a JWS if it was there when Apple signed it, so the
// transaction from before a refund stays verifiable until it expires. Requiring a recent
// signature is what makes the device fetch one that carries the revocation — and bounds
// how long a leaked JWS is worth anything (pickles-email#476 item 4).
func TestAStaleSignatureIsRefusedOnlyWhenAnAgeIsSet(t *testing.T) {
	apple := newFakeApple(t, now)
	payload := goodPayload(now.Add(300 * 24 * time.Hour))
	payload["signedDate"] = now.Add(-60 * 24 * time.Hour).UnixMilli()
	jws := apple.sign(t, payload)

	// Unset, which is where it ships until the log says what real devices present.
	unchecked := verifier(apple)
	tx, err := unchecked.Verify(jws, "com.evilforbeginners.Pickles", false, now)
	if err != nil {
		t.Fatalf("with no age configured a stale signature must still be admitted: %v", err)
	}
	if tx.Signed.IsZero() {
		t.Fatal("the signing date was not reported, so nothing can decide what to set")
	}

	checked := verifier(apple)
	checked.MaxSignedAge = 30 * 24 * time.Hour
	if _, err := checked.Verify(jws, "com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("a signature two months old passed a thirty-day limit")
	}

	recent := goodPayload(now.Add(300 * 24 * time.Hour))
	recent["signedDate"] = now.Add(-time.Hour).UnixMilli()
	if _, err := checked.Verify(apple.sign(t, recent), "com.evilforbeginners.Pickles", false, now); err != nil {
		t.Fatalf("an hour-old signature was refused by a thirty-day limit: %v", err)
	}

	// A transaction with no signedDate at all cannot be judged, and once an age is
	// required, "cannot be judged" is a refusal rather than a pass.
	if _, err := checked.Verify(apple.sign(t, goodPayload(now.Add(300*24*time.Hour))),
		"com.evilforbeginners.Pickles", false, now); err == nil {
		t.Fatal("a transaction with no signedDate passed an age check")
	}
}

// A wrong secret is refused whatever its length, and the comparison does not answer
// sooner for one of those than the other (pickles-email#476, also-noted).
func TestAWrongSecretIsRefusedAtEveryLength(t *testing.T) {
	policy := Policy{Secret: "the-right-secret"}
	for _, presented := range []string{"", "x", "the-right-secre", "the-right-secret-and-more", "THE-RIGHT-SECRET"} {
		if _, err := policy.Admit("Bearer "+presented, "", "com.evilforbeginners.Pickles", false, now); err == nil {
			t.Fatalf("admitted %q", presented)
		}
	}
	if _, err := policy.Admit("Bearer the-right-secret", "", "com.evilforbeginners.Pickles", false, now); err != nil {
		t.Fatalf("the right secret was refused: %v", err)
	}
}

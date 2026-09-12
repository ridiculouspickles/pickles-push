package entitlement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	_ "embed"
)

// AppleVerifier accepts a StoreKit 2 signed transaction (a JWS Apple issues to the
// device) as proof of a live subscription.
//
// Verification is entirely offline. The JWS carries its certificate chain in the
// header; the chain is checked to Apple Root CA G3, which is embedded here, and the
// signature is checked against the leaf. Nothing is sent to Apple and nothing is kept:
// the relay learns that *some* subscription exists for this bundle until a date, and
// that is all it needs to know.
//
// A transaction from Xcode's local StoreKit configuration is signed by a certificate
// Xcode made up and will not verify here. That is correct: a development build talks
// to a relay with a secret, not to ours.
type AppleVerifier struct {
	// ProductIDs are the subscriptions accepted, e.g. the yearly one.
	ProductIDs []string
	// Roots to trust. Nil means Apple's.
	Roots *x509.CertPool
	// Grace is how long past its expiry a transaction still counts. A renewal reaches
	// the relay through the device's daily re-registration, and the device may be off
	// for a day or two across a renewal; the grace is what keeps its push alive
	// meanwhile.
	Grace time.Duration
	// AllowSandbox admits a Sandbox StoreKit transaction from a device registered for
	// production APNs.
	//
	// **This is what TestFlight needs, and it is off by default.** A TestFlight build
	// is a Release build, so it registers for the production APNs environment -- but
	// every purchase made in TestFlight is a Sandbox one. Tying the two together, which
	// is the obvious reading, refuses the first tester who ever subscribes, and the
	// symptom is push that took a subscription and then stayed silent.
	//
	// It is a deliberate hole while it is open: a Sandbox transaction costs nobody
	// anything, so anyone who can build against this bundle id can mint one. Turn it
	// off when the beta ends.
	AllowSandbox bool
	// MaxSignedAge is how old Apple's signature on the transaction may be. Zero does
	// not check it.
	//
	// `revocationDate` is only in the JWS if it was there when Apple signed it, so a
	// refunded subscriber can present the *pre-refund* JWS until its expiry plus the
	// grace and be admitted every time. Requiring a recent signature forces the device
	// to bring a re-signed transaction, which carries the revocation — and bounds how
	// long a leaked JWS is worth anything (pickles-email#476 item 4).
	//
	// **Left at zero until we know what real devices present.** A window shorter than
	// StoreKit's own refresh interval refuses a paying subscriber and the symptom is
	// silence, which is the failure this whole component is written to avoid. Verify
	// reports the age on every admission so the distribution can be read off the log
	// first.
	MaxSignedAge time.Duration
}

// Transaction is the part of the payload the relay reads.
type Transaction struct {
	BundleID    string
	ProductID   string
	Type        string
	Environment string
	Expires     time.Time
	// Signed is when Apple signed this JWS, which is not when the subscription
	// started. See MaxSignedAge.
	Signed time.Time
}

//go:embed AppleRootCA-G3.pem
var appleRootPEM []byte

// AppleRoots is Apple Root CA - G3, from
// https://www.apple.com/certificateauthority/AppleRootCA-G3.cer, SHA-256
// 63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179. Valid to 2039.
func AppleRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(appleRootPEM) {
		panic("entitlement: the embedded Apple root did not parse")
	}
	return pool
}

var (
	// Marks a certificate Apple issued for signing App Store receipts and transactions.
	oidAppStoreSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	// Marks the Apple Worldwide Developer Relations intermediate.
	oidWWDRIntermediate = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
)

const autoRenewable = "Auto-Renewable Subscription"

// Verify checks the JWS and its claims against what this device says it is.
func (v *AppleVerifier) Verify(jws, bundleID string, sandbox bool, now time.Time) (Transaction, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return Transaction{}, errors.New("transaction is not a JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Transaction{}, errors.New("transaction header is not base64url")
	}
	var header struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Transaction{}, errors.New("transaction header is not JSON")
	}
	if header.Alg != "ES256" {
		return Transaction{}, fmt.Errorf("transaction algorithm %q is not ES256", header.Alg)
	}
	if len(header.X5C) < 2 {
		return Transaction{}, errors.New("transaction carries no certificate chain")
	}
	chain := make([]*x509.Certificate, 0, len(header.X5C))
	for _, encoded := range header.X5C {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return Transaction{}, errors.New("certificate in chain is not base64")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return Transaction{}, errors.New("certificate in chain did not parse")
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	roots := v.Roots
	if roots == nil {
		roots = AppleRoots()
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return Transaction{}, errors.New("certificate chain does not lead to Apple")
	}
	// **The verified chain, not the submitted one.** Verify returns the chains it
	// actually built; checking the WWDR marker on `chain[1]` instead checked whichever
	// certificate the client happened to put second, which is a claim rather than a
	// finding. It has never differed in practice — Go builds the same chain the JWS
	// carries — and that is exactly why reading the wrong one would never have shown up
	// (pickles-email#476 item 3).
	verified := chains[0]
	if len(verified) < 2 {
		return Transaction{}, errors.New("certificate chain has no intermediate")
	}
	if !hasExtension(leaf, oidAppStoreSigning) {
		return Transaction{}, errors.New("signing certificate is not an App Store one")
	}
	if !hasExtension(verified[1], oidWWDRIntermediate) {
		return Transaction{}, errors.New("intermediate is not Apple Worldwide Developer Relations")
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return Transaction{}, errors.New("signing key is not P-256")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return Transaction{}, errors.New("transaction signature is malformed")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(public, digest[:], r, s) {
		return Transaction{}, errors.New("transaction signature does not verify")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Transaction{}, errors.New("transaction payload is not base64url")
	}
	var payload struct {
		BundleID       string `json:"bundleId"`
		ProductID      string `json:"productId"`
		Type           string `json:"type"`
		Environment    string `json:"environment"`
		ExpiresDate    int64  `json:"expiresDate"`
		RevocationDate int64  `json:"revocationDate"`
		SignedDate     int64  `json:"signedDate"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return Transaction{}, errors.New("transaction payload is not JSON")
	}
	tx := Transaction{
		BundleID:    payload.BundleID,
		ProductID:   payload.ProductID,
		Type:        payload.Type,
		Environment: payload.Environment,
		Expires:     time.UnixMilli(payload.ExpiresDate).UTC(),
	}
	if payload.SignedDate != 0 {
		tx.Signed = time.UnixMilli(payload.SignedDate).UTC()
	}
	if tx.BundleID != bundleID {
		return tx, errors.New("transaction is for another app")
	}
	if !contains(v.ProductIDs, tx.ProductID) {
		return tx, errors.New("transaction is for another product")
	}
	if tx.Type != autoRenewable {
		return tx, errors.New("transaction is not a subscription")
	}
	if payload.RevocationDate != 0 {
		return tx, errors.New("subscription was refunded or revoked")
	}
	if payload.ExpiresDate == 0 {
		return tx, errors.New("subscription has no expiry")
	}
	if v.MaxSignedAge > 0 {
		switch {
		case tx.Signed.IsZero():
			return tx, errors.New("transaction does not say when it was signed")
		case now.Sub(tx.Signed) > v.MaxSignedAge:
			// The device has one: StoreKit re-signs on renewal and on refresh. What it
			// is holding is old enough that a refund since would not be in it.
			return tx, errors.New("transaction was signed too long ago; the device needs a current one")
		case tx.Signed.After(now.Add(24 * time.Hour)):
			return tx, errors.New("transaction is signed in the future")
		}
	}
	wanted := "Production"
	if sandbox {
		wanted = "Sandbox"
	}
	// A Sandbox transaction from a production registration is what every TestFlight
	// tester has; see AllowSandbox. Nothing else is ever admitted from the wrong
	// environment -- a Production transaction offered to a sandbox registration is
	// still refused, because that direction is not a beta, it is a mistake.
	sandboxException := v.AllowSandbox && tx.Environment == "Sandbox"
	if tx.Environment != wanted && !sandboxException {
		return tx, fmt.Errorf("transaction is from the %s environment", strings.ToLower(tx.Environment))
	}
	if !now.Before(tx.Expires.Add(v.Grace)) {
		return tx, errors.New("subscription has expired")
	}
	return tx, nil
}

func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

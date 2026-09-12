package relay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tokens are minted here with a key installed in sharedJWKS, so verifyPubSub checks a
// real RS256 signature rather than a stub.

const (
	testAudience       = "3f9c2b7e0d514a8e9b6c1f2a7d4e5b60"
	testServiceAccount = "pickles-push@pickles-email.iam.gserviceaccount.com"
	testKid            = "test-signing-key"
)

var testNow = time.Unix(1_700_000_000, 0)

func installSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sharedJWKS.mu.Lock()
	savedKeys, savedFetched := sharedJWKS.keys, sharedJWKS.fetched
	sharedJWKS.keys = map[string]*rsa.PublicKey{testKid: &key.PublicKey}
	sharedJWKS.fetched = time.Now()
	sharedJWKS.mu.Unlock()
	t.Cleanup(func() {
		sharedJWKS.mu.Lock()
		sharedJWKS.keys, sharedJWKS.fetched = savedKeys, savedFetched
		sharedJWKS.mu.Unlock()
	})
	return key
}

func mint(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signingInput := encode(map[string]string{"alg": "RS256", "kid": testKid, "typ": "JWT"}) +
		"." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// claimsFor is a token as the push subscription's own account would have it minted:
// everything right, and the account given.
func claimsFor(email string) map[string]any {
	return map[string]any{
		"aud":            testAudience,
		"iss":            "https://accounts.google.com",
		"exp":            testNow.Add(time.Hour).Unix(),
		"iat":            testNow.Unix(),
		"email":          email,
		"email_verified": true,
	}
}

func gmailRelay(t *testing.T) (*Relay, *recordingPusher) {
	t.Helper()
	r, pusher := newRelay(t)
	r.GmailAudience = testAudience
	r.GmailServiceAccount = testServiceAccount
	r.Now = func() time.Time { return testNow }
	return r, pusher
}

func gmailPush(r *Relay, token, address string) *httptest.ResponseRecorder {
	data := base64.StdEncoding.EncodeToString(
		[]byte(`{"emailAddress":"` + address + `","historyId":42}`))
	request := httptest.NewRequest(http.MethodPost, "/v1/gmail",
		strings.NewReader(`{"message":{"data":"`+data+`"}}`))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	return recorder
}

// The attack in #458, end to end: a token Google really signed, for the right audience,
// minted for some other account. The same push from the subscription's own account goes
// through, so the refusal is about the account and nothing else.
func TestGmailPushFromAnotherGoogleAccountIsRefused(t *testing.T) {
	key := installSigningKey(t)
	r, pusher := gmailRelay(t)
	register(t, r, `{"deviceToken":"abcdef0123456789abcdef0123456789",`+
		`"topic":"net.pickles.mail.dev","sandbox":true,"gmailAddress":"victim@gmail.com"}`)

	forged := mint(t, key, claimsFor("someone@their-own-project.iam.gserviceaccount.com"))
	if code := gmailPush(r, forged, "victim@gmail.com").Code; code != http.StatusForbidden {
		t.Fatalf("a token minted for another account got %d, want 403", code)
	}
	if len(pusher.all()) != 0 {
		t.Fatal("a token minted for another account woke the device")
	}

	genuine := mint(t, key, claimsFor(testServiceAccount))
	if code := gmailPush(r, genuine, "victim@gmail.com").Code; code != http.StatusNoContent {
		t.Fatalf("the subscription's own token got %d, want 204", code)
	}
	if len(pusher.all()) != 1 {
		t.Fatalf("the subscription's own token sent %d pushes, want 1", len(pusher.all()))
	}
}

func TestPubSubTokenClaims(t *testing.T) {
	key := installSigningKey(t)
	r, _ := gmailRelay(t)

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		believe bool
	}{
		{"the subscription's account", func(map[string]any) {}, true},
		{"the account in another case", func(c map[string]any) {
			c["email"] = strings.ToUpper(testServiceAccount)
		}, true},
		{"email_verified written as a string", func(c map[string]any) {
			c["email_verified"] = "true"
		}, true},
		{"another account", func(c map[string]any) {
			c["email"] = "attacker@example.iam.gserviceaccount.com"
		}, false},
		{"no account at all", func(c map[string]any) { delete(c, "email") }, false},
		{"the account, unverified", func(c map[string]any) { c["email_verified"] = false }, false},
		{"the account, verification missing", func(c map[string]any) {
			delete(c, "email_verified")
		}, false},
		{"the right account for the wrong audience", func(c map[string]any) {
			c["aud"] = "https://push-a.example.com/v1/gmail"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := claimsFor(testServiceAccount)
			tc.mutate(claims)
			request := httptest.NewRequest(http.MethodPost, "/v1/gmail", nil)
			request.Header.Set("Authorization", "Bearer "+mint(t, key, claims))
			err := r.verifyPubSub(request)
			if tc.believe && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.believe && err == nil {
				t.Fatal("believed")
			}
		})
	}
}

// Configured with an audience and no account, the relay would check everything a token
// from anybody's project already passes. Closed, not half-open.
func TestGmailEndpointIsClosedWithoutAServiceAccount(t *testing.T) {
	key := installSigningKey(t)
	r, pusher := gmailRelay(t)
	r.GmailServiceAccount = ""

	token := mint(t, key, claimsFor("anyone@example.iam.gserviceaccount.com"))
	if code := gmailPush(r, token, "victim@gmail.com").Code; code != http.StatusNotFound {
		t.Fatalf("with no service account configured the endpoint must not exist, got %d", code)
	}
	if len(pusher.all()) != 0 {
		t.Fatal("a push was sent with no service account configured")
	}
}

// `alg` and `kid` are read before the signature can be checked — `kid` is what chooses
// the key — so an unauthenticated caller writes them, and the refusal is logged. One
// line per refusal, not one line of whatever length the caller picked
// (pickles-email#475).
func TestARefusalQuotesAtMostSixtyFourBytesOfWhatTheCallerSent(t *testing.T) {
	r, _ := gmailRelay(t)
	encode := func(value any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	for _, header := range []map[string]string{
		{"alg": strings.Repeat("A", 4000), "kid": testKid},
		{"alg": "RS256", "kid": strings.Repeat("K", 4000)},
	} {
		token := encode(header) + "." + encode(claimsFor(testServiceAccount)) + ".signature"
		request := httptest.NewRequest(http.MethodPost, "/v1/gmail", strings.NewReader("{}"))
		request.Header.Set("authorization", "Bearer "+token)
		err := r.verifyPubSub(request)
		if err == nil {
			t.Fatalf("expected a refusal for %v", header)
		}
		if len(err.Error()) > 128 {
			t.Fatalf("a refusal ran to %d bytes: %q", len(err.Error()), err)
		}
	}
}

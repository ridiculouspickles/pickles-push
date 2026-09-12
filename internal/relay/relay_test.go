package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ridiculouspickles/pickles-push/internal/apns"
	"github.com/ridiculouspickles/pickles-push/internal/store"
)

type recordingPusher struct {
	mu   sync.Mutex
	sent []apns.Notification
	err  error
}

func (p *recordingPusher) Push(_ context.Context, n apns.Notification) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, n)
	return p.err
}

func (p *recordingPusher) all() []apns.Notification {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]apns.Notification(nil), p.sent...)
}

func newRelay(t *testing.T) (*Relay, *recordingPusher) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	pusher := &recordingPusher{}
	return &Relay{
		Store:     s,
		Pusher:    pusher,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		PublicURL: "https://push-a.example.com",
	}, pusher
}

func register(t *testing.T, r *Relay, body string) registerResponse {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("register returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response registerResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

const goodRegistration = `{"deviceToken":"abcdef0123456789abcdef0123456789","topic":"net.pickles.mail.dev","sandbox":true}`

func TestRegisterReturnsThisSitesURL(t *testing.T) {
	r, _ := newRelay(t)
	response := register(t, r, goodRegistration)
	if !strings.HasPrefix(response.PushURL, "https://push-a.example.com/v1/push/") {
		// Each site hands out its own URL; a device holds one subscription per site and
		// they must not collide.
		t.Fatalf("push URL was %q", response.PushURL)
	}
	if !validToken(response.Token) {
		t.Fatalf("token %q is not the shape we issue", response.Token)
	}
}

func TestRegisterRejectsANonHexDeviceToken(t *testing.T) {
	r, _ := newRelay(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/register",
		strings.NewReader(`{"deviceToken":"not a token at all uh huh","topic":"x"}`))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}

func TestReregisteringKeepsTheSameToken(t *testing.T) {
	r, _ := newRelay(t)
	first := register(t, r, goodRegistration)
	// A device re-registers on every foreground. If that minted a new token it would
	// have to recreate its provider subscription each time, which is the opposite of
	// what re-registration is for.
	again := register(t, r, `{"deviceToken":"abcdef0123456789abcdef0123456789",`+
		`"topic":"net.pickles.mail.dev","sandbox":true,"token":"`+first.Token+`"}`)
	if again.Token != first.Token {
		t.Fatalf("token changed on re-registration: %q then %q", first.Token, again.Token)
	}
	if r.Store.Count() != 1 {
		t.Fatalf("re-registration created a second row: %d", r.Store.Count())
	}
}

func TestPushForwardsThePayloadWithoutReadingIt(t *testing.T) {
	r, pusher := newRelay(t)
	response := register(t, r, goodRegistration)

	// Deliberately not JSON, and not anything we could parse if we wanted to: this is
	// what an RFC 8291 encrypted StateChange looks like from here.
	ciphertext := []byte{0x00, 0x01, 0xff, 0xfe, 0x7f, 0x80}
	request := httptest.NewRequest(http.MethodPost, "/v1/push/"+response.Token,
		strings.NewReader(string(ciphertext)))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	sent := pusher.all()
	if len(sent) != 1 {
		t.Fatalf("expected one push, got %d", len(sent))
	}
	var payload struct {
		APS map[string]any `json:"aps"`
		P   string         `json:"p"`
	}
	if err := json.Unmarshal(sent[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload.P)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(ciphertext) {
		t.Fatal("the payload reached Apple altered")
	}
	if payload.APS["mutable-content"] != float64(1) {
		// Without this the service extension never runs and the reader only ever sees
		// the placeholder.
		t.Fatalf("alert push must be mutable: %v", payload.APS)
	}
	if sent[0].Background {
		t.Fatal("default mode must be an alert, or nothing is ever visible")
	}
	if !sent[0].Sandbox {
		t.Fatal("sandbox flag did not reach the client, so the push would go to the wrong host")
	}
}

func TestBackgroundModeSendsASilentPush(t *testing.T) {
	r, pusher := newRelay(t)
	response := register(t, r, `{"deviceToken":"abcdef0123456789abcdef0123456789",`+
		`"topic":"net.pickles.mail.dev","mode":"background"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/push/"+response.Token, strings.NewReader("x"))
	r.Routes().ServeHTTP(httptest.NewRecorder(), request)

	sent := pusher.all()
	if len(sent) != 1 || !sent[0].Background {
		t.Fatalf("expected one background push, got %+v", sent)
	}
	var payload struct {
		APS map[string]any `json:"aps"`
	}
	_ = json.Unmarshal(sent[0].Payload, &payload)
	if _, ok := payload.APS["alert"]; ok {
		// A secondary site must be able to deliver without raising a second banner.
		t.Fatal("a background push must carry no alert")
	}
	if payload.APS["content-available"] != float64(1) {
		t.Fatalf("background push needs content-available: %v", payload.APS)
	}
}

func TestPushToAnUnknownTokenIs404AndSendsNothing(t *testing.T) {
	r, pusher := newRelay(t)
	request := httptest.NewRequest(http.MethodPost,
		"/v1/push/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.NewReader("x"))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
	if len(pusher.all()) != 0 {
		t.Fatal("an unknown token must not cause a push")
	}
}

func TestOversizedPayloadIsRefused(t *testing.T) {
	r, pusher := newRelay(t)
	response := register(t, r, goodRegistration)
	request := httptest.NewRequest(http.MethodPost, "/v1/push/"+response.Token,
		strings.NewReader(strings.Repeat("x", maxPayload+1)))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", recorder.Code)
	}
	if len(pusher.all()) != 0 {
		t.Fatal("nothing oversized should reach Apple, which would reject it anyway")
	}
}

func TestAppleSayingGoneDropsTheRegistration(t *testing.T) {
	r, pusher := newRelay(t)
	response := register(t, r, goodRegistration)
	pusher.err = apns.ErrUnregistered

	request := httptest.NewRequest(http.MethodPost, "/v1/push/"+response.Token, strings.NewReader("x"))
	r.Routes().ServeHTTP(httptest.NewRecorder(), request)

	if _, err := r.Store.Get(response.Token); err == nil {
		// Apple only tells us once. Keeping the row means pushing into the void for a
		// month until Prune notices.
		t.Fatal("a registration Apple reported as gone was kept")
	}
}

func TestUnregisterIsQuietAboutWhetherATokenExisted(t *testing.T) {
	r, _ := newRelay(t)
	for _, token := range []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "not-a-valid-token"} {
		request := httptest.NewRequest(http.MethodDelete, "/v1/register/"+token, nil)
		recorder := httptest.NewRecorder()
		r.Routes().ServeHTTP(recorder, request)
		// Distinguishing "malformed" from "unknown" would turn this into an oracle that
		// confirms whether a guessed token is real.
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("token %q gave %d", token, recorder.Code)
		}
	}
}

func TestGmailEndpointIsClosedUnlessConfigured(t *testing.T) {
	r, _ := newRelay(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/gmail", strings.NewReader("{}"))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("with no audience configured the endpoint must not exist, got %d", recorder.Code)
	}
}

func TestGmailEndpointRefusesAnUnsignedRequest(t *testing.T) {
	r, pusher := newRelay(t)
	r.GmailAudience = "https://push-a.example.com/v1/gmail"
	r.GmailServiceAccount = "push@pickles-email.iam.gserviceaccount.com"
	r.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	body := `{"message":{"data":"eyJlbWFpbEFkZHJlc3MiOiJhQGdtYWlsLmNvbSIsImhpc3RvcnlJZCI6MX0="}}`
	request := httptest.NewRequest(http.MethodPost, "/v1/gmail", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		// Unauthenticated, this endpoint lets anyone claim any address has mail and
		// wake somebody's phone all night.
		t.Fatalf("expected 403 with no bearer token, got %d", recorder.Code)
	}
	if len(pusher.all()) != 0 {
		t.Fatal("an unverified Pub/Sub request caused a push")
	}
}

// Health says the process is up, and nothing about who it is serving. It used to
// report the number of registrations — a subscriber count, on the one endpoint that is
// deliberately unauthenticated so a monitor can reach it (pickles-email#476).
func TestHealthSaysOnlyThatItIsUp(t *testing.T) {
	r, _ := newRelay(t)
	register(t, r, goodRegistration)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("health returned %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"ok":true`) {
		t.Fatalf("health said %q", body)
	}
	for _, leak := range []string{"registrations", "abcdef0123456789"} {
		if strings.Contains(body, leak) {
			t.Fatalf("health leaked %q: %s", leak, body)
		}
	}
}

func TestValidTokenShape(t *testing.T) {
	if !validToken("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("32 url-safe characters is the shape we issue")
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 33), "aaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if validToken(bad) {
			t.Fatalf("%q should not have passed", bad)
		}
	}
}

func TestASecretGuardsRegistration(t *testing.T) {
	r, _ := newRelay(t)
	r.Policy.Secret = "hunter2"
	refused := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(goodRegistration))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, refused)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("without the secret: %d", recorder.Code)
	}
	if r.Store.Count() != 0 {
		t.Fatal("a refused registration must not be stored")
	}
	admitted := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(goodRegistration))
	admitted.Header.Set("Authorization", "Bearer hunter2")
	recorder = httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, admitted)
	if recorder.Code != http.StatusOK {
		t.Fatalf("with the secret: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestALapsedRegistrationGetsNothing(t *testing.T) {
	r, pusher := newRelay(t)
	response := register(t, r, goodRegistration)
	registration, err := r.Store.Get(response.Token)
	if err != nil {
		t.Fatal(err)
	}
	registration.ExpiresAt = time.Now().Add(-time.Minute)
	if err := r.Store.Put(registration); err != nil {
		t.Fatal(err)
	}
	push := httptest.NewRequest(http.MethodPost, "/v1/push/"+response.Token, strings.NewReader("ciphertext"))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, push)
	if recorder.Code != http.StatusOK {
		// The provider is still told 200: a lapsed subscriber's server should not
		// retry, and the subscription should survive a renewal.
		t.Fatalf("push returned %d", recorder.Code)
	}
	if len(pusher.all()) != 0 {
		t.Fatal("nothing should reach Apple for a lapsed registration")
	}
}

// A JMAP push naming a token the relay has never held is the shape of a subscription
// that outlived its device registration. It answers 404 -- never 410, which would have
// the provider destroy the subscription while a device is mid-re-registration.
func TestJMAPPushForAnUnknownTokenIsNotFound(t *testing.T) {
	relay, _ := newRelay(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		"POST", "/v1/push/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.NewReader("{}"))
	relay.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("want 404 for an unknown delivery token, got %d", recorder.Code)
	}
}

// `mode` is a client string, and Put's refusal quotes it: `unknown mode %q`. The relay
// logged that error under a comment promising it never logged a value, so a registration
// carrying 8 KiB of junk in `mode` put 8 KiB of junk in relay.log (pickles-email#475).
func TestAnUnknownModeIsRefusedWithoutLoggingIt(t *testing.T) {
	r, _ := newRelay(t)
	var log strings.Builder
	r.Log = slog.New(slog.NewTextHandler(&log, nil))

	shout := strings.Repeat("shout", 400)
	request := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(
		`{"deviceToken":"abcdef0123456789abcdef0123456789","topic":"net.pickles.mail.dev","mode":"`+
			shout+`"}`))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
	if strings.Contains(log.String(), "shout") {
		t.Fatalf("the mode the client sent reached the log: %q", log.String())
	}
	if r.Store.Count() != 0 {
		t.Fatal("a registration with no usable mode was stored anyway")
	}
}

// A registration is not a StateChange and does not fit in a StateChange's budget: a real
// StoreKit signed transaction carries its certificate chain, about 6 KB of the 8 KiB the
// two used to share, and one more certificate from Apple would have taken it over
// (pickles-email#476 item 5).
func TestARegistrationMayBeLargerThanAStateChange(t *testing.T) {
	r, _ := newRelay(t)
	// Bigger than maxPayload, smaller than maxRegistration. The relay is open here, so
	// the transaction is not read — this is about what may be *sent*.
	body := `{"deviceToken":"abcdef0123456789abcdef0123456789","topic":"net.pickles.mail.dev",` +
		`"transaction":"` + strings.Repeat("j", 12<<10) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a 12 KiB registration returned %d: %s", recorder.Code, recorder.Body.String())
	}

	// There is still a limit, and it says which limit it was.
	var log strings.Builder
	r.Log = slog.New(slog.NewTextHandler(&log, nil))
	huge := `{"deviceToken":"abcdef0123456789abcdef0123456789","topic":"net.pickles.mail.dev",` +
		`"transaction":"` + strings.Repeat("j", 64<<10) + `"}`
	request = httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(huge))
	recorder = httptest.NewRecorder()
	r.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 64 KiB registration returned %d", recorder.Code)
	}
	if !strings.Contains(log.String(), "registration refused") {
		t.Fatalf("the refusal was not distinguishable in the log: %q", log.String())
	}
	if strings.Contains(log.String(), "jjjj") {
		t.Fatal("the body reached the log")
	}
}

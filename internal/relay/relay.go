// Package relay is the HTTP surface: registration, the JMAP push endpoint, and the
// Gmail Pub/Sub endpoint.
//
// The design rule this package exists to enforce: **nothing here reads a payload.** The
// JMAP body arrives encrypted to a key only the device has (RFC 8291) and is forwarded as
// opaque bytes. There is no branch anywhere in this file that depends on what a message
// says, because there is no code here that could find out.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/yeled/pickles-push/internal/apns"
	"github.com/yeled/pickles-push/internal/store"
)

// maxPayload caps what we will read from a provider.
//
// A JMAP StateChange is a few hundred bytes and APNs refuses more than 4 KiB of payload
// anyway, so anything larger is a mistake or an attack and there is no reason to buffer
// it.
const maxPayload = 8 << 10

// Pusher is the half of apns.Client this package uses, so tests need no network.
type Pusher interface {
	Push(ctx context.Context, n apns.Notification) error
}

type Relay struct {
	Store  *store.Store
	Pusher Pusher
	Log    *slog.Logger
	// Now is swappable for tests.
	Now func() time.Time
	// PublicURL is this site's base URL, used to tell a device where to point its
	// subscription. Each site has its own; they are never the same address.
	PublicURL string
	// GmailAudience, when set, is the expected `aud` of the OIDC token Cloud Pub/Sub
	// sends. Empty disables Gmail entirely.
	GmailAudience string
}

func (r *Relay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Relay) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", r.handleRegister)
	mux.HandleFunc("DELETE /v1/register/{token}", r.handleUnregister)
	mux.HandleFunc("POST /v1/push/{token}", r.handleJMAPPush)
	mux.HandleFunc("POST /v1/gmail", r.handleGmailPush)
	mux.HandleFunc("GET /healthz", r.handleHealth)
	return mux
}

// ---------------------------------------------------------------- registration

type registerRequest struct {
	DeviceToken  string `json:"deviceToken"`
	Topic        string `json:"topic"`
	Sandbox      bool   `json:"sandbox"`
	Mode         string `json:"mode"`
	GmailAddress string `json:"gmailAddress,omitempty"`
	// Token is sent when re-registering. A device keeps its delivery token for the life
	// of its subscription, because changing it would mean recreating the subscription
	// at the provider on every foreground.
	Token string `json:"token,omitempty"`
}

type registerResponse struct {
	Token   string `json:"token"`
	PushURL string `json:"pushUrl"`
}

// handleRegister creates or refreshes a registration.
//
// Deliberately unauthenticated. There is no account here to attach it to, and the only
// thing an attacker gains by registering is the ability to have their own device woken
// up. What must not happen is *unbounded* registration, which is what the rate limiter in
// front of this is for.
func (r *Relay) handleRegister(w http.ResponseWriter, request *http.Request) {
	var body registerRequest
	if err := json.NewDecoder(io.LimitReader(request.Body, maxPayload)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if body.DeviceToken == "" || body.Topic == "" {
		http.Error(w, "deviceToken and topic are required", http.StatusBadRequest)
		return
	}
	if !validDeviceToken(body.DeviceToken) {
		http.Error(w, "deviceToken must be hex", http.StatusBadRequest)
		return
	}
	mode := store.Mode(body.Mode)
	if body.Mode == "" {
		mode = store.Alert
	}
	token := body.Token
	if token == "" {
		var err error
		if token, err = newToken(); err != nil {
			r.Log.Error("token generation failed", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else if !validToken(token) {
		http.Error(w, "malformed token", http.StatusBadRequest)
		return
	}
	now := r.now()
	registration := store.Registration{
		Token:        token,
		DeviceToken:  body.DeviceToken,
		Topic:        body.Topic,
		Sandbox:      body.Sandbox,
		Mode:         mode,
		GmailAddress: body.GmailAddress,
		SeenAt:       now,
	}
	if err := r.Store.Put(registration); err != nil {
		// Never the value: an error from Put can quote what it was given.
		r.Log.Error("registration rejected", "error", err.Error())
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, registerResponse{
		Token:   token,
		PushURL: strings.TrimSuffix(r.PublicURL, "/") + "/v1/push/" + token,
	})
}

func (r *Relay) handleUnregister(w http.ResponseWriter, request *http.Request) {
	token := request.PathValue("token")
	if !validToken(token) {
		// Same answer as a token that is simply not here. An endpoint that distinguishes
		// "malformed" from "unknown" is an endpoint that confirms tokens for you.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := r.Store.Delete(token); err != nil {
		r.Log.Error("delete failed", "error", err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- JMAP push

// handleJMAPPush is what a JMAP server POSTs a StateChange to.
//
// The body is forwarded without being parsed. On the JMAP path the relay does not learn
// the account id, the mailbox, or that the change was mail at all — the StateChange is
// encrypted to the device's key before it ever leaves the provider.
//
// This also carries the PushVerification handshake (RFC 8620 § 7.2.2), which is the same
// shape and equally opaque: the device completes it, not us.
func (r *Relay) handleJMAPPush(w http.ResponseWriter, request *http.Request) {
	token := request.PathValue("token")
	if !validToken(token) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	registration, err := r.Store.Get(token)
	if err != nil {
		// 404 rather than 410: a device that is mid-re-registration should not cause its
		// provider to tear the subscription down.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maxPayload+1))
	if err != nil || len(payload) > maxPayload {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.deliver(request.Context(), registration, payload)
	// 200 unconditionally once the push is on its way. A JMAP server that reads a 5xx
	// will retry, and a retry produces a second notification to suppress on a device
	// that has very likely already had the first.
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------- Gmail push

type pubsubEnvelope struct {
	Message struct {
		Data      string `json:"data"`
		MessageID string `json:"messageId"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

type gmailNotification struct {
	EmailAddress string `json:"emailAddress"`
	HistoryID    uint64 `json:"historyId"`
}

// handleGmailPush receives a Cloud Pub/Sub push.
//
// **This is the one endpoint that learns who you are**, and it is unavoidable: Pub/Sub
// names the mailbox in the clear and there is no RFC 8291 on this path. The relay reads
// the address because it is the only routing key available, and reads nothing else — the
// historyId is a cursor, not content, and is forwarded for the device to act on.
//
// See ADR-0017. The honest sentence is "on JMAP the relay cannot identify you; on Gmail
// it knows your address and nothing else."
func (r *Relay) handleGmailPush(w http.ResponseWriter, request *http.Request) {
	if r.GmailAudience == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := r.verifyPubSub(request); err != nil {
		r.Log.Warn("pub/sub rejected", "error", err.Error())
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var envelope pubsubEnvelope
	if err := json.NewDecoder(io.LimitReader(request.Body, maxPayload)).Decode(&envelope); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Message.Data)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var notification gmailNotification
	if err := json.Unmarshal(raw, &notification); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	registrations := r.Store.ByGmail(notification.EmailAddress)
	// Acknowledge either way. Pub/Sub redelivers on anything but a 2xx, and redelivering
	// to an address nobody has registered would go on for a week.
	payload, err := json.Marshal(map[string]any{"historyId": notification.HistoryID})
	if err == nil {
		encoded := base64.RawURLEncoding.EncodeToString(payload)
		for _, registration := range registrations {
			r.deliver(request.Context(), registration, []byte(encoded))
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- delivery

// deliver wraps an opaque payload in the smallest APNs envelope that will carry it.
//
// The alert text is a placeholder and is meant to be replaced: the device's notification
// service extension decrypts `p`, works out what actually arrived, and rewrites the
// notification locally before it is shown. If the extension fails or runs out of its
// thirty seconds, the reader sees "New mail", which is true and says nothing.
func (r *Relay) deliver(ctx context.Context, registration store.Registration, payload []byte) {
	background := registration.Mode == store.Background
	aps := map[string]any{}
	if background {
		aps["content-available"] = 1
	} else {
		aps["alert"] = map[string]any{"loc-key": "NEW_MAIL"}
		aps["mutable-content"] = 1
		aps["sound"] = "default"
	}
	body, err := json.Marshal(map[string]any{
		"aps": aps,
		// The provider's payload, untouched. Base64 because APNs bodies are JSON and
		// this is ciphertext.
		"p": base64.RawURLEncoding.EncodeToString(payload),
	})
	if err != nil {
		r.Log.Error("payload encode failed", "error", err.Error())
		return
	}
	err = r.Pusher.Push(ctx, apns.Notification{
		DeviceToken: registration.DeviceToken,
		Topic:       registration.Topic,
		Sandbox:     registration.Sandbox,
		Background:  background,
		Payload:     body,
	})
	switch {
	case err == nil:
	case errors.Is(err, apns.ErrUnregistered):
		// Apple says this device is gone. Believe it — this is the only signal we get,
		// and keeping the row means pushing into the void until Prune notices.
		if deleteErr := r.Store.Delete(registration.Token); deleteErr != nil {
			r.Log.Error("could not drop dead registration", "error", deleteErr.Error())
		}
		r.Log.Info("dropped a registration Apple reported as gone")
	default:
		r.Log.Error("push failed", "error", err.Error())
	}
}

func (r *Relay) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"registrations": r.Store.Count(),
	})
}

// ---------------------------------------------------------------- helpers

func newToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// validToken checks shape only. It is a cheap gate in front of the store, not a check
// that the token means anything.
func validToken(token string) bool {
	if len(token) != 32 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func validDeviceToken(token string) bool {
	if len(token) < 32 || len(token) > 200 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

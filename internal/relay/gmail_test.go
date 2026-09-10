package relay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Gmail's own notifications carry historyId as a number; the Gmail API renders the
// same value as a string everywhere else, and so did the first message ever
// published to the topic by hand. The device treats it as an opaque cursor, so the
// relay keeps whichever spelling arrived rather than refusing one of them.
func TestHistoryIDAcceptsNumberOrString(t *testing.T) {
	for _, raw := range []string{
		`{"emailAddress":"a@example.com","historyId":9876543210}`,
		`{"emailAddress":"a@example.com","historyId":"9876543210"}`,
	} {
		var n gmailNotification
		if err := json.Unmarshal([]byte(raw), &n); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if n.HistoryID != "9876543210" {
			t.Fatalf("%s: historyId = %q", raw, n.HistoryID)
		}
	}
	// What the device receives is the same cursor, as text, whichever way it came.
	out, err := json.Marshal(map[string]any{"historyId": historyID("42")})
	if err != nil || string(out) != `{"historyId":"42"}` {
		t.Fatalf("payload = %s, %v", out, err)
	}
}

func TestHistoryIDRefusesNonsense(t *testing.T) {
	var n gmailNotification
	if err := json.Unmarshal([]byte(`{"emailAddress":"a@example.com","historyId":true}`), &n); err == nil {
		t.Fatal("a boolean is not a cursor")
	}
}

// The device decodes `p` once. A Gmail payload that was encoded on the way into
// deliver *and* again inside it arrived as a base64 string: not JSON to parse, not a
// well-formed RFC 8291 body to decrypt, and every Gmail push reported
// "decrypt: malformed" on the phone.
func TestDeliverEncodesThePayloadExactlyOnce(t *testing.T) {
	relay, pusher := newRelay(t)
	response := register(t, relay, goodRegistration)
	registration, err := relay.Store.Get(response.Token)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"historyId":"9912"}`)
	relay.deliver(context.Background(), registration, body)

	sent := pusher.all()
	if len(sent) != 1 {
		t.Fatalf("expected one push, got %d", len(sent))
	}
	var envelope struct {
		P string `json:"p"`
	}
	if err := json.Unmarshal(sent[0].Payload, &envelope); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(envelope.P)
	if err != nil {
		t.Fatalf("p is not base64url: %v", err)
	}
	// One decode must yield exactly what the provider sent. A second encoding
	// anywhere would leave more base64 here.
	if string(raw) != string(body) {
		t.Fatalf("p decoded to %q, want %q", raw, body)
	}
}

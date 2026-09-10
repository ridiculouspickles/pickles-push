package relay

import (
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

// Package apns talks to Apple's push service.
//
// No dependencies. The JWT is forty lines of ECDSA and base64, and Go's net/http speaks
// HTTP/2 to Apple over ALPN without being asked. A relay whose entire job is to forward
// an opaque blob should not need a supply chain.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	ProductionHost = "https://api.push.apple.com"
	SandboxHost    = "https://api.sandbox.push.apple.com"

	// Apple rejects a token older than an hour and also rejects one refreshed more than
	// every twenty minutes. Between those, and not near either edge.
	tokenLifetime = 40 * time.Minute
)

// ErrUnregistered means Apple says the device token is dead: the app was deleted, or the
// token belongs to the other environment. The caller should drop the registration.
var ErrUnregistered = errors.New("apns: device token is no longer valid")

// Key is the signing half of an APNs auth key: the .p8 Apple issues, plus its two ids.
type Key struct {
	PrivateKey *ecdsa.PrivateKey
	KeyID      string
	TeamID     string
}

// ParseKey reads a PKCS#8 .p8 as downloaded from the developer portal.
func ParseKey(pemBytes []byte, keyID, teamID string) (*Key, error) {
	if keyID == "" || teamID == "" {
		return nil, errors.New("apns: key id and team id are required")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("apns: not PEM — expected the .p8 from the developer portal")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns: parse key: %w", err)
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("apns: expected an ECDSA key, got %T", parsed)
	}
	// ES256 means P-256 and nothing else. Accepting another curve here did not fail
	// here: a P-384 signature has 48-byte components, and writing one into the 32-byte
	// half of a JWS signature panicked *at push time*, on every push, in a goroutine
	// far from the configuration that caused it (pickles-email#476).
	if private.Curve != elliptic.P256() {
		return nil, fmt.Errorf("apns: the key must be on P-256, this one is on %s — "+
			"Apple issues P-256 .p8 keys, so this is probably not an APNs key",
			private.Curve.Params().Name)
	}
	return &Key{PrivateKey: private, KeyID: keyID, TeamID: teamID}, nil
}

// Client sends notifications. Safe for concurrent use; one is enough for a process.
type Client struct {
	HTTP *http.Client
	Key  *Key
	// Now is swappable so the token cache can be tested without sleeping.
	Now func() time.Time

	mu       sync.Mutex
	token    string
	tokenAge time.Time
}

func NewClient(key *Key) *Client {
	return &Client{
		Key: key,
		Now: time.Now,
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

// bearer returns a cached JWT, minting a new one when it is old enough.
//
// Cached because Apple rate-limits token *creation* separately from pushes, and a relay
// that minted one per notification would be throttled by its own diligence.
func (c *Client) bearer() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	if c.token != "" && now.Sub(c.tokenAge) < tokenLifetime {
		return c.token, nil
	}
	token, err := sign(c.Key, now)
	if err != nil {
		return "", err
	}
	c.token, c.tokenAge = token, now
	return token, nil
}

func sign(key *Key, now time.Time) (string, error) {
	header := map[string]string{"alg": "ES256", "kid": key.KeyID}
	claims := map[string]any{"iss": key.TeamID, "iat": now.Unix()}
	encode := func(v any) (string, error) {
		data, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(data), nil
	}
	headerPart, err := encode(header)
	if err != nil {
		return "", err
	}
	claimsPart, err := encode(claims)
	if err != nil {
		return "", err
	}
	signingInput := headerPart + "." + claimsPart
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key.PrivateKey, digest[:])
	if err != nil {
		return "", err
	}
	// JWS wants fixed-width r and s, not the ASN.1 sequence ecdsa.Sign would give from
	// SignASN1. A short r must be left-padded or Apple rejects the token as malformed.
	// FillBytes does the left-padding JWS wants, and on a value too big for the
	// destination it panics saying so rather than with a slice-bounds error from an
	// index calculation. ParseKey now refuses anything but P-256, so neither can
	// happen; this is the belt to that pair of braces.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// withoutTheURL returns a transport failure with the request URL removed.
//
// net/http wraps everything a RoundTripper returns in a *url.Error, which stringifies as
//
//	Post "https://api.push.apple.com/3/device/<DEVICE TOKEN>": dial tcp: …
//
// and the relay logs that string. So every DNS blip and every dropped connection wrote a
// device token into relay.log — the one thing registrations.json is 0600 to keep off the
// rest of the box (pickles-email#475). The wrapped error underneath says everything
// operationally useful ("dial tcp: i/o timeout") and names nothing.
func withoutTheURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// Notification is one push, already addressed.
type Notification struct {
	DeviceToken string
	Topic       string
	Sandbox     bool
	// Background sends a silent, content-available push instead of an alert.
	Background bool
	// CollapseID, when set, tells Apple to replace any undelivered notification with the
	// same id. Optional, and the relay never invents one: see the README on why two
	// independently encrypted payloads cannot produce a matching id.
	CollapseID string
	// Payload is the whole APNs JSON body.
	Payload []byte
}

// Push sends one notification and reports what Apple said.
func (c *Client) Push(ctx context.Context, n Notification) error {
	bearer, err := c.bearer()
	if err != nil {
		return err
	}
	host := ProductionHost
	if n.Sandbox {
		host = SandboxHost
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, host+"/3/device/"+n.DeviceToken, bytes.NewReader(n.Payload))
	if err != nil {
		return err
	}
	request.Header.Set("authorization", "bearer "+bearer)
	request.Header.Set("apns-topic", n.Topic)
	request.Header.Set("content-type", "application/json")
	if n.Background {
		// Apple requires priority 5 with a background push and drops it otherwise.
		request.Header.Set("apns-push-type", "background")
		request.Header.Set("apns-priority", "5")
	} else {
		request.Header.Set("apns-push-type", "alert")
		request.Header.Set("apns-priority", "10")
	}
	if n.CollapseID != "" {
		request.Header.Set("apns-collapse-id", n.CollapseID)
	}
	// A code is worthless in an hour and mail keeps. Expiring the push means a phone
	// that has been off all day is not greeted with yesterday's banners.
	request.Header.Set("apns-expiration", strconv.FormatInt(c.Now().Add(time.Hour).Unix(), 10))

	response, err := c.HTTP.Do(request)
	if err != nil {
		return fmt.Errorf("apns: %w", withoutTheURL(err))
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	switch {
	case response.StatusCode == http.StatusOK:
		return nil
	case response.StatusCode == http.StatusGone:
		return ErrUnregistered
	}
	var reason struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &reason)
	if reason.Reason == "BadDeviceToken" || reason.Reason == "Unregistered" {
		return ErrUnregistered
	}
	// The reason is Apple's own vocabulary and describes our configuration, never the
	// mail: "TopicDisallowed", "ExpiredProviderToken". Safe to log, and necessary to.
	return fmt.Errorf("apns: %d %s", response.StatusCode, reason.Reason)
}

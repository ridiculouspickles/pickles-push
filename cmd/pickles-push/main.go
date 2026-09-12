// Command pickles-push forwards provider push notifications to Apple.
//
// It is one static binary with no dependencies, meant to be run at two or more sites that
// never talk to each other. See ADR-0017 in the pickles-email repository for why that is
// possible: the device is the source of truth for its own registration, and the only
// thing this program stores is a routing table it can rebuild by waiting.
//
// Configuration is environment variables, because there are seven of them and a config
// file format would be the largest thing in the repository.
//
//	PICKLES_PUSH_LISTEN         address to listen on            (default :8080)
//	PICKLES_PUSH_PUBLIC_URL     this site's base URL, e.g. https://push-a.example.com
//	PICKLES_PUSH_STORE          path to the registrations file  (default ./registrations.json)
//	PICKLES_PUSH_APNS_KEY       path to the .p8 from the developer portal
//	PICKLES_PUSH_APNS_KEY_ID    the key's ten-character id
//	PICKLES_PUSH_APNS_TEAM_ID   the team id
//	PICKLES_PUSH_GMAIL_AUDIENCE expected `aud` of the Cloud Pub/Sub OIDC token;
//	                            unset disables the Gmail endpoint entirely
//	PICKLES_PUSH_GMAIL_SERVICE_ACCOUNT
//	                            the service account the push subscription mints its
//	                            tokens for; without it the Gmail endpoint stays closed
//
// Who may register (ADR-0018), one or both, or neither for an open relay:
//
//	PICKLES_PUSH_REGISTRATION_SECRET   a secret the operator types into the app beside
//	                                   this relay's URL; the self-hoster's way in
//	PICKLES_PUSH_SUBSCRIPTION_PRODUCTS comma-separated StoreKit product ids whose signed
//	                                   transaction proves a subscription; the hosted way in
//	PICKLES_PUSH_SUBSCRIPTION_GRACE    how long past expiry a subscription still counts
//	                                   (default 72h)
//	PICKLES_PUSH_SUBSCRIPTION_MAX_SIGNED_AGE
//	                                   how old Apple's signature on the transaction may
//	                                   be; unset does not check it. A refunded
//	                                   subscriber can present the pre-refund JWS until
//	                                   it expires, and this is what bounds that
//	PICKLES_PUSH_ALLOW_SANDBOX         "1" admits Sandbox StoreKit transactions from
//	                                   production registrations. TestFlight needs this;
//	                                   a shipped relay should not have it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ridiculouspickles/pickles-push/internal/apns"
	"github.com/ridiculouspickles/pickles-push/internal/entitlement"
	"github.com/ridiculouspickles/pickles-push/internal/relay"
	"github.com/ridiculouspickles/pickles-push/internal/store"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

// How long a registration outlives the last time its device said hello.
//
// Seven daily renewals. Long enough for a phone in a drawer over a holiday, short enough
// that the address in a Gmail registration does not outlive the device by a month
// (pickles-email#520).
const registrationLifetime = 7 * 24 * time.Hour

func run(log *slog.Logger) error {
	listen := envOr("PICKLES_PUSH_LISTEN", ":8080")
	publicURL := os.Getenv("PICKLES_PUSH_PUBLIC_URL")
	if publicURL == "" {
		return errors.New("PICKLES_PUSH_PUBLIC_URL is required: a device has to be told " +
			"where to point its subscription, and each site's URL is its own")
	}
	if !strings.HasPrefix(publicURL, "https://") {
		// A push URL is a bearer capability in a query-free path. Over http it is a
		// capability anyone on the path can copy.
		return errors.New("PICKLES_PUSH_PUBLIC_URL must be https")
	}

	keyPath := os.Getenv("PICKLES_PUSH_APNS_KEY")
	if keyPath == "" {
		return errors.New("PICKLES_PUSH_APNS_KEY is required")
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	key, err := apns.ParseKey(keyBytes,
		os.Getenv("PICKLES_PUSH_APNS_KEY_ID"), os.Getenv("PICKLES_PUSH_APNS_TEAM_ID"))
	if err != nil {
		return err
	}

	registrations, err := store.Open(envOr("PICKLES_PUSH_STORE", "registrations.json"))
	if err != nil {
		return err
	}

	gmailAudience := os.Getenv("PICKLES_PUSH_GMAIL_AUDIENCE")
	gmailServiceAccount := os.Getenv("PICKLES_PUSH_GMAIL_SERVICE_ACCOUNT")
	switch {
	case gmailAudience == "":
		log.Info("gmail endpoint disabled: PICKLES_PUSH_GMAIL_AUDIENCE is unset")
	case gmailServiceAccount == "":
		// Closed rather than half-open. Signature, audience and expiry are all a token
		// from anybody's Google Cloud project needs to pass.
		log.Error("gmail endpoint disabled: PICKLES_PUSH_GMAIL_SERVICE_ACCOUNT is unset, " +
			"and without it a token minted for any Google account would be believed")
	}

	policy := entitlement.Policy{Secret: os.Getenv("PICKLES_PUSH_REGISTRATION_SECRET")}
	if products := os.Getenv("PICKLES_PUSH_SUBSCRIPTION_PRODUCTS"); products != "" {
		// Trimmed, because a list written with spaces after the commas matched no
		// product at all and said so as "transaction is for another product" — which
		// reads like the device's fault rather than the unit file's.
		ids := productIDs(products)
		if len(ids) == 0 {
			return errors.New("PICKLES_PUSH_SUBSCRIPTION_PRODUCTS is set but names no product")
		}
		grace := 72 * time.Hour
		if text := os.Getenv("PICKLES_PUSH_SUBSCRIPTION_GRACE"); text != "" {
			if grace, err = time.ParseDuration(text); err != nil {
				return errors.New("PICKLES_PUSH_SUBSCRIPTION_GRACE is not a duration")
			}
			if grace < 0 {
				// It parses, and it means every live subscription is already expired.
				return errors.New("PICKLES_PUSH_SUBSCRIPTION_GRACE cannot be negative")
			}
		}
		var maxSignedAge time.Duration
		if text := os.Getenv("PICKLES_PUSH_SUBSCRIPTION_MAX_SIGNED_AGE"); text != "" {
			if maxSignedAge, err = time.ParseDuration(text); err != nil {
				return errors.New("PICKLES_PUSH_SUBSCRIPTION_MAX_SIGNED_AGE is not a duration")
			}
			if maxSignedAge <= 0 {
				return errors.New("PICKLES_PUSH_SUBSCRIPTION_MAX_SIGNED_AGE must be positive; " +
					"unset it to not check the signature's age")
			}
		}
		allowSandbox := os.Getenv("PICKLES_PUSH_ALLOW_SANDBOX") == "1"
		if allowSandbox {
			log.Warn("sandbox subscriptions are admitted: every TestFlight purchase is one, " +
				"and so is every free one anybody can mint. Unset PICKLES_PUSH_ALLOW_SANDBOX " +
				"when the beta ends")
		}
		if maxSignedAge == 0 {
			// Said once at start rather than left to be discovered: this is the
			// difference between "the subscription is live" and "the subscription was
			// live when Apple last signed for it".
			log.Info("the age of a transaction's signature is not checked: a refunded " +
				"subscriber can present the pre-refund transaction until it expires. " +
				"Every admission logs signedDaysAgo; set " +
				"PICKLES_PUSH_SUBSCRIPTION_MAX_SIGNED_AGE once that number is known")
		}
		policy.Apple = &entitlement.AppleVerifier{
			ProductIDs:   ids,
			Grace:        grace,
			AllowSandbox: allowSandbox,
			MaxSignedAge: maxSignedAge,
		}
	}
	switch {
	case policy.Open():
		log.Warn("registration is open: set PICKLES_PUSH_REGISTRATION_SECRET (yours) or " +
			"PICKLES_PUSH_SUBSCRIPTION_PRODUCTS (ours) so that not everyone may register")
	case policy.Apple != nil && policy.Secret != "":
		log.Info("registration takes a subscription or the secret")
	case policy.Apple != nil:
		log.Info("registration takes a subscription")
	default:
		log.Info("registration takes the secret")
	}

	service := &relay.Relay{
		Store:               registrations,
		Pusher:              apns.NewClient(key),
		Log:                 log,
		PublicURL:           publicURL,
		GmailAudience:       gmailAudience,
		GmailServiceAccount: gmailServiceAccount,
		Policy:              policy,
	}

	server := &http.Server{
		Addr:              listen,
		Handler:           service.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Devices re-register daily and on every foreground, so a row unseen for a week has
	// missed seven of those: a device that was wiped, reinstalled, or had push turned
	// off, none of which Apple reports reliably. A phone that is merely offline costs
	// nothing here — its push expires at Apple within the hour and its row is refreshed
	// the moment it comes back.
	//
	// It was a month, which is a long time to keep a device token and — on the Gmail
	// path — an email address, for a device that is not there (pickles-email#520).
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				removed, err := registrations.Prune(now.Add(-registrationLifetime), now)
				if err != nil {
					log.Error("prune failed", "error", err.Error())
				} else if removed > 0 {
					log.Info("pruned stale registrations", "count", removed)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	// The toolchain goes in the line, because "what was this built with" is otherwise
	// answerable only by having the binary in front of you (pickles-email#526, and #465
	// makes the same point about the source).
	log.Info("listening", "addr", listen, "registrations", registrations.Count(),
		"go", runtime.Version())
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// A push is queued off the request goroutine now, so the listener stopping is not
	// the end of the work: the provider has already been told 200 for whatever is in
	// the queue. Refuse new work, then finish what was accepted.
	service.Close()
	service.WaitForDeliveries()
	log.Info("stopped")
	return nil
}

// productIDs splits a comma-separated list and drops the whitespace and the blanks.
func productIDs(list string) []string {
	var ids []string
	for _, id := range strings.Split(list, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

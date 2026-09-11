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
//	PICKLES_PUSH_ALLOW_SANDBOX         "1" admits Sandbox StoreKit transactions from
//	                                   production registrations. TestFlight needs this;
//	                                   a shipped relay should not have it.
//	                                   (default 72h)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
		grace := 72 * time.Hour
		if text := os.Getenv("PICKLES_PUSH_SUBSCRIPTION_GRACE"); text != "" {
			if grace, err = time.ParseDuration(text); err != nil {
				return errors.New("PICKLES_PUSH_SUBSCRIPTION_GRACE is not a duration")
			}
		}
		allowSandbox := os.Getenv("PICKLES_PUSH_ALLOW_SANDBOX") == "1"
		if allowSandbox {
			log.Warn("sandbox subscriptions are admitted: every TestFlight purchase is one, " +
				"and so is every free one anybody can mint. Unset PICKLES_PUSH_ALLOW_SANDBOX " +
				"when the beta ends")
		}
		policy.Apple = &entitlement.AppleVerifier{
			ProductIDs:   strings.Split(products, ","),
			Grace:        grace,
			AllowSandbox: allowSandbox,
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

	// Devices re-register daily, so anything unseen for a month is a device that was
	// wiped, reinstalled, or had push turned off — none of which Apple tells us about
	// reliably.
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				removed, err := registrations.Prune(time.Now().Add(-30 * 24 * time.Hour))
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

	log.Info("listening", "addr", listen, "registrations", registrations.Count())
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

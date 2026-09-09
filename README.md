# pickles-push

A push relay for [Pickles](https://github.com/yeled/pickles-email). It receives a
notification from a mail provider and hands it to Apple. That is the whole program.

It exists because iOS suspends apps, so an iPhone cannot hold a JMAP `EventSource` open
the way the Mac app does. Everything else about Pickles is local-first and stays that way:
this is opt-in, off by default, and the app works fully without it. See
[ADR-0017](https://github.com/yeled/pickles-email/blob/main/docs/adr/0017-push-relay.md)
for the reasoning and [ADR-0001](https://github.com/yeled/pickles-email/blob/main/docs/adr/0001-no-backend-in-v1.md)
for the position it revises.

## What it can and cannot see

**On JMAP: nothing.** The device creates its own `PushSubscription` and supplies its own
RFC 8291 keys, so what arrives here is ciphertext addressed to a key the relay has never
held. It cannot read the sender, the subject, the body, the mailbox, or which account
changed. It forwards bytes it cannot interpret to a device token, and that is all it is
able to do. Grep the source: nothing in `internal/relay` parses a JMAP body.

**On Gmail: your address, and nothing else.** Cloud Pub/Sub names the mailbox in the
clear and there is no equivalent of RFC 8291 on that path. The relay reads the address
because it is the only routing key available, and the `historyId`, which is a cursor. It
never holds a Google credential: the device calls `users.watch()` with its own token and
renews it.

**It never holds a credential of yours, on any path.** There is no vault here to breach.
The worst an attacker who owns this box can do is learn *when* mail arrives, and wake your
phone with a notification whose content your device will decline to decrypt.

**It logs no payloads.** It counts them.

## The duplicate problem, honestly

Pickles points each device at two sites, each with its own subscription, so **every
notification arrives twice**. That is deliberate: it buys two sites that share no address,
no database and no failure mode. The duplicate is suppressed on the device, by message id,
in code that had to exist anyway because a background refresh can already race a push.

What does **not** work, and was assumed to in the first draft of ADR-0017: using
`apns-collapse-id` to make Apple merge the two banners. A collapse id would have to be
derived from the event, the two sites receive independently encrypted payloads for the
same event, and the relay cannot read either — so there is nothing common to derive it
from. The design that made the relay blind is the same design that stops it from
deduplicating. That is the correct trade, but it should be stated rather than assumed:
**suppression is entirely the client's job, and the client must be right.**

This is why registrations carry a `mode`. A device can register `alert` with one site and
`background` with the other, so only one site raises a banner and the second still
delivers the wake-up. That makes the relay policy-free: the topology is a client decision
and does not need this binary redeployed to change.

## Running it

One static binary, no dependencies, no database.

```sh
go build ./cmd/pickles-push
```

Configuration is environment variables:

| Variable | Meaning |
| --- | --- |
| `PICKLES_PUSH_LISTEN` | listen address, default `:8080` |
| `PICKLES_PUSH_PUBLIC_URL` | **this site's** base URL, e.g. `https://push-a.example.com`; must be https |
| `PICKLES_PUSH_STORE` | registrations file, default `./registrations.json` |
| `PICKLES_PUSH_APNS_KEY` | path to the `.p8` from the developer portal |
| `PICKLES_PUSH_APNS_KEY_ID` | the key's ten-character id |
| `PICKLES_PUSH_APNS_TEAM_ID` | the team id |
| `PICKLES_PUSH_GMAIL_AUDIENCE` | expected `aud` of the Pub/Sub OIDC token; unset disables Gmail |
| `PICKLES_PUSH_REGISTRATION_SECRET` | a secret you choose and type into Pickles beside this relay's URL; **set this if you run your own** |
| `PICKLES_PUSH_SUBSCRIPTION_PRODUCTS` | StoreKit product ids whose signed transaction admits a device; what *our* sites set |
| `PICKLES_PUSH_SUBSCRIPTION_GRACE` | how long past its expiry a subscription still counts, default `72h` |

Put a TLS terminator in front of it. The push URL is a bearer capability in a path, and
over plain http it is a capability anyone on the wire can copy.

Each site gets its own hostname and its own `PICKLES_PUSH_PUBLIC_URL`. **They must not
share an address.** The sites never talk to each other and have nothing to synchronise.

### Who may register

Three ways to run it, and the difference is one environment variable:

- **Yours.** Set `PICKLES_PUSH_REGISTRATION_SECRET` to anything long and random, and
  enter the same secret in Pickles beside the relay's URL. The device sends it as a
  bearer token; the relay compares it in constant time and stores nothing.
- **Ours.** The sites we run set `PICKLES_PUSH_SUBSCRIPTION_PRODUCTS` instead. A device
  presents StoreKit's signed transaction for the Pickles Push subscription; the relay
  checks the certificate chain to Apple Root CA G3 (embedded), the signature, the
  bundle, the product and the expiry — offline, with no call to Apple, no account and
  nothing kept but the expiry. A capability, not an identity. The subscription is the
  hosting, not the software: the app is free and this program is AGPL.
- **Open.** Neither set. Anyone may register; the log says so at start. Fine on a
  laptop, not on the internet.

Both set means either proof admits a device. A lapsed subscription is not deleted;
its pushes are skipped until the device re-registers with a renewed transaction, so a
renewal picks up the same token and the provider-side subscription with it.

### The store

A JSON file, rewritten whole under one mutex and renamed into place. This is not a
placeholder. The rows are tiny, they are written only by the devices that own them, and
the device is their source of truth — it re-registers on every foreground and at least
daily. Losing the file costs at most a day of push on the affected site and repairs
itself with no operator action. A database here would be machinery guarding a cache.

A *corrupt* file, on the other hand, refuses to start. Starting empty would look identical
to a healthy start while silently dropping every device.

## API

Four endpoints, all JSON.

```
POST   /v1/register          {deviceToken, topic, sandbox, mode, gmailAddress?, token?, transaction?}
                             Authorization: Bearer <secret>   (a self-hosted relay)
                             → {token, pushUrl}; 403 with a reason when refused
DELETE /v1/register/{token}  → 204, whether or not it existed
POST   /v1/push/{token}      the JMAP PushSubscription URL; body forwarded unread
POST   /v1/gmail             Cloud Pub/Sub push, OIDC-verified
GET    /healthz              → {ok, registrations}
```

`POST /v1/register` has no account behind it: what it checks is a proof — the secret or
a signed subscription, see above — and the only thing registering buys an attacker is
the ability to have their own device woken. Rate-limit it at the edge anyway.

Sending `token` back on re-registration keeps the same delivery token, which is what lets
a device keep one provider-side subscription for its lifetime instead of recreating it
every time the app comes to the foreground.

## Tests

```sh
go test ./...
```

The entitlement tests build a certificate chain shaped like Apple's — root, WWDR-marked
intermediate, App Store-marked leaf — sign transactions with it, and check that every
claim is enforced and that a home-made chain is nothing against Apple's real root. The
APNs tests generate a key and verify the JWT against it, including the fixed-width
`r||s` encoding Apple is strict about and no error message ever explains. The store tests
cover concurrent writers, because a JSON file as a datastore is only defensible if the
locking is right. The relay tests assert that a payload reaches Apple byte-identical and
that health leaks no device token.

## Licence

AGPL-3.0-or-later. Copyright 2026 Charlie Allom.

Chosen so that anyone may run this — for themselves, their family, their company — and
nobody may sell it as a hosted service without publishing their changes. The reasoning
is docs/12 in the pickles-email repository.

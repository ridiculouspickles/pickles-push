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
| `PICKLES_PUSH_GMAIL_AUDIENCE` | expected `aud` of the Pub/Sub OIDC token; unset disables Gmail. A long random string rather than the endpoint URL, set as the push subscription's audience |
| `PICKLES_PUSH_GMAIL_SERVICE_ACCOUNT` | the service account the push subscription mints its tokens for; **unset also disables Gmail**, because any Google Cloud project can mint a token for any audience |
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
POST   /v1/register          {deviceToken, topic, sandbox, mode, gmailAddress?, token?,
                              transaction?, secret?}
                             Authorization: Bearer <secret>   (a self-hosted relay)
                             → {token, pushUrl}; 403 with a reason when refused
                               503 when the site holds as many as it will
                               409 when one Gmail address has as many devices as it will
DELETE /v1/register/{token}  X-Pickles-Registration-Secret: <secret>
                             → 204, whether or not it existed — and whether or not it
                               was yours to delete
POST   /v1/push/{token}      the JMAP PushSubscription URL; body forwarded unread
POST   /v1/gmail             Cloud Pub/Sub push, OIDC-verified
GET    /healthz              → {ok}
```

`POST /v1/register` has no account behind it: what it checks is a proof — the secret or
a signed subscription, see above — and the only thing registering buys an attacker is
the ability to have their own device woken.

### What is bounded, and where

The edge cannot do this, which is why the binary does. Apache sees a path whose only
meaningful part is a delivery token it must not log, and one Gmail endpoint shared by
every subscriber, so *per token* and *per address* are limits only this program can
express.

| | limit | why |
|---|---|---|
| registrations on a site | 5,000 | the file is rewritten whole, fsynced and renamed on every write, so its size is the cost of every write — and a registration with no `token` mints one, from a JWS that can be replayed |
| devices per Gmail address | 16 | the address is accepted on trust, and this bounds both what one unverified claim costs and how far one published message fans out |
| registrations per device | 1 per bundle id | not a cap so much as a rule: registering again *replaces*, so a device cannot accumulate rows and be woken twice for one message |
| pushes to one registration | a burst of 20, then 10 a minute | holding a delivery token means being able to wake a device; it must not mean being able to wake it all night |
| pushes in flight to Apple | 8, with 1,024 waiting | a flood of pushes is a flood of connections carrying our team's key, and the throttling that follows would not be confined to whoever caused it |

A rate-limited push is **dropped, and the provider is still answered 200**. A 4xx to a
JMAP server is a retry, and a retry is a second notification to suppress on a device
that has probably had the first; the device syncs when it is next opened regardless.

**The Gmail address is not verified, and cannot be here.** Any device admitted by the
policy may register any address and be woken when that mailbox receives mail. There is
no proof of mailbox ownership on this path — Pub/Sub names the mailbox in the clear and
that is the only routing key there is — so the per-address cap is a bound on the damage
rather than a fix. On the JMAP path the question does not arise: the relay is told a URL
to deliver to and nothing about who is being served.

Sending `token` back on re-registration keeps the same delivery token, which is what lets
a device keep one provider-side subscription for its lifetime instead of recreating it
every time the app comes to the foreground.

### Which registration is yours

`secret` is **minted by the device**, kept beside its delivery token, and sent on every
registration. The first one seen for a delivery token takes ownership of the row; after
that only the same secret may rewrite it, and `DELETE` needs it in the
`X-Pickles-Registration-Secret` header.

It is not the relay's own secret, which travels in `Authorization` and answers a
different question: that one is *may you register here*, this one is *is this
registration yours*.

Without it, the delivery token alone was enough to take a registration over — point it
at another device token and the original stops being woken while the new one starts —
and `DELETE` needed no proof at all. A token reaches the provider and nobody else, so
that took a leak first; but a token is documented as a capability to wake *one* device,
and the code granted more than that.

Three things worth knowing about it:

- **The device mints it, not the relay.** A relay that issued one would have to be
  trusted to keep it, and the rollout would need a flag day: every device already
  registered would be handed a secret it did not know to send back, and its next
  re-registration would be refused — silently, since the symptom is no notifications.
  Minted at the far end, a build that does not know about this stays exactly as it is.
- **A row with no secret is still rewritten and deleted without one**, because that is
  what every build shipped so far expects. The window closes by itself: a row is pruned
  a week after its device last said hello, so once the only build in use mints secrets
  there are no unowned rows left.
- **Refusals are indistinguishable from a token nobody holds** — `400 malformed token`
  on registration, `204` on delete, in both cases what an unknown token gets. An
  endpoint that answers "that exists, but it is not yours" is an endpoint that confirms
  tokens for you.

Only the SHA-256 is stored. There is no operation here that needs the secret back, and a
file of them would be a file of credentials rather than a routing table.

### What a registration keeps, and for how long

A row holds the APNs device token, the delivery token, the bundle id, the mode, and — on
the Gmail path only — **the mailbox address**, because Pub/Sub identifies a mailbox by
address and there is no other way to route it. That address is the one personal thing
this relay stores.

A row goes when either is true:

- **Not seen for seven days.** Devices re-register daily and on every foreground, so
  seven days is seven missed hellos: a device wiped, reinstalled, or with push turned
  off, none of which Apple reports reliably. A phone that is merely *offline* costs
  nothing — its push expires at Apple within the hour, and its row is refreshed the
  moment it comes back.
- **Its proof has expired.** Nothing is delivered to a row past `ExpiresAt` anyway, so
  keeping it is storage with no purpose. A registration whose proof does not expire — a
  self-hoster's secret, or an open relay — is never dropped by this rule.

The store is a cache the device rebuilds by re-registering, so pruning early costs a
returning device one round trip and nothing else.

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

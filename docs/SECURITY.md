# Security model

Status: EXPERIMENTAL design sketch. Nothing here has been implemented or reviewed by anyone but its
authors. This document states what the design intends to be true; none of it is true yet.

**Two processes.** A *frontend* establishes who is calling and applies policy; a *backend* draws the
windows and holds the token. Every rule below says which one it binds, because after
[0008](decisions/0008-build-to-the-upstream-shape.md) "the service" is not one thing. The division
is [ARCHITECTURE.md](ARCHITECTURE.md#who-does-what); the private interface between them, and how it
is kept private, is [IMPL-INTERFACE.md](IMPL-INTERFACE.md).

## What this is a boundary against, and what it is not

Stated plainly, because the temptation to overclaim here is enormous:

- **For sandboxed applications this can be a strong boundary.** A Flatpak or Snap has an identity a
  containment framework can vouch for, cannot reach `pcscd` without a permission it need no longer
  hold, cannot read the service's memory, and cannot see the PIN. Replacing `--socket=pcsc` with a
  consented, scoped, revocable grant is a real improvement in a real threat model.
- **For ordinary host applications this is an identity-and-consent boundary, not an isolation
  boundary.** It makes the user's decision explicit, attributable and revocable. It does not stop a
  determined hostile process.
- **It is NOT absolute same-UID isolation, and this project must never claim it is.** A hostile
  unsandboxed process running as the user may, depending on how the system is hardened, be able to
  inspect other processes, read or manipulate their environment, reach runtime files, inject input
  into windows, or impersonate desktop context. `ptrace` restrictions, a locked-down Wayland
  compositor and a hardened `/proc` all change this answer, and none of them is guaranteed.

The consent dialog is worth having even in the weak case: it turns silent use into a decision, and
a decision into an audit trail. It is not a sandbox.

## Threat model

**Assume the caller is adversarial.** Every request arrives from a process that may be trying to
misuse the card, mislead the user, or impersonate another application. Design as though this is
normal, because it is the only assumption that produces a defensible UI.

**The card can be induced to sign.** This is the central asset and the reason the design is shaped
the way it is. Possession of a signing capability against a PIV authentication key is, for practical
purposes, possession of the user's identity for as long as it lasts. A PKCS#11 session that can sign
is a standing capability; a brokered `Sign` call is a countable, revocable, expiring event. That
difference is the entire argument for
[0007](decisions/0007-brokered-operations-are-the-core.md).

**A PIN prompt is not consent.** It proves the user was present and knew the PIN. It does not tell
them which application asked, for what, or how long the answer lasts. Consent is the chooser, and
the per-purpose policy that decides how many operations one consent covers. A design where the PIN
prompt is the only user-visible moment has trained the user to type their PIN whenever asked, which
is exactly the behaviour an attacker needs.

**A signature does not attest its purpose.** The service cannot show that a `Sign` input came from a
TLS handshake rather than from a PDF, a challenge string, or nothing at all. `purpose` constrains
which certificates are offered and what the dialog says. Anyone reading it as a guarantee about
later use has misread it, and the interface documentation says so in those words.

**Assets protected**

| Asset | Exposure if this fails |
|---|---|
| The private key on the card | Cannot be extracted, but can be *used*: signatures as the user, for as long as a grant lasts |
| The PIN | Full offline use of the card by anyone who also has it physically |
| The card's remaining retry counter | A blocked card is a locked-out user, and an easy denial of service |
| The user's trust in a service-owned window | If the window can be imitated or is inconsistent, every other protection here is decorative |
| Which certificates and tokens the user has | Discloses employer, issuance, sometimes clearance |
| Attribution — which application did what | Without it there is no audit trail and no revocation story |

## Caller identity

**The frontend establishes it. The backend is told.** This is the single security property the
frontend/backend split buys, and it is worth stating before the mechanics: the process that draws
the window asserting "this application is asking" is not the process that had to work out which
application it was. `app_id`, the display name, and the honesty level all arrive at the backend as
arguments to `AcquireCredential`. A backend cannot derive an app id even by accident, because it is
not talking to the application.

Executable paths are not application identities. A same-UID process can execute another path,
manipulate launch context, or connect directly to the bus. `/proc/$pid/exe` is a hint.

xdg-desktop-portal's actual approach is the model to follow: sandboxed callers have identities
supplied by their containment framework; host applications are normally inferred through
standardised cgroups; and a host registry lets an unsandboxed peer associate itself with a
desktop-file app ID while the
[documentation warns that mechanism is expected to change](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.host.portal.Registry.html).

This service resolves identity into three honesty levels, and **displays which one it got**:

1. **Verified sandboxed** — Flatpak or Snap identity obtained through the containment framework's
   mediation. Treated as authenticated metadata. Displayed as the application, with its sandbox
   status.
2. **Derived host label** — a cgroup-derived desktop identity. A useful label, **not** a security
   principal. Displayed as the application, with an explicit warning that it is unverified.
3. **Unidentified** — nothing trustworthy. Displayed as "an unidentified application", with the
   strongest warning the design has.

Rules that follow:

- **Identity is derived once, in the frontend, at the start of the transaction**, and travels as an
  argument from there. There is no second derivation anywhere, and no option, key or header by
  which a caller can supply one.
- **The backend must never trust a caller directly.** Its only legitimate caller is the frontend; it
  checks that the sender owns the frontend's well-known name and refuses everything else. See
  [IMPL-INTERFACE.md](IMPL-INTERFACE.md), "Why an application cannot call this" — including the part
  about what that check does *not* protect against.
- **Bind every grant to the initiating unique D-Bus connection** (plus its delegated endpoint
  holders — see lifetime).
- **Never use an unverified app ID as the sole key** for selection memory, policy, or anything else
  that persists.
- **Selection memory is unavailable to level 3**, and to level 2 unless the user opts in explicitly
  each time it is offered.
- **First use by an unidentified caller requires explicit confirmation**, and the dialog says the
  application could not be identified rather than inventing a name for it.
- **Rate-limit** background requests, repeated requests, and repeated failures, per caller and
  globally.
- **The trusted identity position in the window is never occupied by caller-supplied text** — not
  `reason`, not `context`, not a title, not the token label, not the certificate subject.

This is now the shape the project is *built* in rather than a thing to hope for later: a frontend
establishes `app_id` and passes it to a backend applications cannot reach. What acceptance upstream
would add is not the shape but the **reach** of level 1 — xdg-desktop-portal's own app-info code has
containment-framework integrations, a maintained host-identity story and a documented Registry
mechanism, and inheriting those is worth more than reimplementing them.
[UPSTREAMING.md](UPSTREAMING.md) lists our `app-info.h` among the files that are *deleted* at
acceptance, for exactly that reason. Levels 2 and 3 do not disappear upstream; they are honestly
labelled there too.

## The trusted dialog

Drawn by the **backend**, from facts the **frontend** established. The first two items in this list
arrive as arguments; the backend renders them and may not substitute anything for them. The chooser
must show all of the following, in backend-owned text:

- verified application **name** and **id**, as the frontend established them;
- **which honesty level that was** — sandboxed and verified, a derived host label, or unidentified —
  with an explicit warning for the second and the strongest warning the design has for the third. A
  backend that displayed an app id without saying how it was established would be lying by
  omission, and the level is an argument on the wire so that it cannot be forgotten;
- the **purpose in the service's own words**, not the caller's;
- the **operation class**: authenticate, sign, or decrypt;
- the certificate's **subject identity** and **issuer**, and a **fingerprint or short stable
  identifier** behind a details view;
- the **token and reader** name;
- the **grant duration**, or "this operation only";
- **whether further operations may occur without another prompt**;
- the caller's `reason` and `context`, visibly separated and **labelled as application-provided
  text**.

For client authentication the destination host matters and this service cannot verify it: it sees a
D-Bus peer, not a TLS connection. `context` carries it and is labelled as *requested* destination.
Selection memory is keyed only on trusted fields.

Accessibility is part of this, not adjacent to it: a security dialog a screen-reader user cannot
navigate is a security dialog that user cannot give informed consent through. The criteria are in
[PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md#accessibility-as-acceptance-criteria) and they are acceptance criteria.

## PIN handling

- **The PIN is collected only in a backend-owned window** and exists only inside the backend
  process. It never crosses D-Bus in either direction — not on the public interface and **not on the
  impl interface either** — never enters a `GVariant`, a `GError` message, a URI, or a log line. The
  frontend cannot see a PIN: not as a rule it obeys, but because it has no window and no token
  session.
- **No `pin-value` and no `pin-source` in any PKCS#11 URI this service emits**, ever. Any URI
  arriving from elsewhere carrying one is truncated before it can be logged.
- **The buffer is wiped on every exit path** — success, failure, cancel, timeout, window destroyed,
  crash handler — allocated in locked, non-swappable memory where the platform allows, and core
  dumps are disabled for the process where practical.
- **Nothing persists a PIN.** There is no "remember PIN", no keyring entry, no option, and no
  configuration key. A design that stores a PIN has converted a two-factor credential into a
  one-factor one.
- **Login happens lazily**, in the broker's own PKCS#11 session, at first private-key use — not at
  grant time. Pre-logging in spends the user's presence before it is needed, and across the facade
  it would buy nothing anyway, because **PKCS#11 login state is per application and does not cross
  the forwarding boundary**.
- **Protected authentication path**: when the token sets `CKF_PROTECTED_AUTHENTICATION_PATH`, the
  login is made with a null PIN and the token or reader collects the secret. The service shows an
  instructional dialog **with no editable PIN field** and never receives the PIN. Emulating a PIN
  field for such a token would be a lie about where the secret goes.
- **Retry handling.** Remaining attempts are displayed only when the token reports them reliably and
  are **never invented**; the user is warned before the final known attempt. Incorrect PIN, blocked
  PIN, cancelled prompt, device error and removal are always distinguished. Retries are
  user-initiated only; the service never retries automatically, and never after an ambiguous
  transport failure. Prompts for the same token are serialised so two grants cannot race two windows
  at the user.
- **Headless: never read a PIN from stdin.** With no display, or with `interaction_mode: forbidden`,
  the call returns `no_display` or `interaction_required`. A trusted agent protocol for headless use
  would be a separate, separately configured and separately reviewed mechanism.
- **We cannot force forgetting.** Some tokens and middleware cache authentication internally, at the
  device or driver level, for a duration this service does not control. `C_Logout` is issued when a
  grant ends, and the design must never promise that the card, the reader firmware or the middleware
  daemon has forgotten. Any documentation that implies otherwise is wrong.

## Grant scoping

A grant authorises **one certificate, one key, one operation set, one verified caller, for one
bounded time**.

Brokered operations enforce this directly: the service holds the session, checks the grant, checks
the mechanism against an allow-list, validates the parameters, applies the purpose's consent policy,
counts the operation and applies a rate limit.

Enforcement is split, and both halves are load-bearing. The **frontend** checks that the grant
exists, is live, is owned by this caller, permits this operation, permits this mechanism, and is
inside its rate limit. The **backend** checks the mechanism against the key, validates the
parameters, applies the per-purpose consent policy, and performs the operation on its own session.
Neither check is redundant: the frontend is the only side that knows which application is asking,
and the backend is the only side that knows what the card will accept.

**The PKCS#11 facade must enforce the same thing at a much harder interface**, which is why it is
experimental and why it is a separate milestone. The minimum it must do:

- one synthetic slot, one synthetic token;
- only the granted leaf certificate, its keys, and explicitly selected chain certificates — no
  unrelated public or private objects, and no enumeration of the rest of the card;
- **synthetic handles mapped to broker-owned handles**; a client-supplied handle is a lookup key,
  never an address;
- **read-only sessions only**; `CKF_RW_SESSION` refused;
- **SO login refused entirely**; user `C_Login` treated as an authorisation-state transition that
  carries no PIN;
- refuse `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_CreateObject`, `C_CopyObject`,
  `C_DestroyObject`, `C_SetAttributeValue`, all key generation, all wrap/unwrap, all derivation
  unless explicitly required, RNG seeding, and operation-state export/import;
- restrict `C_GetAttributeValue` so sensitive and unexpected attributes cannot leak;
- expose only allow-listed mechanisms, **validating their parameters** — RSA-PSS hash, MGF and salt
  length above all — rather than forwarding them;
- refuse encrypt/decrypt unless the grant permits it, and refuse signing until the grant is
  authorised;
- **never trust client-supplied handles, lengths or operation state**;
- rate-limit, and terminate on expiry, revocation or removal;
- filter the **PKCS#11 v3 interface tables** as well as the classic v2 function list — filtering
  `C_GetFunctionList` alone leaves `C_GetInterface` as an unfiltered way back in.

This is a security-sensitive PKCS#11 implementation facing a hostile peer over a wire protocol. It
runs in **its own process** — a child of the backend, since that is where the token session is —
holding no PIN and reaching the card only through the broker, and it is the first thing that should
be fuzzed. Its socket is created by the backend and **relayed** by the frontend, which checks the
grant and the caller and then passes the descriptor through without holding a copy.

**Hiding objects during enumeration is not scoping.** A caller that can use templates, cached
handles, object creation, key generation, wrapping or derivation does not need `C_FindObjects` to
reach the rest of the card. Every entry point is either refused or constrained; there is no
allow-by-default path.

## Card removal, and what happens to a grant

Removal invalidates everything: every synthetic object and session, any in-flight operation
cancelled, the appropriate PKCS#11 device or token error returned to a facade client,
`GrantInvalidated` emitted with reason `token_removed`, and the endpoint **poisoned** so it cannot
silently rebind to a card inserted later. Reinsertion requires explicit reselection **even when the
label and slot number are identical**, because a label and a slot number prove nothing about which
card is in the reader. Tokens are identified by every stable attribute available — manufacturer,
model, serial, label — never by slot number alone.

## Grant lifetime and delegation

Binding a grant to its owner's D-Bus connection alone is wrong in both directions: the process that
actually performs the cryptography may be a browser's **network subprocess** with its own connection
to the endpoint, so killing the grant when the owner's connection drops can kill a valid handshake,
while keeping it alive for the subprocess lets it be used after the request that authorised it
ended. The model:

- one **owner** connection, which acquired the grant and is the only one that may release it;
- zero or more **delegated endpoint holders**, connections the owner caused to exist;
- the grant dies when the owner releases it, **or** when all permitted holders have gone;
- a **short orphan grace period** covers acquisition-to-connection, after which an unclaimed grant is
  destroyed;
- `expires_at` always applies, and `RenewGrant` never expands what a grant permits.

The fd-lifetime rules the
[USB portal documents](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Usb.html)
— usable until released, until the connection closes, until the device is removed, or until the
portal revokes them — are the precedent and are deliberately mirrored.

## Selection memory

Three things must never be conflated:

1. **remember which certificate was selected** — the only one this design offers;
2. **token login caching** — hardware and driver behaviour this service does not control and must not
   present as a feature;
3. **remembered authorisation to use the key** — deliberately absent.

Selection memory is keyed on verified application identity, purpose and filter context; it
**preselects** and never skips the trusted consent step or a PIN prompt; it is unavailable to
unverified callers; it is session-scoped unless the user makes it durable; and it is listed and
revocable in the service's own UI. There is no "remember PIN" and there never will be.

## Logging

- **Two journals, one story.** The frontend records the decision and the caller; the backend records
  the card event. The grant id and the operation id are what join them, and neither journal alone
  answers "what used my card, and when".
- **Allowed**: counts, stable reason codes, purposes, resolved caller identity and its honesty
  level, grant and operation ids, mechanism names, token presence, timings, and — frontend only —
  which backend was selected.
- **Never**: PINs, PKCS#11 URIs, object labels, key ids, card serials, certificate subjects, signed
  data, plaintext, or the contents of `reason` and `context`.
- Error text from p11-kit, OpenSC and GnuTLS is **truncated before any embedded URI**, because those
  libraries put URIs in error strings and a URI may carry a `pin-value`.
- Redaction is **structural** — a logging helper that accepts only the fields it may emit — not a
  regex applied to strings on the way out. A filter that must recognise a secret has already been
  handed one.
- The default log level records decisions, not data: which caller, which purpose, which honesty
  level, granted or refused, and why.

## Open problems

Named because they are unsolved, not because they are minor.

- **Delegation across one hop.** `webauth-service` asks on behalf of an RDP client. This service sees
  only its immediate peer. Version 1 shows the immediate peer, honestly. An attested chain is a
  protocol neither project has.
- **Module loading for facade consumers.** If the only workable shape is one permanently registered
  broker module, then a compromised consumer process shares an already-loaded module with every other
  consumer in that process, and grant binding must be enforced inside the module by caller identity
  rather than by socket. That is a different and harder security argument. [SPIKES.md](SPIKES.md) S3.
- **`purpose` is not enforceable.** Stated everywhere it appears; there is no fix, only honesty.
- **The impl boundary is not a privilege boundary.** Both processes run as the user. The split makes
  identity derivation and window drawing structurally separate, which is worth a great deal; it does
  not make the backend safe from a hostile process that can `ptrace` it. A deployment that wants
  more can add a D-Bus policy rule or a private socket; neither is in v1.
  [IMPL-INTERFACE.md](IMPL-INTERFACE.md) says so in the same words.
- **Hardened-desktop assumptions.** How much level-2 and level-3 identity is worth depends on
  `ptrace` scope, compositor input isolation and `/proc` hardening, none of which this service
  controls or can detect reliably.

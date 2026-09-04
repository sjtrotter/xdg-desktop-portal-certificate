# Architecture

Status: EXPERIMENTAL design sketch. None of this is implemented, and
[SPIKES.md](SPIKES.md) may invalidate parts of it.

**Two processes, plumbed exactly like xdg-desktop-portal — because one of them *is*
xdg-desktop-portal.** A *frontend* owns the public bus name, establishes who is calling,
applies policy and permissions, and owns the request and session lifecycle. A *backend*
draws the windows, holds the PKCS#11 session, and performs the cryptography. The
application talks only to the frontend and never learns the backend's name.

This repository is **the backend**. The frontend is a branch of xdg-desktop-portal:
`experimental/certificate-webauthentication`, commits `3f46e3c..661e441`, with
`703fb22 certificate: Add an experimental Certificate portal` defining the two interfaces
and implementing the portal. Why it lives there rather than here is
[0010](decisions/0010-backend-only-frontend-lives-upstream.md); the split itself is
[0008](decisions/0008-build-to-the-upstream-shape.md), which 0010 preserves.

**The core contract is unchanged by the split**: credential selection plus brokered
operations. The application never receives the key, never receives the PIN, and never
receives a PKCS#11 handle either — the compatibility endpoint that would have given it
one is not in the interface at all (see "The endpoint that is not there" below).

## Who does what

The division is upstream's, not invented here, and it is no longer paraphrased from
upstream: the left-hand column now describes code that exists, in
`xdg-desktop-portal/desktop-portal/certificate.c` on the branch.

| Concern | Frontend — `xdg-desktop-portal` (branch) | Backend — `xdg-desktop-portal-certificate` (here) |
|---|---|---|
| **Caller identity** | `xdp_invocation_get_app_info()`; derives `app_identity_level` (`verified_sandboxed` / `derived_host` / `unidentified`) once and forwards it | Never derives anything. Receives `app_id` and `app_identity_level` as **arguments** |
| **Bus name applications use** | `org.freedesktop.portal.Desktop` — the only one | `org.freedesktop.impl.portal.desktop.certificate` — not for applications |
| **Object path** | `/org/freedesktop/portal/desktop` | the same path, on its own bus name |
| **Policy** | `xdp_filter_options()` with per-key validators: `purpose` ∈ `client_auth\|signing\|email\|ssh` (required), `interaction_mode` ∈ `required\|allowed\|forbidden`, `mechanism` ∈ `RSA_PKCS1_V1_5\|RSA_PSS\|ECDSA`, `reason` ≤ 256 chars, `data`/`ciphertext` ≤ 1 MiB. Unknown keys dropped, not forwarded | Enforces what it is told, plus its own hard limits. Never widens |
| **Grant lifetime** | `requested_lifetime` clamped to 3600 s, default 300, forwarded as `lifetime` — a decision, not a request | Obeys it. Cannot expire or renew a grant |
| **Results clamping** | Intersects the backend's `supported_mechanisms` and `permitted_operations` with its own lists, in its own order, before the app sees them *and* before recording them on the grant | Reports what it can do; over-claiming gets clamped, not believed |
| **Permissions** | Permission store table `certificate`, id = app id, value = the backend's `certificate_id`; written only when the app passed `allow_selection_memory` **and** the user asked to remember, never for an unidentified app; read back as `preselect_certificate` | Never touches it. Told what to preselect; reports `certificate_id` and `remember_selection` |
| **Request lifecycle** | `xdp_request_dex_*`; one terminal `Response`; cancellation | Exports an impl `Request` at the path the frontend chose; `Close()` only |
| **Session lifecycle** | `xdp_session_dex_*` plus its own grant table; `RenewGrant` decided **entirely** here — the backend is never asked and no window appears | The token session behind it: PKCS#11 session, login state, handles |
| **Backend selection** | `.portal` files and `portals.conf` (`xdp-portal-config.c`) | Declares itself in `data/certificate.portal` |
| **UI** | Draws nothing | Chooser and PIN prompt, in its own words, with accessibility as acceptance criteria |
| **Device access** | Loads no PKCS#11 module, never talks to p11-kit, never sees a card serial | Token discovery, certificate reading, `C_Login`, `C_Sign`, card-removal watching |
| **PIN** | Cannot see one — not a rule it obeys, a thing it cannot do | Collects it in its own window; it never leaves the process |
| **Logging** | Which app, which honesty level, which purpose, granted or refused | Token presence, mechanism names, PIN outcome codes |

Upstream splits Camera and USB slightly differently — for those the *frontend* opens the
device (a PipeWire remote, an fd from `open()`) and the backend only draws the permission
dialog. That does not work here: a PKCS#11 session is not a file descriptor you can hand
over, it is a login state with handles attached, and the process that draws the PIN prompt
must be the process that holds it. The precedent this follows is ScreenCast and
RemoteDesktop, where the backend owns the device and hands back a descriptor. That was
recorded as "a thing to raise with maintainers"; it is now a thing that is *written down
in the branch*, which is a better place to argue about it from.

```
  application                  FRONTEND (xdg-desktop-portal)     BACKEND (here)        the card
  ───────────                  ─────────────────────────────     ──────────────        ────────
                    D-Bus                       D-Bus impl iface
  CreateSession ─────────────►  Request + Session ─────────────►  impl session
    ◄── Response(0, {session_handle})   ← A REQUEST, not a direct return
  AcquireCredential ─────────►  xdp_invocation_get_app_info()  ← WHO IS ASKING
                                certificate.c   ← purpose, options, policy, ceiling
                                xdp-permissions ← remembered SELECTION
                                xdp-portal-config ← which backend
                                     │
                                     │ AcquireCredential(handle, session, app_id,
                                     │                   parent_window, options)
                                     └──────────────────►  tokens/discovery.h ──► p11-kit ──► OpenSC ──► pcscd
                                                           tokens/filter.h
                                                           ui/chooser.h   ← THE CONSENT WINDOW
                                                                │
                                     ◄─────────────────────── (response, results)
                                grant table   ← identity, expiry, ownership, clamping
  ◄─── Response(0, { grant_id, certificate_der, chain_der, chain_status,
                     token_display, key_type, supported_mechanisms,
                     permitted_operations, expires_at, may_prompt_later })

  Sign(session, opts) ───────►  check grant, owner, operation, mechanism
                                     │  Sign(handle, session, app_id, parent, options)
                                     └──────────────────►  broker/operations.h
                                                             ├─ consent policy for this purpose
                                                             ├─ ui/pin.h ── C_Login ──►  (backend's OWN session)
                                                             └─ mechanism + parameter validation
  ◄─── Response(0, { signature })                            └─ C_Sign ──────────────►
```

## The endpoint that is not there

`OpenPkcs11Endpoint` is **not** on either interface. The frontend branch left it out
deliberately: an fd-returning method needs its own review, and a python-dbusmock backend
cannot hand back a usable endpoint fd, so a first version carrying it would have shipped
untested. It is a follow-up, to land with the facade rules in [SECURITY.md](SECURITY.md).

Everything this document used to say about relaying a descriptor through two processes is
therefore a description of future work, not of the current contract.
[`../src/export/facade.h`](../src/export/facade.h) is kept for the same reason: its
requirements list is the acceptance criteria for that follow-up, and deleting it would
mean rediscovering it.

## The correction this design is built on

An earlier draft of this project said: hand the consumer a PKCS#11 module scoped to one certificate
and key, already logged in, produced with `p11-kit server`. **That was wrong**, in ways that change
the architecture rather than the wording:

- `p11-kit server`'s unit of exposure is a **token**, selected by a token URI. There is no
  supported object-scoping guarantee.
- Forwarding forwards the *whole* PKCS#11 interface, including object creation, key generation,
  wrapping and derivation.
- **Login state does not transfer.** The consumer's TLS stack opens its own sessions and makes its
  own `C_Login` call; a session the service logged into is not the session the consumer gets. Any
  device-wide login caching is provider behaviour and must never become an API contract.
- `p11-kit-client.so` is located through process-level p11-kit configuration plus one
  `P11_KIT_SERVER_ADDRESS`, which does not accommodate several concurrent per-request grants inside
  one process.
- A PKCS#11 URI cannot name a socket, and `g_tls_certificate_new_from_pkcs11_uris()` has no module
  parameter — so "return a URI and an address" does not compose.

The ten failure modes are enumerated in
[decisions/0006-failure-modes-of-naive-p11kit-forwarding.md](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md).
The consequence is [0007](decisions/0007-brokered-operations-are-the-core.md): brokered operations
are the core contract, and any PKCS#11 surface must be a **synthetic facade the broker implements**,
not the real token forwarded. The frontend branch has taken that to its conclusion for now by
shipping the brokered half and deferring the facade half entirely.

## Components

Everything below is in this repository. The frontend's components are upstream's and are
not re-described here; read `desktop-portal/certificate.c` on the branch.

### The impl skeleton — [`../src/certificate-impl.h`](../src/certificate-impl.h), [`request-impl.h`](../src/request-impl.h), [`session-impl.h`](../src/session-impl.h)

Owns `org.freedesktop.impl.portal.desktop.certificate` on the session bus and exports
`/org/freedesktop/portal/desktop`. One file per portal interface, exactly as
xdg-desktop-portal-gtk does it. The impl `Request` has `Close()` and no `Response` signal:
the result of an impl call is the method's own return value, and exactly one object — the
frontend's `Request` — is responsible for the at-most-one-terminal-response rule.

Two upstream traps worth knowing about, both found while writing the frontend and recorded
in the branch write-up: `xdp_request_dex_new()` does *not* export the frontend Request
(`xdp_request_dex_export()` must be called separately, or the Response is silently
swallowed), and `xdp_session_dex_store_new_wrapped()` is unusable as written. Neither is
this backend's problem, but both explain why the frontend looks the way it does.

**Nothing here derives or decides.** The backend renders the app id and identity level it
was given, applies the lifetime it was told, and re-validates every mechanism and
parameter even though the frontend already did. Two checks against a hostile caller is the
correct number.

### Token and slot discovery — [`../src/tokens/discovery.h`](../src/tokens/discovery.h)

Enumerates slots and tokens through p11-kit's configured modules, asynchronously and under a
`GCancellable`, and watches for insertion and removal.

The Remmina RDP plugin's PKCS#11 support
([`patches/0005-…-PKCS11-client-certificates-in-WebKit.patch`](https://gitlab.com/Remmina/Remmina),
GPL-2.0-or-later, not copied here) is the working prior art, and its scars are the requirements
list. It proved, on real hardware:

- enumeration by driving a **fixed argv** (`p11tool --list-certs --only-urls`) in a cancellable,
  time-bounded subprocess with a bounded output buffer, rather than loading arbitrary modules into
  the UI process;
- **asynchronous discovery with cancellation**, so a missing reader or a wedged middleware daemon
  never blocks the main loop;
- p11-kit's own **trust tokens** (`model=p11-kit-trust`) never hold client certificates and are
  skipped without spawning anything;
- a token holding **no matching object** makes the tool exit non-zero with no output — not an error
  and it must not abort discovery, while a non-zero exit *with* output, a signal death, an
  output-limit breach or a token-listing failure all must;
- locating the tool at run time rather than assuming a path;
- certificate loading off the UI thread, because a card can take seconds;
- `g_tls_certificate_new_from_pkcs11_uris()`
  ([GLib 2.68+](https://docs.gtk.org/gio/ctor.TlsCertificate.new_from_pkcs11_uris.html)) turning a
  chosen URI into a usable `GTlsCertificate` — the *ends* of the WebKit chain, though not the
  middle; see [SPIKES.md](SPIKES.md) S3;
- a PIN answered **once per challenge plus one engine-initiated retry**, then expired, so the card's
  retry counter is never spent by a loop;
- everything logged as counts and reason codes, never URIs, labels, serials or PINs.

**This service should not shell out.** A fixed-argv subprocess was right inside a Remmina plugin,
where a runtime dependency on `gnutls-utils` is cheaper than linking. Here enumeration is the
*product*, so `src/tokens/discovery.h` describes direct use of the p11-kit managed-module API. The
edge-case list above survives the change of mechanism unaltered — it is a list of things cards do,
not things `p11tool` does — and it is the acceptance criteria for the rewrite.

**Tokens are identified by every stable attribute available** — manufacturer, model, serial, label
— never by slot number, and never by label alone. A reinserted card is a *new* token until proven
otherwise.

### Certificate filtering — [`../src/tokens/filter.h`](../src/tokens/filter.h)

Reduces the discovered certificates to the ones that can satisfy the request, before any are shown.
All filters optional, all AND-ed:

| Filter | Meaning |
|---|---|
| `purpose` | `client_auth` → EKU `1.3.6.1.5.5.7.3.2`; `signing` → `1.3.6.1.5.5.7.3.3`; `email` → `1.3.6.1.5.5.7.3.4`; `ssh` → no EKU constraint but its own consent policy |
| `eku` | explicit OID list where the purpose shorthand is not enough |
| `issuers` | DER-encoded issuer DNs, as a TLS `CertificateRequest` supplies them |
| `key_usage` | X.509 key-usage bits that must be present |
| `key_algorithms` | acceptable key types and signature schemes the caller can actually use |
| `token_label` | restrict to one token |
| `piv_slot` | PIV slot by name — `authentication` (9A), `signature` (9C), `key_management` (9D), `card_authentication` (9E) |

**There is no `any` purpose.** A request that will not say what it is for cannot be described to
the user in the service's own words, cannot be given a consent policy, and cannot be filtered. The
frontend rejects it before this backend is woken.

Two rules are not negotiable. **Expired and not-yet-valid certificates are shown, marked, and
selectable** — an expired certificate is a diagnosis the user needs, and hiding it produces "my card
is empty" bug reports. **Filtering never narrows the set to one and auto-confirms**: a single
candidate still gets a chooser, because the chooser is where consent happens.

### Chooser UI — [`../src/ui/chooser.h`](../src/ui/chooser.h)

A **backend**-owned window, parented to `parent_window` when one was supplied and valid,
unparented otherwise. It must show, in text the caller cannot influence — and note that the
first two items *arrive from the frontend as arguments*, which is the whole point of the
split: the side that knows who is calling is not the side drawing the window, so the window
cannot be talked into naming the wrong application by the application:

1. **the application id the frontend established**, and a human-readable name this backend
   derives from it if it can — there is no `app_display_name` on the wire;
2. **how well that identity is known** — `app_identity_level` is `verified_sandboxed`,
   `derived_host` or `unidentified` — with an explicit warning for the second and the
   strongest warning the design has for the third;
3. **the purpose, in the service's own words** — "sign in to a website", "sign a document" — never
   the caller's;
4. **the operation class** being granted: authenticate, sign, or decrypt;
5. **the certificate**: subject identity, issuer, validity, and a fingerprint or short stable
   identifier behind a details view;
6. **the token and reader** name;
7. **the grant duration**, or "this operation only";
8. **whether further operations may occur without another prompt** — stated plainly, because this
   is the part users get wrong;
9. the caller's `reason` string, visibly separated and **labelled as application-provided text**.

Nothing may occupy the trusted application-identity position except the identity the frontend
established: not `reason`, not a caller-supplied title, not the token label, not the certificate
subject. A caller that writes `reason: "Microsoft Login"` must not get a window that reads as
Microsoft's.

**There is no `context` option.** The earlier sketch had one, carrying the destination host
for client authentication as caller-supplied text. The branch interface does not have it,
so a client-authentication request arrives with no place to state a destination except
`reason` — which is the same untrusted text with a different name. Remembered selection is
keyed by the frontend on the app id and nothing the caller supplied.

Accessibility is an acceptance criterion, not polish: AT-SPI exposure for every control, complete
keyboard-only operation, meaningful focus order, screen-reader announcement of the verified caller,
purpose and operation class, scalable text, high contrast, reduced-animation behaviour, no
information carried by colour alone, accessible error and cancellation states, and focus restored
to the calling application afterwards. The chooser and the PIN prompt *carry* the security
decision; nothing else in the stack covers them.

### PIN UI — [`../src/ui/pin.h`](../src/ui/pin.h)

A separate **backend**-owned window, shown when the broker needs to log into its own session — which is
**at first private-key use, not at grant time** (see "Login model" below). It names the token being
unlocked and restates the verified caller, purpose and operation class.

- The PIN buffer is allocated in locked, non-swappable memory where the platform allows, is wiped on
  every exit path — success, failure, cancel, timeout, window destroyed, crash handler — and never
  enters a `GVariant`, a log, a `GError` message, a URI, or a D-Bus message. Neither interface has a
  field a PIN could travel in. Core dumps are disabled for the process where practical.
- **Remaining retries are displayed only when the token reliably reports them, and never invented.**
  A login failure warns before the final known retry.
- The service **distinguishes and reports separately**: incorrect PIN, blocked PIN, cancelled
  prompt, device error, and token removal. It never automatically retries after an ambiguous
  transport failure, and all retries are user-initiated.
- **Protected authentication path.** When the token sets `CKF_PROTECTED_AUTHENTICATION_PATH` — PIN
  pad readers, biometric tokens — the underlying login is made with a null PIN and the token or
  reader collects the secret itself. The service shows an **instructional dialog with no editable
  PIN field** and never receives the PIN. Emulating a PIN field for such a token would be a lie
  about where the secret goes. The frontend advertises this to applications as
  `protected_authentication_path` in `GetCapabilities`, having asked this backend.
- **Prompts for the same token are serialised.** Two grants wanting the same card do not race two
  windows at the user.
- **Headless: never read a PIN from stdin.** With no display, or with `interaction_mode: forbidden`,
  the call fails rather than prompting. A trusted agent protocol for headless use would be a
  separate, separately configured, separately reviewed thing.

Same accessibility criteria as the chooser, plus: the PIN field is never echoed and its contents
never enter the accessibility tree, while the "incorrect PIN, N attempts remaining" state is
announced.

### Broker — [`../src/broker/operations.h`](../src/broker/operations.h)

The core. Holds the underlying PKCS#11 session and performs operations on the application's behalf.

- **Consent policy is per purpose**, applied per operation:
  - `client_auth` — one consent per short-lived grant, bound to one verified application and one
    certificate; expires after the authentication attempt or a few minutes.
  - `signing` — **per-operation consent by default**, showing the application context and a digest
    or fingerprint of what is being signed when the content cannot safely be rendered. High-volume
    or unattended signing needs separately configured policy, never a checkbox.
  - `email` — a session grant is defensible for sending or reading mail; bulk behaviour must be
    explicit.
  - `decrypt` — per-operation, or a tightly bounded session, because decryption exposes confidential
    data rather than producing an authentication artefact.
  - `ssh` — its own purpose and its own policy. It is not "signing with extra steps".
- **A PIN prompt is not consent.** Consent is the chooser and the per-operation policy above.
  A cached token login must never silently authorise a different application or a different purpose.
- **Mechanism allow-list with parameter validation.** The frontend's list is exactly
  `RSA_PKCS1_V1_5`, `RSA_PSS` and `ECDSA`, and it intersects whatever this backend reports
  with that list, in its order, before any of it reaches an application. RSA-PSS parameters
  (hash, MGF, salt length) are validated against the mechanism and the key here, not passed
  through. Nothing the client sends — handles, lengths, operation state — is trusted.
- **Rate limits** per grant and per caller. Note that the frontend does *not* implement rate
  limiting yet — it is on the branch's own open-items list — so for now this is the only
  place it could happen.
- Operations carry a caller-supplied `operation_id` so a cancellation, a result and a log line can
  be correlated without correlating them by content.

**Login model: lazy login.** Of the three options —

1. the consumer calls `C_Login` and the service intercepts and prompts;
2. the grant is pre-authorised and the service logs into **its own** session lazily, at first
   private-key use;
3. protected authentication path, where the token collects the secret —

this design picks **(2)**, with (3) wherever the token advertises it. Pre-logging in at grant time
is wrong twice over: it spends the user's presence before it is needed, and across any future facade
it buys nothing, because login state does not cross the forwarding boundary. Libraries that expect
particular `C_Login` return codes are a known compatibility hazard and are part of
[SPIKES.md](SPIKES.md) S2 — which only becomes answerable when there is an endpoint to answer it
about.

### The synthetic PKCS#11 facade — [`../src/export/facade.h`](../src/export/facade.h)

**EXPERIMENTAL, and currently unreachable: the interface has no method that returns an
endpoint.** See "The endpoint that is not there" above. What follows is the requirements
list for the follow-up, kept so it does not have to be rediscovered.

It is not the real token forwarded. It is a `CK_FUNCTION_LIST` the broker implements, served over a
socket, which:

- exposes **one synthetic slot** containing **one synthetic token**;
- exposes **only** the granted leaf certificate, its public key, its private key, and explicitly
  selected chain certificates — nothing else on the card, and no unrelated public or private
  objects;
- **maps synthetic handles** to broker-owned underlying handles; a client-supplied handle is a
  lookup key, never an address;
- allows **read-only sessions only**; `CKF_RW_SESSION` is refused;
- refuses **SO login** entirely, and treats user `C_Login` as an authorisation-state transition;
- refuses `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_CreateObject`, `C_CopyObject`,
  `C_DestroyObject`, `C_SetAttributeValue`, all key generation, all wrap/unwrap, all derivation
  unless a grant explicitly requires it, RNG seeding, and operation-state export/import;
- restricts `C_GetAttributeValue` so sensitive and unexpected attributes cannot leak;
- exposes only the allow-listed mechanisms, validates their parameters, and refuses encryption and
  decryption unless the grant permits them;
- rate-limits, and terminates on expiry, revocation or card removal;
- implements the **PKCS#11 v3 interface tables** as well as the classic v2 function list — filtering
  only `C_GetFunctionList` leaves `C_GetInterface` as an unfiltered way back in.

The transport can reuse p11-kit's RPC server entry point,
`p11_kit_remote_serve_module(CK_FUNCTION_LIST *module, int in_fd, int out_fd)`, declared in
[`p11-kit/remote.h`](https://github.com/p11-glue/p11-kit/blob/master/p11-kit/remote.h) behind
`P11_KIT_FUTURE_UNSTABLE_API`. **Transport is the small part.** The value p11-kit adds here is a
wire protocol, not a policy.

**The endpoint would be returned as a Unix file descriptor, not a path.** A path is discoverable, is
subject to filesystem races, and needs a bind mount to cross a sandbox; an fd passed over D-Bus is
already the capability and already crosses. `certificate_uri` and `private_key_uri` would be returned
*with* it and are meaningful only on it; a URI without an endpoint that resolves it is not a
capability and is never returned alone. **No `pin-value` or `pin-source` attribute appears in any
URI this service emits, ever**, and error paths truncate any URI that arrives carrying one.

**The likely real architecture, per [SPIKES.md](SPIKES.md) S3.** Handing out a *new* module per
grant probably does not work for GLib/WebKitGTK consumers: a PKCS#11 URI cannot name a socket,
`g_tls_certificate_new_from_pkcs11_uris()` has no module parameter, and WebKit's network process
may already have started before the module exists. The most plausible workaround is the opposite
shape: **one broker module, permanently registered in p11-kit configuration at install time, which
exposes synthetic grant-bound slots** and finds the live grant through the calling process's
identity and the returned URI. That changes the contract from "here is a new module" to "here is a
URI your already-registered broker module can resolve". It is described here as the likely
architecture, and S3 is what decides.

### Where the grant registry went

It is upstream's, in `desktop-portal/certificate.c`. **The frontend owns the grant registry,
and this backend owns the token session behind it.** Grant identity, the binding to an app id
and an owning connection, the operation set, expiry, renewal and invalidation are policy, and
policy is the frontend's; the PKCS#11 session, the login state and the object handles are the
device, and the device is the backend's. So a grant exists before this backend has a session,
this backend cannot expire or renew one, and a backend that dies takes every grant with it —
announced to applications as `GrantInvalidated` with reason `backend_gone` rather than left
for the caller to discover at the next `Sign`.

The `GrantInvalidated` reasons the frontend can emit are fixed by the public XML:
`released`, `expired`, `token_removed`, `owner_gone`, `policy`, `service_shutdown`,
`backend_gone`, `error`. The three this backend can *cause*, through
`SessionInvalidated`, are `token_removed`, `device_error` and `backend_shutdown`.

**Card removal** invalidates every session, cancels any in-flight operation, and emits
`SessionInvalidated`. Reinsertion requires explicit reselection even when the label and slot number
are identical, because they prove nothing.

**Selection memory** (`allow_selection_memory`) remembers **which certificate** the user picked, for
the same verified application. It is preselection, not authorisation: it never skips the trusted
consent step, never skips a PIN prompt, and is unavailable to callers whose identity could not be
verified. The frontend stores it, keyed on the app id, as this backend's `certificate_id`; this
backend never writes it and only receives it back as `preselect_certificate`. There is no "remember
PIN", and there is no remembered authorisation to use the key.

### Logging — [`../src/redact.h`](../src/redact.h)

Structured, with a stable reason code per event, and a hard rule about what may appear: counts,
reason codes, purposes, the app id the frontend supplied, grant and operation ids, token *presence*,
and mechanism names. Never: PINs, PKCS#11 URIs, object labels, key ids, card serials, certificate
subjects, signed data, or the contents of `reason`. Error text from p11-kit, OpenSC and GnuTLS is
truncated before any embedded URI. Redaction is **structural** — a helper that takes the fields it
is allowed to emit — not a filter applied to strings on the way out.

Two journals answer different halves of "what used my card, and when" — xdg-desktop-portal records
the decision and the caller, this backend records the card event — and the grant id and operation
id are what join them. This file used to be `shared/`, compiled into a frontend and a backend in
one repository; it is `src/` now because only one of those is here.

## Process model

- **One D-Bus-activated per-user service in this repository.** Started by
  xdg-desktop-portal's first impl call, via
  `data/org.freedesktop.impl.portal.desktop.certificate.service`. It exits when idle with
  no live sessions: a backend that never exits is a backend holding a card session nobody
  asked it to hold. It is not a system service: cards are the user's and nothing here needs
  root.
- **The frontend is xdg-desktop-portal**, one process for the whole desktop, already
  running, already activated by everything else. There is no second portal process any
  more, which removes the "three processes for one signature" cost
  [0008](decisions/0008-build-to-the-upstream-shape.md) accepted — and would have removed a
  fourth, the facade helper, if the facade existed.
- **The impl interface is private.** Applications talk to `org.freedesktop.portal.Desktop`
  and nothing else. How that is enforced — and what it does and does not protect against on
  a same-UID desktop — is [IMPL-INTERFACE.md](IMPL-INTERFACE.md).
- **The public interface is gated.** With `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` unset,
  `org.freedesktop.portal.experimental.Certificate` is not exported, does not appear in
  introspection, and this backend is never called. That is a property of the frontend, and
  this repository cannot turn it on.
- **UI toolkit.** GTK4 here. A Qt/KDE chooser and PIN prompt is a second *backend package*
  with its own `.portal` file, selected by `portals.conf`, not a second code path inside one
  binary. It remains a phase 1 goal and a prerequisite for phase 2; there is still no KDE
  equivalent of gcr's prompter to defer to.

## What this project does not own

- **The public interface.** It is defined by the xdg-desktop-portal branch, and the copy of
  the impl XML in `data/` tracks that branch verbatim. If this repository and the branch
  disagree, the branch is right.
- **TLS.** Nothing here does a handshake, chooses a cipher, or validates a chain. It produces
  signatures on request.
- **Semantic attestation.** A `Sign` call cannot prove its input came from a TLS handshake rather
  than from a PDF or from nothing. Purpose constrains certificate selection and consent language; it
  does not prove what a signature was later used for. Anyone who reads a `purpose` as a guarantee
  has misread it.
- **The application's UI.** This backend draws a chooser and a PIN prompt. It draws no progress,
  results or errors on the consumer's behalf.
- **Chain construction as a trust claim.** Many tokens store only the leaf. The service returns what
  the card holds plus what it can assemble from system stores, and labels the result `complete`,
  `partial` or `leaf_only`. It never implies the chain is trusted.
- **Key generation, enrolment, PIN change, PIN unblock, certificate import.** Real needs, entirely
  out of scope for v1, each a different consent question with a different UI — and the reason the
  facade would refuse `C_InitPIN`, `C_SetPIN` and key management outright. A service that mediates
  *use* should not be able to perform *administration*.
- **PIN caching beyond a grant.** The service never holds a PIN after the login that used it.
  Nothing persists a PIN and no option asks it to.
- **The CA trust store.** p11-kit already forwards the trust module into sandboxes; different
  problem, already solved.
- **pcscd, OpenSC, or the card's firmware.** Bugs there are bugs there.
- **Non-PIV cards, in v1.** OpenSC-compatible PIV only, because that is what can be tested.

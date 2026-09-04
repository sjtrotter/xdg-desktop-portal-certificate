# Architecture

Status: EXPERIMENTAL design sketch. None of this is implemented, and
[SPIKES.md](SPIKES.md) may invalidate parts of it.

One process owns the user's credentials and the user's interaction with them. **The core contract
is credential selection plus brokered operations**: the application never receives the key, never
receives the PIN, and — unless it explicitly asks for the experimental compatibility endpoint and
the service grants it — never receives a PKCS#11 handle either.

```
    application                 smartcard-portal                    the card
    ───────────                 ────────────────                    ────────
                        D-Bus
    AcquireCredential ───────►  transaction layer  (src/dbus/)
                                       │
                                       ▼
                                token discovery    (src/tokens/discovery.h)  ──► p11-kit ──► OpenSC ──► pcscd
                                certificate filter (src/tokens/filter.h)
                                       │
                                       ▼
                                chooser window     (src/ui/chooser.h)
                                       │
                                       ▼
                                grant registry     (src/grant/registry.h)
    ◄─── Response(0, { grant_id, certificate_der, chain_der, chain_status,
                       token_display, key_type, supported_mechanisms,
                       permitted_operations, expires_at, may_prompt_later })

    Sign(grant_id, op_id, ─────►  broker           (src/broker/operations.h)
         mechanism, params,               │
         data)                            ├─ consent policy for this purpose
                                          ├─ PIN window (src/ui/pin.h) ── C_Login ──►  (broker's OWN session)
                                          └─ mechanism allow-list + parameter validation
    ◄─── signature                                          └─ C_Sign ──────────────►

    ── EXPERIMENTAL, milestone 2, opt-in ───────────────────────────────────────────
    OpenPkcs11Endpoint(grant_id) ►  synthetic facade (src/export/facade.h)
    ◄─── endpoint_fd                      one synthetic slot, one synthetic token,
                                          the granted objects, read-only sessions,
                                          a mechanism allow-list, handle mapping,
                                          lazy login through the broker's own session
```

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
not the real token forwarded.

## Components

### D-Bus transaction layer — `src/dbus/service.h`, `src/dbus/request.h`

Owns `io.github.sjtrotter.Smartcard1` on the session bus and exports
`/io/github/sjtrotter/Smartcard1`. Interactive calls follow the
[xdg-desktop-portal `Request` pattern](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html):
the caller supplies an unguessable `handle_token`, can compute the request object path and subscribe
to it *before* the call returns, cancels through `Request.Close()` rather than a bespoke `Cancel`,
and receives at most one terminal `Response`. The pattern is copied; the namespace is not.

Non-interactive calls (`Sign`, `Decrypt`, `ReleaseGrant`, `GetCapabilities`) are ordinary methods —
except that `Sign` and `Decrypt` *may* become interactive, when the purpose's consent policy or a
lazy login requires a prompt. That is why the acquire response carries `may_prompt_later`: a caller
must never be able to claim it was promised silence.

### Token and slot discovery — `src/tokens/discovery.h`

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

### Certificate filtering — `src/tokens/filter.h`

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
the user in the service's own words, cannot be given a consent policy, and cannot be filtered. It
is rejected.

Two rules are not negotiable. **Expired and not-yet-valid certificates are shown, marked, and
selectable** — an expired certificate is a diagnosis the user needs, and hiding it produces "my card
is empty" bug reports. **Filtering never narrows the set to one and auto-confirms**: a single
candidate still gets a chooser, because the chooser is where consent happens.

### Chooser UI — `src/ui/chooser.h`

A service-owned window, parented to `parent_window` when one was supplied and valid, unparented
otherwise. It must show, in text the caller cannot influence:

1. **verified application name and application id**;
2. **sandboxed or unsandboxed**, with an explicit warning for unverified or unsandboxed callers;
3. **the purpose, in the service's own words** — "sign in to a website", "sign a document" — never
   the caller's;
4. **the operation class** being granted: authenticate, sign, or decrypt;
5. **the certificate**: subject identity, issuer, validity, and a fingerprint or short stable
   identifier behind a details view;
6. **the token and reader** name;
7. **the grant duration**, or "this operation only";
8. **whether further operations may occur without another prompt** — stated plainly, because this
   is the part users get wrong;
9. the caller's `reason` and `context` strings, visibly separated and **labelled as
   application-provided text**.

Nothing may occupy the trusted application-identity position except the identity the service
established: not `reason`, not a caller-supplied title, not the token label, not the certificate
subject. A caller that writes `reason: "Microsoft Login"` must not get a window that reads as
Microsoft's.

For client authentication the user also needs the **destination host**, and this service cannot
derive it: it sees a D-Bus peer, not a TLS connection. `context` carries it, is displayed as
*requested* destination, and is treated as application-provided. Remembered selection is keyed only
on trusted fields unless the service can independently verify the peer.

Accessibility is an acceptance criterion, not polish: AT-SPI exposure for every control, complete
keyboard-only operation, meaningful focus order, screen-reader announcement of the verified caller,
purpose and operation class, scalable text, high contrast, reduced-animation behaviour, no
information carried by colour alone, accessible error and cancellation states, and focus restored
to the calling application afterwards. The chooser and the PIN prompt *carry* the security
decision; nothing else in the stack covers them.

### PIN UI — `src/ui/pin.h`

A separate service-owned window, shown when the broker needs to log into its own session — which is
**at first private-key use, not at grant time** (see "Login model" below). It names the token being
unlocked and restates the verified caller, purpose and operation class.

- The PIN buffer is allocated in locked, non-swappable memory where the platform allows, is wiped on
  every exit path — success, failure, cancel, timeout, window destroyed, crash handler — and never
  enters a `GVariant`, a log, a `GError` message, a URI, or a D-Bus message. Core dumps are disabled
  for the process where practical.
- **Remaining retries are displayed only when the token reliably reports them, and never invented.**
  A login failure warns before the final known retry.
- The service **distinguishes and reports separately**: incorrect PIN, blocked PIN, cancelled
  prompt, device error, and token removal. It never automatically retries after an ambiguous
  transport failure, and all retries are user-initiated.
- **Protected authentication path.** When the token sets `CKF_PROTECTED_AUTHENTICATION_PATH` — PIN
  pad readers, biometric tokens — the underlying login is made with a null PIN and the token or
  reader collects the secret itself. The service shows an **instructional dialog with no editable
  PIN field** and never receives the PIN. Emulating a PIN field for such a token would be a lie
  about where the secret goes.
- **Prompts for the same token are serialised.** Two grants wanting the same card do not race two
  windows at the user.
- **Headless: never read a PIN from stdin.** With no display, or with `interaction_mode: forbidden`,
  the call returns `no_display` or `interaction_required`. A trusted agent protocol for headless use
  would be a separate, separately configured, separately reviewed thing.

Same accessibility criteria as the chooser, plus: the PIN field is never echoed and its contents
never enter the accessibility tree, while the "incorrect PIN, N attempts remaining" state is
announced.

### Broker — `src/broker/operations.h`

The core. Holds the underlying PKCS#11 session and performs operations on the application's behalf.

- **Consent policy is per purpose**, applied per operation:
  - `client_auth` — one consent per short-lived grant, bound to one verified application, one
    certificate and preferably one destination `context`; expires after the authentication attempt
    or a few minutes.
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
- **Mechanism allow-list with parameter validation.** Only the mechanisms the granted key and the
  approved use require — RSA PKCS#1 v1.5, RSA-PSS and ECDSA as the tested cards need. RSA-PSS
  parameters (hash, MGF, salt length) are validated against the mechanism and the key, not passed
  through. Nothing the client sends — handles, lengths, operation state — is trusted.
- **Rate limits** per grant and per caller, and an optional single-use grant.
- Operations carry a caller-supplied `operation_id` so a cancellation, a result and a log line can
  be correlated without correlating them by content.

**Login model: lazy login.** Of the three options —

1. the consumer calls `C_Login` and the service intercepts and prompts;
2. the grant is pre-authorised and the service logs into **its own** session lazily, at first
   private-key use;
3. protected authentication path, where the token collects the secret —

this design picks **(2)**, with (3) wherever the token advertises it. Pre-logging in at grant time
is wrong twice over: it spends the user's presence before it is needed, and across the facade it
buys nothing, because login state does not cross the forwarding boundary. On the facade, a
consumer's `C_Login` is treated as an **authorisation-state transition** — it does not carry a real
PIN and the facade does not forward one — and the broker prompts and logs into its own underlying
session when the first `C_Sign` or `C_Decrypt` arrives. Libraries that expect particular `C_Login`
return codes are a known compatibility hazard and are part of [SPIKES.md](SPIKES.md) S2.

### The synthetic PKCS#11 facade — `src/export/facade.h`

**EXPERIMENTAL, milestone 2, requested explicitly through `OpenPkcs11Endpoint`, never returned
automatically.** This is the compatibility path for consumers that can only consume a module, and
it is a **security-sensitive PKCS#11 implementation** — not plumbing, not a wrapper, not "p11-kit
does it for us".

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

**The endpoint is returned as a Unix file descriptor, not a path.** A path is discoverable, is
subject to filesystem races, and needs a bind mount to cross a sandbox; an fd passed over D-Bus is
already the capability and already crosses. `certificate_uri` and `private_key_uri` are returned
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

### Grant registry — `src/grant/registry.h`

Live grants: id, owner connection, delegated endpoint holders, verified caller identity, certificate,
token identity, purpose, operation policy, mechanism allow-list, operation counter, expiry, and one
atomic terminal state with an invalidation reason.

**Lifetime is not simply the owner's D-Bus connection.** The process that performs the cryptography
may be a browser network subprocess with its own socket connection, so killing the grant when the UI
process's D-Bus connection drops can kill a valid handshake — while keeping it alive for the
subprocess permits use after the request that authorised it has ended. The model is:

- an **owner** D-Bus connection, which acquired the grant;
- zero or more **delegated endpoint holders**, connections to the grant's endpoint that the owner
  caused to exist;
- the grant dies when the owner releases it **or** when all permitted holders have disappeared;
- with a **short orphan grace period** for the gap between the owner asking and the subprocess
  connecting, after which an unclaimed grant is destroyed.

**Multiple concurrent grants per application are supported** and are independent: separate
lifetimes, separate cancellation, separate certificates, separate policy. Two origins in one browser
is the normal case, not the exotic one.

`RenewGrant` extends a grant only while the caller identity and token binding are unchanged, and
**never expands the permitted operations**. Reauthorisation is required after long inactivity, token
reinsertion, policy change, or a change in application identity.

**Card removal** invalidates every synthetic object and session, cancels any in-flight operation,
returns the appropriate PKCS#11 device or token error to a facade client, emits `GrantInvalidated`,
and **poisons the endpoint** so it cannot silently rebind to a reinserted card. Reinsertion requires
explicit reselection even when the label and slot number are identical, because they prove nothing.

**Selection memory** (`allow_selection_memory`) remembers **which certificate** the user picked, for
the same verified application, purpose and filter context. It is preselection, not authorisation: it
never skips the trusted consent step, never skips a PIN prompt, is unavailable to callers whose
identity could not be verified, is session-scoped unless the user makes it durable, and is listed
and revocable in the service's own UI. There is no "remember PIN", and there is no remembered
authorisation to use the key.

### Logging — `src/log/redact.h`

Structured, with a stable reason code per event, and a hard rule about what may appear: counts,
reason codes, purposes, resolved caller identity, grant and operation ids, token *presence*, and
mechanism names. Never: PINs, PKCS#11 URIs, object labels, key ids, card serials, certificate
subjects, signed data, or the contents of `reason` and `context`. Error text from p11-kit, OpenSC
and GnuTLS is truncated before any embedded URI. Redaction is **structural** — a helper that takes
the fields it is allowed to emit — not a filter applied to strings on the way out.

## Sequence — client authentication through brokered signing

```
application                     smartcard-portal                    card
  │
  ├─ AcquireCredential(parent, {handle_token, purpose: client_auth,
  │      certificate_filter: {issuers: <from CertificateRequest>},
  │      operation_policy: {sign}, interaction_mode: allowed,
  │      context: "<destination host>"})                     ──────►
  │   ◄── o /io/github/sjtrotter/Smartcard1/request/<sender>/<token>
  │                                │
  │                                ├─ resolve caller identity (sandboxed? verified?)
  │                                ├─ discover tokens, filter by issuer + EKU ────────►
  │                                ├─ chooser: verified app, sandbox status, purpose,
  │                                │   certificate, token, duration, "may prompt again"
  │   ◄── Response(0, {grant_id, certificate_der, chain_der, chain_status: partial,
  │                    token_display, key_type, supported_mechanisms,
  │                    permitted_operations: [sign], expires_at, may_prompt_later: true})
  │
  ├─ (TLS stack builds CertificateVerify input)
  ├─ Sign(grant_id, op_id, "ECDSA", {hash: SHA256}, <digest>)  ───►
  │                                ├─ consent policy: covered by this grant
  │                                ├─ first private use → PIN window ── C_Login ──────►
  │                                ├─ mechanism + parameters validated
  │                                └─ C_Sign ──────────────────────────────────────────►
  │   ◄── signature
  │
  ├─ handshake completes
  └─ ReleaseGrant(grant_id)        └─ close session, log out, invalidate, reap
```

No `--socket=pcsc`. No PIN in the application. No PKCS#11 handle in the application. What the
application does need is a TLS stack that will let it supply a signature rather than a key — which
is exactly the integration work that makes Firefox and Chromium **not** MVP consumers.

## Sequence — the web-auth service answering a WebKit challenge

```
entra client → webauth-service                    smartcard-portal
                    │
                    │ WebKit "authenticate" signal, client certificate,
                    │ host certauth.<authority>
                    │
                    ├─ AcquireCredential({purpose: client_auth, operation_policy: {sign},
                    │      context: "<origin>", certificate_filter: {issuers}}) ────►
                    │                                    ├─ identity resolves to
                    │                                    │  webauth-service, NOT to the
                    │                                    │  RDP client behind it
                    │                                    ├─ chooser, naming webauth-service
                    │                                    │  and the requested destination
                    │   ◄─── Response(0, {grant_id, certificate_der, …})
                    │
                    ├─ OpenPkcs11Endpoint(grant_id) ────────────────────────► EXPERIMENTAL
                    │   ◄─── {endpoint_fd, certificate_uri, private_key_uri, endpoint_version}
                    │
                    ├─ g_tls_certificate_new_from_pkcs11_uris(cert_uri, key_uri)
                    │      ── and this is the step that may not work; see SPIKES S3 ──
                    ├─ webkit_credential_new_for_certificate(...)
                    ├─ webkit_authentication_request_authenticate(request, credential)
                    ├─ GnuTLS drives the handshake; the signature happens in the broker
                    │   ── possibly from WebKit's NETWORK process, not this one ──
                    └─ ReleaseGrant on every exit path
```

Two windows will name the same origin — the web view's own security chrome and this service's
chooser. That is not duplication: they are two independent statements of the same true thing, one of
which the caller cannot influence. Two windows asking for a PIN would be duplication, and there is
one.

**Two problems are open here and both are called out rather than papered over.**

*Module loading.* This is the weakest link in the entire design and is S3. Until a real WebKitGTK
mutual-TLS handshake completes through the facade, `webauth-service` must keep its in-process
certificate handling behind an internal adapter, so that it can use either path.

*Delegation.* `webauth-service` asks on behalf of an RDP client that asked on behalf of a user. This
service sees only its immediate D-Bus peer. Version 1 shows the immediate peer and nothing else,
honestly. Passing an *attested* original caller through one hop is a protocol both projects would
have to agree, and neither has. See
[0005](decisions/0005-first-consumer-is-the-web-auth-service.md).

## Process model

- **One D-Bus-activated per-user service.** Started by the session bus on first method call via
  `data/io.github.sjtrotter.Smartcard1.service.in`, exits when idle with no live grants. Not a
  system service: cards are the user's and nothing here needs root.
- **One helper process per facade endpoint.** The synthetic module runs in its own process, holding
  no PIN and reaching the card only by asking the broker, so a bug in the facade — the most
  attacker-exposed code in the project, speaking a wire protocol to a hostile peer — cannot reach
  another grant, the chooser, or the PIN buffer. The brokered `Sign` path does not need one.
- **No frontend/backend split.** There is no `org.freedesktop.impl.portal.*` ABI here. Imitating a
  portal's names confers none of a portal's properties while doubling the D-Bus surface, the
  activation and crash handling, the versioning obligations, the packaging and the transaction
  lifetime bugs. Internally the seam exists — transaction layer → chooser/PIN interface → GTK4
  implementation — as a C vtable, which is where the split goes if it is ever earned.
- **UI toolkit.** GTK4 for the reference chooser and PIN prompt, behind that vtable so a Qt
  implementation is a second implementation rather than a fork. A KDE implementation is a phase 1
  goal and a prerequisite for phase 2; there is no KDE equivalent of gcr's prompter to defer to.

## What this project does not own

- **TLS.** Nothing here does a handshake, chooses a cipher, or validates a chain. It produces
  signatures on request and, on the facade, answers PKCS#11 calls.
- **Semantic attestation.** A `Sign` call cannot prove its input came from a TLS handshake rather
  than from a PDF or from nothing. Purpose constrains certificate selection and consent language; it
  does not prove what a signature was later used for. Anyone who reads a `purpose` as a guarantee
  has misread it.
- **The application's UI.** This service draws a chooser and a PIN prompt. It does not draw progress,
  results or errors on the consumer's behalf.
- **Chain construction as a trust claim.** Many tokens store only the leaf. The service returns what
  the card holds plus what it can assemble from system stores, and labels the result `complete`,
  `partial` or `leaf_only`. It never implies the chain is trusted.
- **Key generation, enrolment, PIN change, PIN unblock, certificate import.** Real needs, entirely
  out of scope for v1, each a different consent question with a different UI — and the reason the
  facade refuses `C_InitPIN`, `C_SetPIN` and key management outright. A service that mediates *use*
  should not be able to perform *administration*.
- **PIN caching beyond a grant.** The service never holds a PIN after the login that used it.
  Nothing persists a PIN and no option asks it to.
- **The CA trust store.** p11-kit already forwards the trust module into sandboxes; different
  problem, already solved.
- **pcscd, OpenSC, or the card's firmware.** Bugs there are bugs there.
- **Non-PIV cards, in v1.** OpenSC-compatible PIV only, because that is what can be tested.

# Security model

Status: EXPERIMENTAL. **Some of this is now implemented and some of it is still an intention**, and
the checklist below says which is which. Nothing here has been reviewed by anyone but its authors,
and nothing here has been run against a real smart card.

The rules in the body of this document are unchanged: they are what the design intends to be true.
The checklist immediately below is what the code in this repository does today, so that a reader
can tell a promise from a fact without reading the source.

**Two processes, one repository.** A *frontend* establishes who is calling and applies policy; a
*backend* draws the windows and holds the token. Every rule below says which one it binds, because
after [0008](decisions/0008-build-to-the-upstream-shape.md) "the service" is not one thing — and
since [0010](decisions/0010-backend-only-frontend-lives-upstream.md) the two things are not even in
the same project. **The frontend is xdg-desktop-portal**, branch
`experimental/certificate-webauthentication`; frontend-side rules below are recorded as *provided
by xdg-desktop-portal*, and are stated here because a backend's obligations only make sense
alongside them, not because this repository implements them. Backend rules are this repository's
and are the ones to hold it to. The division is
[ARCHITECTURE.md](ARCHITECTURE.md#who-does-what); the private interface between them, and how it is
kept private, is [IMPL-INTERFACE.md](IMPL-INTERFACE.md).

**The public interface is gated.** `org.freedesktop.portal.experimental.Certificate` is not
exported unless the portal was started with `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate`.
With the gate off, no application can reach any of this and this backend is never activated. That
is a property of the frontend and this repository cannot change it in either direction.

## What is implemented, and what is not

Backend controls only — the frontend's are xdg-desktop-portal's, on the branch, and are marked as
such throughout the rest of this document.

### Implemented and exercised

| Control | Where | How it is exercised |
|---|---|---|
| Only the owner of `org.freedesktop.portal.Desktop` may call any method — **including `Request.Close()` and `Session.Close()`** | `src/certificate-impl.c`, `reject_stranger()`; `src/request-impl.c`; `src/session-impl.c` | `tests/test-impl-dbus.c`: a third connection calls every method, and both `Close()`s, and is refused |
| The owner is resolved from the bus on every call, not taken from a watcher's cache | `src/certificate-impl.c`, `resolve_frontend_owner()` | `NameOwnerChanged` is not ordered against the former owner's messages; a 100 ms cache bounds the round trips and every *refusal* is decided on a fresh answer |
| A session is bound to the `app_id` it was created for, and its identity level may fall but never rise | `src/certificate-impl.c`, `lookup_session()` | `tests/test-impl-dbus.c`: app B cannot use app A's session; `unidentified` cannot become `verified_sandboxed` |
| A closed session leaves the table and its path can be used again | `src/certificate-impl.c`, `handle_create_session()` | `tests/test-impl-dbus.c`: create, close, create again |
| The Session skeleton stays on the bus after invalidation, so the frontend's answering `Close()` is answered | `src/session-impl.c` | `Close()` is idempotent; the frontend sends one in reply to every `SessionInvalidated` |
| Options are validated strictly: a present field of the wrong type, an unknown enum value or an unknown key in a security-relevant nested vardict is refused, and defaults apply only to absent fields | `src/certificate-impl.c`, `parse_acquire_options()`; `src/tokens/filter.c`; `src/broker/mechanism.c` | `tests/test-impl-dbus.c` drives fourteen malformed option sets; `tests/test-mechanism.c` covers the parameters |
| Export failures abort the call; an unexported session is never inserted | `src/certificate-impl.c`, `src/request-impl.c`, `src/session-impl.c` | a session the frontend cannot close, or a prompt it cannot cancel, is worse than a failed call |
| The app id and its identity level are **displayed, never derived** | `src/ui/chooser.c`, `build_identity()` | the private-bus run shows `identity=unidentified` and the window says so in words |
| Every externally sourced display string — app display name, app id, subject, issuer, token label, reader name, `reason` — is sanitised and capped, with a cap on combining-mark runs | `src/certificate.c`, `certificate_display_text()` | `tests/test-redact.c`; a desktop file's `Name=` is writable by any unsandboxed process and a card's label is chosen by whoever issued it |
| The purpose is rendered in this backend's own words | `src/certificate.c`, `certificate_purpose_display()` | — |
| Expired certificates are offered and marked **in words, not colour** | `src/tokens/filter.c`, `src/ui/chooser.c` | `tests/test-filter.c` |
| A single candidate still opens the chooser | `src/certificate-impl.c` | by construction: there is no code path that skips it |
| The PIN never leaves the process, never enters a GVariant, a GError or a log line | `src/ui/pin.c` | there is no entry point that returns a PIN; the caller passes a login function |
| The PIN buffer is page-aligned, `mlock()`ed where the rlimit allows, `MADV_DONTDUMP`ed, and `explicit_bzero()`ed on every exit path | `src/ui/pin.c`, `PinBuffer` | wiped before the callback runs, on success, failure, cancel and window destroy; an `mlock()` failure is warned about once and does not refuse the login |
| The login worker gets a **private copy** of the PIN that it owns and wipes itself | `src/ui/pin.c`, `pin_buffer_dup()` | `tests/test-cancellation.c` asserts the worker still sees the whole PIN after the window was cancelled |
| Cancelling while `C_Login` is in flight hides the window, defers the answer, and frees nothing until the worker returns | `src/ui/pin.c`, `pin_prompt_finish()` | `tests/test-cancellation.c`, under ASan |
| Core dumps are disabled and `ptrace` attach is blocked for this process | `src/main.c`, `harden()` | `PR_SET_DUMPABLE(0)` plus `RLIMIT_CORE 0`, before anything can fault. `--debug-allow-core` turns it off for development and is never in an installed service file |
| The bus name is only offered for replacement under `--replace` | `src/main.c` | otherwise any process running as the user could take the name and draw the PIN window |
| Nothing persists a PIN | — | there is no option, no keyring call and no configuration key |
| Protected authentication path draws **no PIN field** and logs in with a NULL PIN | `src/ui/pin.c` | — |
| Retry state is shown only from `CKF_USER_PIN_COUNT_LOW` / `FINAL_TRY` / `LOCKED`, never as an invented number, and is **re-read after every refusal** | `src/ui/pin.c`, `retry_hint()`; `src/tokens/discovery.c`, `certificate_tokens_refresh_flags()` | `FINAL_TRY` is normally set by the attempt that just failed |
| Once `FINAL_TRY` is set the window requires a second, explicit Unlock before the attempt is spent | `src/ui/pin.c`, `on_unlock()` | — |
| One window offers at most three attempts | `src/ui/pin.c`, `PIN_MAX_ATTEMPTS` | it is not a rate limit (see below); it is a bound on one prompt |
| Retries are user-initiated; nothing retries on its own | `src/ui/pin.c` | `tests/test-broker-device.c` checks the wrong PIN is reported as `PIN_INCORRECT` and not collapsed |
| PIN prompts are serialised process-wide, and two operations on one session share **one** prompt | `src/ui/pin.c`, the prompt queue; `src/broker/operations.c`, the waiter list | two concurrent `Sign` calls on a logged-out grant produce one window, not two |
| Login is **lazy**: at first private-key use, not at grant time | `src/broker/operations.c` | the UI smoke run shows the PIN window appearing at `Sign` |
| Every mechanism and parameter is re-validated against the mechanism **and the key** | `src/broker/mechanism.c` | `tests/test-mechanism.c`, including the RSA-PSS salt that does not fit |
| `data` is a digest of a stated length, never an arbitrary blob | `src/broker/mechanism.c` | `tests/test-mechanism.c` |
| **`Decrypt` is refused outright** | `src/broker/mechanism.c` | the only decryption mechanism on the interface is RSA PKCS#1 v1.5, which would be a padding oracle over the card's key; `tests/test-mechanism.c` and `tests/test-impl-dbus.c` |
| The token behind a grant is re-resolved by manufacturer, model, serial and label — never by slot | `src/tokens/discovery.c`, `certificate_tokens_open_session()` | a different card in the same slot is a different token |
| A token with no serial cannot back a grant, and that is said at `AcquireCredential` time | `src/certificate-impl.c`, `finish_acquire()` | it used to be discovered at the first `Sign`, after consent and a PIN |
| The backend enforces the grant lifetime itself and tears the card session down when it expires | `src/session-impl.c` | closed, expired and cancelled are re-checked before the device lock and again with it held |
| Token removal invalidates every grant on that token | `src/certificate-impl.c`, `on_token_event()` | — |
| The frontend leaving the bus closes every grant, and so does the name changing hands | `src/certificate-impl.c`, `on_frontend_vanished()`, `set_frontend_owner()` | — |
| Shutdown emits `SessionInvalidated(backend_shutdown)` and flushes before exit | `src/main.c` | — |
| Logging is structural: no format-string entry point, no PIN, no subject, no URI, no signature — and every external field is escaped and capped | `src/redact.h`, `src/redact.c` | `tests/test-redact.c` asserts `pin-value` never survives and that a newline in an app id cannot forge a journal line |
| Card serials are truncated in logs and **absent from `token_display`** | `src/redact.c`, `src/certificate-impl.c` | — |
| `TokenAdded`/`TokenRemoved` carry **presence only** — a per-process salted id and the protected-path flag | `src/certificate-impl.c`, `token_presence_for()` | the frontend re-emits these to every client on the bus; a PIV label is routinely the cardholder's name |
| Every PKCS#11 call runs off the main thread, `GetCapabilities` included | `src/broker/`, `src/tokens/discovery.c`, `src/certificate-impl.c` | `GetCapabilities` used to enumerate every slot from the method handler, under the lock a card enumeration holds for seconds |
| Every request is tied to one `GCancellable` that `Close()` cancels, and a cancelled operation answers 1 rather than 2 | `src/request-impl.c`, `src/certificate-impl.c` | `tests/test-cancellation.c` |
| Discovery does not log in | `src/tokens/discovery.c` | `tests/test-broker-device.c` |

### Not implemented

| | |
|---|---|
| The synthetic PKCS#11 facade | there is no method to reach it: `OpenPkcs11Endpoint` is on neither interface. `src/export/facade.h` holds the requirements |
| Rate limiting | neither side does it. The frontend is the right place; it is on that branch's open-items list. The three-attempt cap on one PIN window is a bound on one prompt, not a rate limit: nothing counts requests per caller or per hour |
| Chain building | `chain_status` is always `leaf_only`, honestly |
| A D-Bus policy denying this backend's name to everything but the portal's uid | recorded in [IMPL-INTERFACE.md](IMPL-INTERFACE.md) as a deployment option, not shipped |
| A wipeable GTK entry buffer | `GtkPasswordEntry` is backed by a `GtkPasswordEntryBuffer`, which GTK allocates from its secure-memory pool and zeroes when it frees it, and GTK places the text in non-pageable memory "if the underlying platform allows it". GTK guarantees nothing about the intermediate copies a text widget, an input method or a Pango layout may have made, so **this project does not claim the PIN existed in exactly one place** — only that its own copy is in one wiped, locked, non-dumpable page |
| `RSA_OAEP`, and therefore any decryption at all | the interface's mechanism vocabulary has no OAEP entry, so `Decrypt` is refused. Adding one — with a validated hash, MGF and label — is a frontend change |
| Any hardware assurance at all | **no real smart card has ever been read by this code.** [TESTING.md](TESTING.md) tier 3 is the run that would change that |

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
application it was. `app_id` and `app_identity_level` arrive at the backend as arguments to
`AcquireCredential`. A backend cannot derive an app id even by accident, because it is not talking
to the application.

**There is no `app_display_name` on the wire.** The branch interface carries an app id and a level
and nothing else about the caller, so a human-readable name is this backend's own to derive from
the app id — or to omit. It must never be taken from anything the application supplied.

Executable paths are not application identities. A same-UID process can execute another path,
manipulate launch context, or connect directly to the bus. `/proc/$pid/exe` is a hint.

xdg-desktop-portal's approach is no longer "the model to follow": it is the implementation, since
the frontend is xdg-desktop-portal. Sandboxed callers have identities supplied by their containment
framework; host applications are normally inferred through standardised cgroups; and a host
registry lets an unsandboxed peer associate itself with a desktop-file app ID while the
[documentation warns that mechanism is expected to change](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.host.portal.Registry.html).
`xdp_invocation_get_app_info()` is where it happens.

The frontend resolves identity into three honesty levels, forwards which one it got as
`app_identity_level`, and **this backend displays it**:

1. **Verified sandboxed** — Flatpak or Snap identity obtained through the containment framework's
   mediation. Treated as authenticated metadata. Displayed as the application, with its sandbox
   status.
2. **Derived host label** — a cgroup-derived desktop identity. A useful label, **not** a security
   principal. Displayed as the application, with an explicit warning that it is unverified.
3. **Unidentified** — nothing trustworthy. Displayed as "an unidentified application", with the
   strongest warning the design has.

Rules that follow:

- **Identity is derived once, in the frontend, at the start of the transaction** *(provided by
  xdg-desktop-portal)*, and travels as an argument from there. There is no second derivation
  anywhere, and no option, key or header by which a caller can supply one.
- **The backend must never trust a caller directly.** Its only legitimate caller is
  xdg-desktop-portal; it checks that the sender owns `org.freedesktop.portal.Desktop` and refuses
  everything else. See
  [IMPL-INTERFACE.md](IMPL-INTERFACE.md), "Why an application cannot call this" — including the part
  about what that check does *not* protect against.
- **Bind every grant to the initiating unique D-Bus connection** *(provided by
  xdg-desktop-portal)*.
- **Never use an unverified app ID as the sole key** for selection memory, policy, or anything else
  that persists *(provided by xdg-desktop-portal: it refuses to write the `certificate` permission
  table for an unidentified app)*.
- **Selection memory is unavailable to level 3** *(provided by xdg-desktop-portal)*, and the user's
  own "remember this" answer is required on top of the application's `allow_selection_memory` —
  this backend reports what the user said as `remember_selection` and stores nothing itself.
- **First use by an unidentified caller requires explicit confirmation**, and the dialog says the
  application could not be identified rather than inventing a name for it. *(Backend: this is the
  chooser, and it is this repository's obligation.)*
- **Rate-limit** background requests, repeated requests, and repeated failures, per caller and
  globally. **This is not implemented anywhere.** It is on the frontend branch's own open-items
  list, which means that for now the only place it could happen is this backend.
- **The trusted identity position in the window is never occupied by caller-supplied text** — not
  `reason`, not a title, not the token label, not the certificate subject. *(Backend.)* Note that
  `reason` is the **only** caller-supplied string on the interface: there is no `context` option.

This is no longer the shape the project is merely *built* in: the reach of level 1 —
xdg-desktop-portal's containment-framework integrations, its maintained host-identity story and its
documented Registry mechanism — is now inherited rather than reimplemented, because the frontend is
xdg-desktop-portal. The `app-info.h` that used to be in this repository is deleted, not moved.
Levels 2 and 3 do not disappear; they are honestly labelled there too.

## The trusted dialog

**This is the part of the security model this repository owns outright.** Drawn by the backend,
from facts the frontend established. The first two items in this list arrive as arguments; the
backend renders them and may not substitute anything for them. The chooser must show all of the
following, in backend-owned text:

- the application **id** the frontend established, and a name derived from it if this backend can
  derive one — there is no display name on the wire;
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
- the caller's `reason`, visibly separated and **labelled as application-provided text**. It is
  the only string on the interface the application controls.

For client authentication the destination host matters and this service cannot verify it: it sees a
D-Bus peer, not a TLS connection. **The interface no longer has anywhere to put it** — the
`context` option the earlier sketch specified is not on the branch's XML — so a caller that wants
to state a destination can only put it in `reason`, which is application-supplied text and is
labelled as such. Selection memory is keyed by the frontend on the app id and nothing the caller
supplied.

Accessibility is part of this, not adjacent to it: a security dialog a screen-reader user cannot
navigate is a security dialog that user cannot give informed consent through. The criteria are in
[PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md#accessibility-as-acceptance-criteria) and they are
acceptance criteria for this repository specifically: the frontend draws nothing, so nobody else can
satisfy them.

## PIN handling

- **The PIN is collected only in a backend-owned window** and exists only inside the backend
  process. It never crosses D-Bus in either direction — not on the public interface and **not on the
  impl interface either** — never enters a `GVariant`, a `GError` message, a URI, or a log line. The
  frontend cannot see a PIN: not as a rule it obeys, but because it has no window and no token
  session, and because neither interface has a field one could travel in.
- **No `pin-value` and no `pin-source` in any PKCS#11 URI this service emits**, ever. Any URI
  arriving from elsewhere carrying one is truncated before it can be logged.
- **The buffer is wiped on every exit path** — success, failure, cancel, timeout, window destroyed
  — allocated in locked, non-swappable memory where the platform allows, marked `MADV_DONTDUMP`,
  and **core dumps are disabled for the process**: `PR_SET_DUMPABLE(0)` and `RLIMIT_CORE 0` are set
  before anything else in `main()`. `PR_SET_DUMPABLE(0)` also makes `/proc/self/*` root-owned,
  which blocks a same-uid `ptrace` attach — a partial mitigation of an open problem below rather
  than a fix for it, since it does nothing about a tracer that attached first.
  - **What it costs, honestly.** A non-dumpable process cannot be attached to by `gdb` either, and
    xdg-desktop-portal's own settings portal cannot read `/proc/$pid/root` to identify this
    process, so GDK logs a warning and falls back to GSettings for the colour scheme.
    `--debug-allow-core` turns the hardening off for development and must never appear in an
    installed service file.
  - **What GTK's copy is.** The PIN is typed into a `GtkPasswordEntry`, which GTK backs with a
    `GtkPasswordEntryBuffer` allocated from its secure-memory pool and zeroed when freed, and which
    GTK places in non-pageable memory "if the underlying platform allows it". GTK promises nothing
    about intermediate copies made by the text widget, an input method or a Pango layout. **This
    project therefore does not claim the PIN exists in exactly one place.** What it claims is that
    the copy it owns is in one page that is locked, non-dumpable and wiped, that the entry is
    cleared the moment that copy is made, and that the worker gets a private copy nothing else can
    free under it.
  - **`mlock()` failing is not fatal**, and that is a policy rather than an oversight: the default
    `RLIMIT_MEMLOCK` is small, a desktop session may have spent it, and refusing to unlock a card
    because the kernel would not pin one page would be a denial of service with no security gain.
    It is warned about once per process, at message level, so the difference between "not written
    to swap" and "probably not written to swap" is in the journal rather than assumed.
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
  are **never invented**; the user is warned before the final known attempt, and the flags are
  **re-read from the token after every refusal**, because `CKF_USER_PIN_FINAL_TRY` is normally set
  by the attempt that just failed. Once it is set, the window requires a second, explicit Unlock
  before spending the attempt, and one window offers at most three attempts in total. Incorrect PIN, blocked
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
that the session belongs to the app id the call names, checks that the identity level has not
risen, checks the mechanism against an allow-list, validates the parameters against the mechanism
and the key, and applies the purpose's consent policy. **It does not count operations and there is
no rate limit** — see the checklist above, which says so in the same words.

Enforcement is split, and both halves are load-bearing. The **frontend** checks that the grant
exists, is live, is owned by this caller, permits this operation and permits this mechanism —
`check_grant()` in `desktop-portal/certificate.c`, run *before* the backend is called at all. The
**backend** checks the mechanism against the key, validates the parameters, applies the per-purpose
consent policy, and performs the operation on its own session. Neither check is redundant: the
frontend is the only side that knows which application is asking, and the backend is the only side
that knows what the card will accept. (Rate limiting is in neither yet; see above.)

**The PKCS#11 facade must enforce the same thing at a much harder interface**, which is why it is
experimental and why it is a separate milestone — and why the frontend branch does not have a
method that returns an endpoint at all. `OpenPkcs11Endpoint` is on neither interface. What follows
is therefore the acceptance criteria for a follow-up rather than a description of something
reachable. The minimum it must do:

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
would run in **its own process** — a child of this backend, since that is where the token session
is — holding no PIN and reaching the card only through the broker, and it is the first thing that
should be fuzzed. Its socket would be created by this backend and **relayed** by the frontend,
which checks the grant and the caller and then passes the descriptor through without holding a
copy. None of that exists on either side today.

**Hiding objects during enumeration is not scoping.** A caller that can use templates, cached
handles, object creation, key generation, wrapping or derivation does not need `C_FindObjects` to
reach the rest of the card. Every entry point is either refused or constrained; there is no
allow-by-default path.

## Card removal, and what happens to a grant

Removal invalidates everything: every session, any in-flight operation cancelled, and
`SessionInvalidated(session_handle, "token_removed")` emitted to the frontend, which turns it into
`GrantInvalidated` with reason `token_removed` and closes the Session. (Were there a facade, the
appropriate PKCS#11 device or token error would go to its client and the endpoint would be
**poisoned** so it cannot silently rebind to a card inserted later.) Reinsertion requires explicit reselection **even when the
label and slot number are identical**, because a label and a slot number prove nothing about which
card is in the reader. Tokens are identified by every stable attribute available — manufacturer,
model, serial, label — never by slot number alone.

## Grant lifetime and delegation

*(Frontend concern — provided by xdg-desktop-portal, recorded here because the delegation shape is
what a facade follow-up would have to satisfy.)*

Binding a grant to its owner's D-Bus connection alone is wrong in both directions: the process that
actually performs the cryptography may be a browser's **network subprocess** with its own connection
to the endpoint, so killing the grant when the owner's connection drops can kill a valid handshake,
while keeping it alive for the subprocess lets it be used after the request that authorised it
ended. Today's frontend implements the simple half — a grant is bound to the connection that
created it and has an expiry — and the delegation model below is what an endpoint would force. The
model:

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

Selection memory is keyed by the frontend on the verified app id, in a permission-store table
called `certificate`, with this backend's `certificate_id` as the value. It **preselects** and
never skips the trusted consent step or a PIN prompt; it is unavailable to unverified callers; it
is written only when the application passed `allow_selection_memory` *and* the user asked to
remember; and because it is in the real permission store it is listed and revocable in the
desktop's own UI rather than in a private store nobody can see. There is no "remember PIN" and
there never will be.

**The impl interface cannot express `allow_selection_memory` yet**, so this backend cannot know
whether the application asked. It used to offer the checkbox to every identified caller, which
meant a user could tick "remember this certificate" and have nothing stored, silently. Until the
frontend adds the key, the checkbox is offered **only when `preselect_certificate` was supplied** —
under-approximating rather than lying. [IMPL-INTERFACE.md](IMPL-INTERFACE.md) records the interface
change that fixes it.

## Logging

- **Two journals, one story.** xdg-desktop-portal records the decision and the caller; this backend
  records the card event. The grant id and the operation id are what join them, and neither journal
  alone answers "what used my card, and when".
- **Allowed**: counts, stable reason codes, purposes, resolved caller identity and its honesty
  level, grant and operation ids, mechanism names, token presence, timings, and — frontend only —
  which backend was selected.
- **Never**: PINs, PKCS#11 URIs, object labels, key ids, card serials, certificate subjects, signed
  data, plaintext, or the contents of `reason`.
- Error text from p11-kit, OpenSC and GnuTLS is **truncated before any embedded URI**, because those
  libraries put URIs in error strings and a URI may carry a `pin-value`.
- Redaction is **structural** — a logging helper that accepts only the fields it may emit — not a
  regex applied to strings on the way out. A filter that must recognise a secret has already been
  handed one.
- The default log level records decisions, not data: which caller, which purpose, which honesty
  level, granted or refused, and why.

## Open problems

Named because they are unsolved, not because they are minor.

- **Delegation across one hop — mostly closed, and the caveat is the interesting part.**
  `xdg-desktop-portal-webauth` asks on behalf of an RDP client, and this backend sees only its
  immediate peer. The fix both projects described as arriving "at acceptance" has arrived early:
  both portals are now in **one frontend process**, which derives the web-authentication caller's
  app id and can hand it to the certificate side in-process, with no attestation crossing a bus.
  What remains open is that the frontend does not actually do this yet, and — permanently — that
  the fix does not generalise: across two processes, passing an app id would be an unattested
  assertion of someone else's identity, which is the identity-laundering this document forbids. It
  is not to be done that way. See
  [0005](decisions/0005-first-consumer-is-the-web-auth-service.md) and
  [0010](decisions/0010-backend-only-frontend-lives-upstream.md).
- **Module loading for facade consumers**, and there is no facade to load. `OpenPkcs11Endpoint` is
  on neither interface, so every consumer that can only speak PKCS#11 is currently unserved. If the
  only workable shape turns out to be one permanently registered broker module, then a compromised
  consumer process shares an already-loaded module with every other consumer in that process, and
  grant binding must be enforced inside the module by caller identity rather than by socket. That is
  a different and harder security argument. [SPIKES.md](SPIKES.md) S3.
- **`purpose` is not enforceable.** Stated everywhere it appears; there is no fix, only honesty.
- **The impl boundary is not a privilege boundary.** Both processes run as the user. The split makes
  identity derivation and window drawing structurally separate, which is worth a great deal; it does
  not make this backend safe from a hostile process that can `ptrace` it — though
  `PR_SET_DUMPABLE(0)` now blocks the ordinary same-uid attach, which is a mitigation and not a
  boundary: it does nothing about a tracer that attached before the flag was set, about a
  `CAP_SYS_PTRACE` process, or about a kernel configured differently. A deployment that wants
  more can add a D-Bus policy rule on `org.freedesktop.impl.portal.desktop.certificate`; that is not
  in v1. [IMPL-INTERFACE.md](IMPL-INTERFACE.md) says so in the same words.
- **The peer check is a check-then-use.** The owner of `org.freedesktop.portal.Desktop` is resolved
  from the bus on every call rather than trusted from a watcher's cache, because `NameOwnerChanged`
  is not ordered against the messages of the process that lost the name. What remains is that the
  answer is a snapshot: the name can change hands between the check and the work the call
  authorises. Sessions belonging to a previous owner are invalidated as soon as this backend
  notices the change, and a deployment that wants more can deny this backend's name in D-Bus policy
  to everything but the portal's uid.
- **Hardened-desktop assumptions.** How much level-2 and level-3 identity is worth depends on
  `ptrace` scope, compositor input isolation and `/proc` hardening, none of which this service
  controls or can detect reliably.

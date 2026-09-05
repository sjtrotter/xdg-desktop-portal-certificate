# Security model

Status: EXPERIMENTAL. **Some of this is now implemented and some of it is still an intention**, and
the checklist below says which is which. Nothing here has been reviewed by anyone but its authors,
and only a narrow slice of it has been run against a real smart card: one PIV card in one reader,
on 2026-09-04, through [TESTING.md](TESTING.md) tiers 3.1–3.4.

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
| A sender is **never accepted** from a remembered answer: every accept decision asks the bus who owns `org.freedesktop.portal.Desktop` now. A *refusal* is decided from the cached owner, with no bus call at all | `src/certificate-impl.c`, `certificate_impl_sender_is_frontend()` | `NameOwnerChanged` is not ordered against the former owner's messages, so a cached "yes" admits a replaced frontend that is still connected. The asymmetry is deliberate in both directions: anything on the bus can send this backend a message, and a `GetNameOwner` round trip per stranger's message would be a main-thread stall an open PIN window feels. A stranger's unique name can never equal the cached owner's, so a stranger never reaches the bus call. The cost is one refused call at the moment a replacement portal takes the name over before this process has seen it. `tests/test-impl-dbus.c` reproduces the race rather than hoping for it |
| A session is bound to the `app_id` it was created for, and its identity level may fall but never rise | `src/certificate-impl.c`, `lookup_session()` | `tests/test-impl-dbus.c`: app B cannot use app A's session; `unidentified` cannot become `sandboxed` |
| A closed session leaves the table and its path can be used again | `src/certificate-impl.c`, `handle_create_session()` | `tests/test-impl-dbus.c`: create, close, create again |
| The Session skeleton stays on the bus after invalidation, so the frontend's answering `Close()` is answered | `src/session-impl.c` | `Close()` is idempotent; the frontend sends one in reply to every `SessionInvalidated` |
| Options are validated strictly: a present field of the wrong type, an unknown enum value or an unknown key in a security-relevant nested vardict is refused, and defaults apply only to absent fields. **Including the mechanism parameters** — `signature_encoding`, `mgf` and `mgf1_hash` used to be silently discarded when they were present with the wrong type | `src/certificate-impl.c`, `parse_acquire_options()`; `src/tokens/filter.c`; `src/broker/mechanism.c`, `lookup_string()` | `tests/test-impl-dbus.c` drives sixteen malformed option sets; `tests/test-mechanism.c` covers the parameters, per operation, including the `MGF1-<hash>` vocabulary the interface names and which nothing tested before |
| Export failures abort the call; an unexported session is never inserted | `src/certificate-impl.c`, `src/request-impl.c`, `src/session-impl.c` | a session the frontend cannot close, or a prompt it cannot cancel, is worse than a failed call |
| The app id and its identity level are **displayed, never derived** | `src/ui/chooser.c`, `build_identity()` | the private-bus run shows `identity=unidentified` and the window says so in words |
| Every externally sourced display string — app display name, app id, subject, issuer, token label, reader name, `reason` — is sanitised and capped, with a cap on combining-mark runs | `src/certificate.c`, `certificate_display_text()` | `tests/test-redact.c`; a desktop file's `Name=` is writable by any unsandboxed process and a card's label is chosen by whoever issued it |
| The purpose is rendered in this backend's own words | `src/certificate.c`, `certificate_purpose_display()` | — |
| Expired certificates are offered and marked **in words, not colour** | `src/tokens/filter.c`, `src/ui/chooser.c` | `tests/test-filter.c` |
| A single candidate still opens the chooser | `src/certificate-impl.c` | by construction: there is no code path that skips it |
| A second `AcquireCredential` on a live session **rebinds the device**: the old token session is logged out and closed, and the next operation asks for the PIN again and signs with the new certificate's key | `src/broker/device.c`, `certificate_device_open()` | the open device remembers the candidate it was opened for. It used to return early on "a module is loaded", so the application was handed certificate B and got a signature made by certificate A's key, with no prompt. `tests/test-broker-regrant.c` verifies the signature against certificate B; `tests/test-broker-device.c` checks the login and the key handle are both thrown away |
| The frontend leaving the bus **cancels every chooser and PIN window**, and the pending calls are answered `owner_gone` rather than "cancelled" | `src/certificate-impl.c`, `cancel_transactions()` | a trusted window outliving the process that asked for it is the single thing this repository exists to make impossible. `tests/test-impl-dbus.c` |
| The PIN never leaves the process, never enters a GVariant, a GError or a log line | `src/ui/pin.c` | there is no entry point that returns a PIN; the caller passes a login function |
| **Which process draws the PIN field is a choice, and it is recorded**: `gtk` (this backend's window) or `system` (the desktop shell's prompter, over `GcrSystemPrompt`). `--pin-prompt=auto|gtk|system`; auto picks `system` when `org.gnome.keyring.SystemPrompter` has an owner or is activatable | `src/ui/pin.c`, `pin_impl()`; `src/ui/pin-gtk.c`; `src/ui/pin-system.c` | every rule in this section holds for both, and the journal says which was used (`pin-prompt-selected detail=...`). `tests/test-pin-system.c` drives the system path end to end against gcr's own prompter on a private bus; `tools/ui-smoke.sh --pin-prompt=system` runs the whole stack through it |
| The system prompter is **never chosen by default by anything but `main()`** | `src/ui/pin.c`, `pin_prompt_kind` | the module default is `gtk`. Linking this code must not be enough to start putting prompts on a session's shell because a name happened to be on the bus, and a test that reached the operator's own prompter would be a test that spends a PIN attempt |
| No prompt this backend opens ever offers "remember" | `src/ui/pin-gtk.c` (no such control); `src/ui/pin-system.c`, `gcr_prompt_set_choice_label(NULL)` [[S56](SOURCES.md)] | `tests/test-pin-system.c` asserts the choice label reaching the prompter is empty and that `password-new` is false |
| A **login timeout**: a `C_Login` that has not returned after `--login-timeout` seconds (60 by default, 0 disables) takes the prompt down, fails the interaction with its own reason, and abandons the login if it lands afterwards | `src/ui/pin.c`, `on_login_timeout()`; `src/broker/operations.c`, `CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT` | `tests/test-pin-system.c` `/pin-system/login-timeout`. **The residual is stated below**: the module call itself cannot be interrupted, so the caller is still answered only when it returns |
| The PIN buffer is page-aligned, `mlock()`ed where the rlimit allows, `MADV_DONTDUMP`ed, and `explicit_bzero()`ed on every exit path | `src/ui/pin.c`, `PinBuffer` | wiped before the callback runs, on success, failure, cancel and window destroy; an `mlock()` failure is warned about once and does not refuse the login |
| The login worker gets a **private copy** of the PIN that it owns and wipes itself | `src/ui/pin.c`, `pin_buffer_dup()` | `tests/test-cancellation.c` asserts the worker still sees the whole PIN after the window was cancelled |
| Cancelling while `C_Login` is in flight hides the window, defers the answer, and frees nothing until the worker returns | `src/ui/pin.c`, `pin_prompt_finish()` | `tests/test-cancellation.c`, under ASan |
| A cancelled login that **succeeded anyway** logs the token out again | `src/ui/pin.c`, the abandon callback; `src/broker/operations.c`, `do_abandon()` | the card is slower than the Escape key, and PKCS#11 cannot withdraw a submitted `C_Login`. Leaving it would turn a cancelled request into an unprompted signing capability for the rest of the grant. `tests/test-cancellation.c` asserts it happens on a cancel and does **not** happen on a normal unlock |
| Core dumps are disabled and `ptrace` attach is blocked for this process | `src/main.c`, `harden()` | `PR_SET_DUMPABLE(0)` plus `RLIMIT_CORE 0`, before anything can fault. `--debug-allow-core` turns it off for development and is never in an installed service file |
| The bus name is only offered for replacement under `--allow-replacement`, which the installed `.service` file does not pass | `src/main.c`, `data/org.freedesktop.impl.portal.desktop.certificate.service.in` | otherwise any process running as the user could take the name and draw the PIN window. `--replace` (ask to replace) and `--allow-replacement` (permit being replaced) are separate flags because D-Bus lets the current owner authenticate neither: an upgrade is a restart, not a `--replace`. See [IMPL-INTERFACE.md](IMPL-INTERFACE.md) and [TESTING.md](TESTING.md) §3.5 |
| Nothing persists a PIN | — | there is no option, no keyring call and no configuration key |
| Protected authentication path draws **no PIN field** and logs in with a NULL PIN | `src/ui/pin-gtk.c`, `src/ui/pin-system.c` | in the shell's prompter that is a message and a Cancel and no password round at all. `tests/test-pin-system.c` asserts zero password rounds and a NULL PIN |
| An **empty PIN is never submitted** by either implementation: the prompt is asked again with a warning and no attempt is spent | `src/ui/pin.c`, `certificate_pin_prompt_hold()` | a stray Return in the shell's field used to reach `C_Login`, and a token that counts a zero-length PIN as a failure would have spent a try on it. `tests/test-pin-system.c` `/pin-system/empty-answer-never-reaches-the-card` asserts one login for two rounds |
| Retry state is shown only from `CKF_USER_PIN_COUNT_LOW` / `FINAL_TRY` / `LOCKED`, never as an invented number, and is **re-read after every refusal** | `src/ui/pin.c`, `certificate_pin_prompt_retry_hint()`; `src/tokens/discovery.c`, `certificate_tokens_refresh_flags()` | `FINAL_TRY` is normally set by the attempt that just failed. `tests/test-pin-system.c` asserts the wording reaches the prompter and carries no number |
| Once `FINAL_TRY` is set the prompt requires a second, explicit confirmation before the attempt is spent — **including on a protected authentication path**, where the reader collects the digits but the try that locks the card is spent all the same | `src/ui/pin.c`, `certificate_pin_prompt_needs_final_confirm()`; `src/ui/pin-gtk.c`, the "Use the last attempt" button; `src/ui/pin-system.c`, `handle_prompt_opened()` | a second Unlock in the window; a confirmation round on the same open system prompt. The protected path used to submit the NULL-PIN login the moment the notice appeared, which made this row untrue for exactly the tokens whose counter cannot be seen. `tests/test-pin-system.c` asserts that refusing it leaves the card **unasked**, on both paths |
| A prompt the **desktop shell takes away** ends the interaction, even with no round outstanding — a Cancel pressed after the PIN went to the card answers `cancelled`, and the login that succeeds anyway is abandoned | `src/ui/pin-system.c`, `on_gcr_prompt_close()` | after submission there is no gcr round left to answer, so the shell's Cancel was invisible here and the grant would sign for a request the user had just refused. `tests/test-pin-system.c` `/pin-system/shell-cancel-after-the-pin-was-submitted` |
| **The two ways a mediated card gets bricked, answered.** There is no `C_InitToken`, `C_InitPIN` or `C_SetPIN` surface to reach: card administration is not a permission this interface can grant, because it is not a feature it has. And a PIN attempt is spent only by a person choosing to spend it — nothing here retries, nothing here logs in without a prompt, and on `CKF_USER_PIN_FINAL_TRY` the prompt demands a second explicit confirmation before the attempt goes to the card, on a protected authentication path too | the whole of `src/broker/`, which exports `Sign` and `Decrypt` and nothing else; `src/ui/pin.c`, `certificate_pin_prompt_needs_final_confirm()` | these are the two attacks named in [xdg-desktop-portal#662](https://github.com/flatpak/xdg-desktop-portal/issues/662) (Daiki Ueno, 2023-06-23) as the reason a smart-card portal needs a permission model at all: "a malicious application could brick smartcards by calling destructive functions like `C_InitToken` or by repeatedly providing incorrect PIN". A forwarded token can only gate the first behind a flag; here neither is expressible. The residual is honest and stated below: a **host** application with its own PKCS#11 access can still do both, and no portal can stop it |
| A **prompter that disappears** settles the interaction rather than leaving it open, at every stage | `src/ui/pin-system.c`, the error branches of the open, password and confirm callbacks | gcr raises `G_IO_ERROR_CANCELLED` from inside itself when the prompter's bus name vanishes. Swallowing it left the caller unanswered and the process's single prompt slot occupied for good. Three tests in `tests/test-pin-system.c`: vanish during open, during password, during confirm |
| One prompt offers at most three attempts | `src/ui/pin.c`, `PIN_MAX_ATTEMPTS` | it is not a rate limit (see below); it is a bound on one prompt. `tests/test-pin-system.c` `/pin-system/attempt-cap` |
| Retries are user-initiated; nothing retries on its own | `src/ui/pin.c` | `tests/test-broker-device.c` checks the wrong PIN is reported as `PIN_INCORRECT` and not collapsed |
| PIN prompts are serialised process-wide, and two operations on one session share **one** prompt | `src/ui/pin.c`, the prompt queue; `src/broker/operations.c`, the waiter list | two concurrent `Sign` calls on a logged-out grant produce one window, not two |
| The shared prompt belongs to the **session**, not to the operation that opened it: cancelling one caller answers that caller and leaves the window up for the others, and the window closes when the last live waiter goes | `src/broker/operations.c`, `waiter_cancelled_idle()`; `src/session-impl.h`, `login_cancellable` | closing the first request used to close the shared window and tell every caller behind it that the *user* had cancelled. `tests/test-cancellation.c` |
| Login is **lazy**: at first private-key use, not at grant time | `src/broker/operations.c` | the UI smoke run shows the PIN window appearing at `Sign` |
| Every mechanism and parameter is re-validated against the mechanism **and the key** | `src/broker/mechanism.c` | `tests/test-mechanism.c`, including the RSA-PSS salt that does not fit |
| `data` is a digest of a stated length, never an arbitrary blob | `src/broker/mechanism.c` | `tests/test-mechanism.c` |
| **`Decrypt` is `RSA_OAEP` only**; PKCS#1 v1.5 decryption is refused by name | `src/broker/mechanism.c` | a v1.5 decryption whose outcome the caller can observe is a Bleichenbacher oracle over the card's key [[S49](SOURCES.md), [S50](SOURCES.md)]. `tests/test-mechanism.c`, `tests/test-broker-device.c` (an openssl-encrypted ciphertext, round tripped through the token) and `tests/test-impl-dbus.c` |
| Every `Decrypt` failure is reported as **one indistinguishable error**; the real reason goes to the journal | `src/broker/operations.c` | `tests/test-broker-decrypt.c` drives two different internal causes and asserts the caller sees the same domain, code and words. It equalises the answer, not the timing |
| A grant buys **32 decryptions**, charged per attempt, checked and incremented **under the device lock** | `src/broker/operations.c`, `CERTIFICATE_MAX_DECRYPTS_PER_GRANT` | `tests/test-broker-decrypt.c`. Nothing else on either side counts them, and every practical attack on RSA decryption needs orders of magnitude more; re-consenting is what buys more. The unlocked check before the mechanism is parsed is a fast refusal, not the one that decides: read-then-increment without the lock is a budget two callers can both spend the last unit of |
| An OAEP ciphertext must be **exactly one modulus** long, and the label at most 256 bytes | `src/broker/mechanism.c` | `tests/test-mechanism.c`, `tests/test-broker-device.c`. The frontend cannot check the length: it does not know the modulus |
| The token behind a grant is re-resolved by manufacturer, model, serial and label — never by slot | `src/tokens/discovery.c`, `certificate_tokens_open_session()` | a different card in the same slot is a different token |
| A token with no serial cannot back a grant, and that is said at `AcquireCredential` time | `src/certificate-impl.c`, `finish_acquire()` | it used to be discovered at the first `Sign`, after consent and a PIN |
| The backend enforces the grant lifetime itself and tears the card session down when it expires | `src/session-impl.c` | closed, expired and cancelled are re-checked before the device lock and again with it held |
| Token removal invalidates every grant on that token | `src/certificate-impl.c`, `on_token_event()` | — |
| The frontend leaving the bus closes every grant, and so does the name changing hands | `src/certificate-impl.c`, `on_frontend_vanished()`, `set_frontend_owner()` | — |
| Shutdown emits `SessionInvalidated(service_shutdown)` and flushes before exit, and the name changing hands emits `owner_gone` for the previous owner's grants | `src/main.c`, `src/certificate-impl.c` | `tests/test-impl-dbus.c` asserts the shutdown reason; the reason is checked against the interface's eight in `src/session-impl.c` and anything else is a `g_critical()` sent as `error` |
| Logging is structural: no format-string entry point, no PIN, no subject, no URI, no signature — and every external field is escaped and capped | `src/redact.h`, `src/redact.c` | `tests/test-redact.c` asserts `pin-value` never survives and that a newline in an app id cannot forge a journal line |
| Card serials are truncated in logs and **absent from `token_display`** | `src/redact.c`, `src/certificate-impl.c` | — |
| Every PKCS#11 call runs off the main thread, `GetCapabilities` and the closing `C_Logout`/`C_CloseSession` included — **with one deliberate exception, at shutdown** | `src/broker/`, `src/tokens/discovery.c`, `src/certificate-impl.c`, `src/session-impl.c` | `GetCapabilities` used to enumerate every slot from the method handler, and `Close()`, expiry, token removal and frontend loss used to close the card from the main thread — under a lock a worker holds for the whole of a `C_Login`, so the PIN window stopped redrawing while it happened. Both now run on workers (`certificate_impl_session_release_device_async()`). The exception is `certificate_impl_shutdown()`, which waits **up to two seconds** for those workers so that `C_Logout` is issued before the process exits; when the wait runs out it says so in the journal and exits anyway. Session finalize also closes synchronously, and cannot race a worker: the asynchronous close holds a reference for its whole life, so by then there is nothing left to close |
| Every request is tied to one `GCancellable` that `Close()` cancels, and a cancelled operation answers 1 rather than 2 | `src/request-impl.c`, `src/certificate-impl.c` | `tests/test-cancellation.c` |
| Discovery does not log in | `src/tokens/discovery.c` | `tests/test-broker-device.c` |
| **Only hardware tokens are offered by default.** A token whose slot does not set `CKF_HW_SLOT` [[S11](SOURCES.md)] is skipped unless `--allow-software-tokens` is given or the module was named with `--module` | `src/tokens/discovery.c`, `token_skip_reason()` | p11-kit on an ordinary desktop presents software key stores as tokens, and a window headed "security token" offering keys from the user's home directory says something untrue about where the key is. `--list-tokens` prints the skipped tokens and the reason. **Not a security boundary**: the flag is a claim by a module already loaded into this process |
| The chooser and the PIN window follow the session's light/dark setting | `src/main.c`, `follow_colour_scheme()` | read from GSettings rather than from the settings portal, because `PR_SET_DUMPABLE(0)` makes the portal unable to identify this process. Measured, both ways; the decision is recorded under **PIN handling** below |
| The reference counts on the objects a worker thread can outlive are atomic | `src/ui/pin.c`, `src/ui/chooser.c`, `src/broker/operations.c` | `g_atomic_int_inc` / `g_atomic_int_dec_and_test`. They were plain `int`s defended by a comment about which callbacks happen to be on the main thread today |
| The scratch directories `tools/` writes into and `rm -rf`s must be under `$TMPDIR` **and** carry this project's marker file | `tools/lib.sh`, `fixture_check()` | the previous check was ownership only, which a mistyped `SOFTHSM_DIR` pointing at `$HOME` passes. A directory that exists without the marker is refused, not emptied |

### Not implemented

| | |
|---|---|
| The synthetic PKCS#11 facade | not being built. There is no method to reach it — `OpenPkcs11Endpoint` is on neither interface — and the consumers it was for are served by the **client-side module** instead: [0011](decisions/0011-client-side-pkcs11-module.md), and "The client-side PKCS#11 module" below. The facade's requirements survive under "Grant scoping" in case an fd-returning method is ever added |
| Two concurrent grants in one application | the client-side module presents one credential per process. [0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) failure mode 8, deferred rather than solved, because no consumer has asked |
| Rate limiting | neither side does it. The frontend is the right place; it is on that branch's open-items list. The three-attempt cap on one PIN window is a bound on one prompt, not a rate limit: nothing counts requests per caller or per hour |
| Chain building | `chain_status` is always `leaf_only`, honestly |
| A D-Bus policy denying this backend's name to everything but the portal's uid | recorded in [IMPL-INTERFACE.md](IMPL-INTERFACE.md) as a deployment option, not shipped |
| A wipeable GTK entry buffer | `GtkPasswordEntry` is backed by a `GtkPasswordEntryBuffer`, which GTK allocates from its secure-memory pool and zeroes when it frees it, and GTK places the text in non-pageable memory "if the underlying platform allows it". GTK guarantees nothing about the intermediate copies a text widget, an input method or a Pango layout may have made, so **this project does not claim the PIN existed in exactly one place** — only that its own copy is in one wiped, locked, non-dumpable page. `--pin-prompt=system` moves that entry out of this process entirely, and moves the same question to the shell |
| Any claim that `--pin-prompt=system` keeps the PIN out of this process | it does not, and the section below says so: `C_Login` takes a PIN. What it moves is where the PIN is **typed** |
| Interrupting a `C_Login` | PKCS#11 has no way to. `--login-timeout` gives up on the interaction; the module call runs to completion and the attempt is spent |
| Decryption with anything but `RSA_OAEP` | and it never will be. PKCS#1 v1.5 decryption is a padding oracle over the card's key, and the interface refuses it on both sides |
| Any hardware assurance beyond a single card | **one PIV card, in one reader, once**: [TESTING.md](TESTING.md) tiers 3.1–3.4 passed on 2026-09-04 — discovery and certificate parsing, the private-bus happy path, a cancel, and the live run through the shell's own prompter. One card, one reader, one middleware, one desktop. The rest of tier 3 is unrun: one PIN per grant, the wrong-PIN and `FINAL_TRY` run, removal during an operation, a PIN-pad reader, a second card |

## What this is a boundary against, and what it is not

Stated plainly, because the temptation to overclaim here is enormous:

- **For sandboxed applications this can be a strong boundary.** A Flatpak or Snap has an identity a
  containment framework can vouch for, cannot reach `pcscd` without a permission it need no longer
  hold, cannot read the service's memory, and cannot see the PIN. Replacing `--socket=pcsc`
  [[S43](SOURCES.md)] with a
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
documentation warns that the mechanism "is expected to eventually be deprecated and may be
removed" — a disclaimer on the
[API reference](https://flatpak.github.io/xdg-desktop-portal/docs/api-reference.html) rather than
on the [Registry interface page](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.host.portal.Registry.html)
itself [[S40](SOURCES.md)].
`xdp_invocation_get_app_info()` is where it happens [[S37](SOURCES.md)].

The frontend resolves identity into three honesty levels, forwards which one it got as
`app_identity_level`, and **this backend displays it**:

1. **`sandboxed`** — Flatpak or Snap identity obtained through the containment framework's
   mediation. Treated as authenticated metadata. Displayed as the application, with its sandbox
   status.
2. **`host`** — a cgroup-derived desktop identity for a host process. A useful label, **not** a
   security principal. Displayed as the application, with an explicit warning that it is
   unverified.
3. **`unidentified`** — nothing trustworthy. Displayed as "an unidentified application", with the
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
  own "remember this" answer would be required on top of the application asking for it —
  this backend is told the effective value in the `AcquireCredential` options, offers the checkbox
  only when it is true, reports what the user said as `remember_selection`, and stores nothing
  itself.
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

- **The PIN is collected only in a prompt this backend controls, and it exists only inside the
  backend process.** It never crosses the portal interfaces in either direction — not the public one
  and **not the impl one either** — never enters a `GVariant`, a `GError` message, a URI, or a log
  line. The frontend cannot see a PIN: not as a rule it obeys, but because it has no window and no
  token session, and because neither interface has a field one could travel in.

### Where the field is drawn, and what that moves

There are two implementations of the prompt and `--pin-prompt` chooses between them. `auto`, the
default, means the system prompter when `org.gnome.keyring.SystemPrompter` has an owner on the
session bus or is activatable, and the in-process window otherwise. The journal records which was
used, once, as `pin-prompt-selected detail=gtk|system`.

| | `gtk` | `system` |
|---|---|---|
| Who draws the field | this backend | the desktop shell (gnome-shell), over `GcrSystemPrompt` [[S55](SOURCES.md)] |
| Where the typed characters first land | a `GtkPasswordEntry` in this process | the shell's own entry, in the shell |
| How the PIN reaches `C_Login` | already here | gcr's secret exchange — an ephemeral Diffie–Hellman over D-Bus, so the plaintext is not in a bus message — into gcr's secure memory, then copied into the same locked page |
| Parented to the requesting application's window | yes, through `xdg_foreign` or an X11 XID | **no**, in practice: `GcrPrompt:caller-window` is sent with the portal's scheme stripped, and gnome-shell's prompter ignores it and draws a session-modal dialog of its own |
| Needs a display in *this* process | yes | no |

**What moves out of this process with `system`**: the entry widget and its buffer, the input method,
and every intermediate copy a text widget or a Pango layout might make. That is the honest gain, and
it is a real one — the thing users have been taught to recognise as a password request on GNOME is
the shell's dialog, and a window a backend draws itself can be covered or imitated by another
client. This project no longer has to reason about GTK's secure-memory pool at all on that path.

**What does not move**: *we still hold a copy.* `C_Login` takes a PIN, so the PIN has to arrive
here. It lands in gcr's secure memory, is copied into the same page-aligned, `mlock()`ed,
`MADV_DONTDUMP`ed, `explicit_bzero()`ed buffer the GTK path uses, and the login worker still gets a
private copy of its own. gcr's copy belongs to the `GcrPrompt` and goes when that object is closed
and released, which is why letting go of it is part of the PIN's exit path in
`src/ui/pin-system.c` rather than bookkeeping — and why the object is released when the prompt is
merely *hidden* too, which is what a cancel or a login timeout arriving while `C_Login` is in
flight does. The worker has had its own private page since submission and needs nothing from this
file, so gcr's copy has no reason to outlive the dialog, and "until the module returns" can mean
for ever. **`system` is not "the PIN never enters this process"; it is "the PIN is not typed into
this process".**

Everything else is identical, because everything else is in `src/ui/pin.c` and neither
implementation can reach it: the attempt cap, the `FINAL_TRY` second confirmation, the flag re-read,
the serialisation queue, the deferred cancel, the login timeout, and the abandon path. An
implementation collects characters and draws warnings; it never decides whether an attempt is spent.

**Nothing about `system` is offered where it cannot be delivered.** If the prompter cannot be
reached the interaction fails with `no_display` and says so in the journal — there is no silent
fallback to the in-process window, because which process asked for the PIN is a fact about the
interaction and must not depend on timing.

**One gcr defect is worked around here and is worth knowing about — and it is not a reported
one.** Nothing in gcr's issue tracker, merge requests or NEWS describes it [[S57](SOURCES.md)];
what follows is a reading of gcr 4.4's source, plus a test here that crashed without the
workaround. gcr 4.4 completes a prompt round *twice*, and closing the prompt is not enough to
avoid it. `perform_close()` — which
`gcr_prompt_close()`, a `PromptDone` from the prompter, and the prompter's bus name vanishing all
reach — takes the round's pending result and completes it from an idle; if the `PerformPrompt`
method call is still on the wire and then comes back an error,
`on_perform_prompt_complete()` completes *the same result again*. `on_call_timeout()` on the open
path does both, in that order, by construction. The first completion drops the reference the round
held, which can be the last one, so the second ran on freed memory.

Two things answer it. Nothing in `src/ui/pin-system.c` passes a `GCancellable` to gcr, which
removes one trigger. And every gcr callback in that file **claims its result before it touches
anything else**: a flag set on the `GAsyncResult` object, which gcr keeps a reference to across
both completions and which is therefore the one thing certainly alive in the second — a flag in
this backend's own state would be the use-after-free it is meant to prevent. The ignored second
completion logs `pin-prompt-round-completed-twice`. Both halves were found by
`tests/test-pin-system.c` crashing, which is the argument for the test existing;
`/pin-system/close-racing-a-transport-error` drives a prompter that leaves `PerformPrompt`
unanswered and then fails it, and asserts the log line.
- **No `pin-value` and no `pin-source` in any PKCS#11 URI this service emits**, ever. Any URI
  arriving from elsewhere carrying one is truncated before it can be logged.
- **The buffer is wiped on every exit path** — success, failure, cancel, timeout, window destroyed
  — allocated in locked, non-swappable memory where the platform allows, marked `MADV_DONTDUMP`,
  and **core dumps are disabled for the process**: `PR_SET_DUMPABLE(0)` and `RLIMIT_CORE 0` are set
  before anything else in `main()`. `PR_SET_DUMPABLE(0)` also makes `/proc/self/*` root-owned,
  which blocks a same-uid `ptrace` attach — a partial mitigation of an open problem below rather
  than a fix for it, since it does nothing about a tracer that attached first.
  - **What it costs, honestly, and what was done about it.** A non-dumpable process cannot be
    attached to by `gdb` either, and xdg-desktop-portal's own settings portal cannot read
    `/proc/$pid/root` to identify this process, so GDK logs
    `Failed to read portal settings: ... Unable to open /proc/<pid>/root`.
    `--debug-allow-core` turns the hardening off for development and must never appear in an
    installed service file.

    **That warning was not cosmetic.** libadwaita takes the colour scheme from the settings portal,
    and the fallbacks did not recover it: measured on Fedora 44 with the session set to
    `prefer-dark`, this backend came up **light** with the hardening on and **dark** with
    `--debug-allow-core`. The chooser and the PIN prompt were the wrong colour on a dark desktop,
    for this reason.

    **The decision, recorded because both options were real.** Dropping `PR_SET_DUMPABLE(0)` and
    relying on `RLIMIT_CORE 0`, `MADV_DONTDUMP` and Yama's `ptrace_scope` would trade a same-uid
    `ptrace` defence for a theme — and `ptrace_scope` is not guaranteed to be set, while the thing a
    tracer would read is the page a PIN is in. So the hardening stays and the backend reads the
    setting itself: `org.gnome.desktop.interface color-scheme` through GSettings, which talks to
    dconf over D-Bus and looks nobody up by pid, fed to `adw_style_manager_set_color_scheme()` and
    followed for changes (`src/main.c`, `follow_colour_scheme()`). Where the schema is absent —
    this is not a GNOME-only backend — libadwaita's own answer stands. `ADW_DEBUG_COLOR_SCHEME`
    still wins, so that `tools/ui-smoke.sh` can check a dark scheme actually reaches the windows.
    `--verbose` logs the outcome as `colour-scheme detail=dark` / `colour-scheme detail=light`
    (its own event name; it used to be filed under `request-received`, where nobody could find it).
  - **What GTK's copy is** (the `gtk` prompt only; with `system` the entry is the shell's). The PIN is typed into a `GtkPasswordEntry`, which GTK backs with a
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
- **Protected authentication path**: when the token sets `CKF_PROTECTED_AUTHENTICATION_PATH`
  [[S12](SOURCES.md)], the
  login is made with a null PIN and the token or reader collects the secret. The service shows an
  instructional dialog **with no editable PIN field** and never receives the PIN. Emulating a PIN
  field for such a token would be a lie about where the secret goes. **The `FINAL_TRY`
  confirmation is not waived here**: the digits are typed on a pin pad, but the attempt that locks
  the card is spent by this process either way, so the null-PIN login waits for an explicit "Use
  the last attempt" — a button in the window, a confirmation round on the shell's prompt.
- **Retry handling.** Remaining attempts are displayed only when the token reports them reliably and
  are **never invented**; the user is warned before the final known attempt, and the flags are
  **re-read from the token after every refusal**, because `CKF_USER_PIN_FINAL_TRY` is normally set
  by the attempt that just failed. PKCS#11 defines the flag but says nothing about when a token
  updates it, and lets a token leave it false always [[S13](SOURCES.md)], so the re-read is an
  operational rule rather than something the specification promises. Once it is set, the prompt
  requires a second, explicit
  confirmation before spending the attempt — unconditionally, protected authentication paths
  included — and one prompt offers at most three attempts in total. An **empty** answer is not an
  attempt at all: it is refused before any submission, in `src/ui/pin.c` so that both
  implementations obey the same rule, and the prompt is asked again. Incorrect PIN, blocked
  PIN, cancelled prompt, device error and removal are always distinguished. Retries are
  user-initiated only; the service never retries automatically, and never after an ambiguous
  transport failure. Prompts for the same token are serialised so two grants cannot race two windows
  at the user.
- **Headless: never read a PIN from stdin.** With no display, or with `interaction_mode: forbidden`,
  the call returns `no_display` or `interaction_required`. A trusted agent protocol for headless use
  would be a separate, separately configured and separately reviewed mechanism.
- **A login that never returns is given up on, and the residual is stated.** A `C_Login` that has
  not come back after `--login-timeout` seconds (60 by default; `0` disables it) takes the prompt
  down at a known moment, logs `pin-timeout`, and fails the interaction with a reason of its own —
  `CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT`, not a generic failure. **What it does not do is
  interrupt the module**, because PKCS#11 offers no way to withdraw a submitted `C_Login`: the
  attempt is spent whatever happens, and *the caller is still answered only when the module
  returns*. Answering earlier would mean freeing, on the main thread, an interaction a worker thread
  is still reading through — which is the exact use-after-free the deferred-cancel machinery exists
  to prevent. What the timeout buys is that the prompt does not sit there with a spinner in it
  forever, that the failure is distinguishable in the journal, and that a login which lands
  afterwards is **abandoned** — the token is logged out again on a worker — rather than being handed
  to whoever was still waiting.
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

**The facade below is not being built** — see
[0011](decisions/0011-client-side-pkcs11-module.md) and the next section. What follows is kept
because it is the acceptance criteria for any future fd-returning method, and because deleting it
would mean rediscovering it. It is *not* the requirements list for the client-side module, which
is on the other side of the boundary and defends nothing. The minimum a served facade must do:

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

## The client-side PKCS#11 module

**What runs in the application's process.** `libpkcs11-portal-certificate.so`
([`../src/module/`](../src/module/)), loaded by p11-kit into any consumer that speaks PKCS#11 and
not D-Bus. It holds: a `GDBusConnection` to the session bus, a worker thread running its own
`GMainContext`, the session handle of at most one grant, and the DER of the certificate the user
chose. It does **not** hold a private key, a PIN, a PKCS#11 session on a real token, or any handle
to a card. There is nothing in its address space that was not either sent by the portal or already
public.

**It grants no capability the D-Bus interface does not.** A compromised application holding this
module can call `Sign` — as itself, under a grant the user consented to, for as long as the grant
lives. It could already do exactly that by calling
`org.freedesktop.portal.experimental.Certificate` directly, which needs no module and no
configuration. Every refusal the module makes is made again by the portal on the other side of the
bus. **It is not a trust boundary for the portal's assets**, and hardening aimed at those belongs
in `desktop-portal/certificate.c` and `src/broker/`.

**That is a statement about the portal's assets, not the consumer's, and the difference is the
whole threat model.** A previously uncompromised application that loads this module acquires a DER
parser, an attribute protocol, a D-Bus client and a worker thread inside its own address space,
beside its own secrets and its own authority. Four things follow.

**1. The portal's reply is hostile input, and "trusted" does not mean "well formed."**
`certificate_der`, `chain_der`, `key_type`, `key_curve` and `supported_mechanisms` cross D-Bus from
the frontend and are parsed here, in the consumer, by `src/module/objects.c` and
`src/module/der.c`. The bus authenticates the frontend and the frontend is a trusted service; the
bytes are another matter. The DER came off a card, through this backend, through the frontend, and
none of the three promises it parses. **This code parses defensively regardless of who sent it**,
because the alternative is that a malformed certificate on a card — or a bug in any service on that
path — becomes memory corruption in a browser.

**2. Certificate operations are reachable from the network.** A TLS server decides when to ask for
a client certificate, which issuers it will accept, and the mechanism and parameters of the
`CertificateVerify`. Those choices arrive at `src/module/mechanism.c` and
`portal_digestinfo_parse()` through GnuTLS or NSS with no user in between, several times per
handshake, and a remote peer can retry. Hostile input here is not a hypothetical adversary with
D-Bus access; it is the ordinary operation of the feature.

**3. What an attacker who controlled the portal's reply could reach.** Not the card and not the
PIN: neither is on this side, and there is nothing in the module's address space that was not
either sent by the portal or already public. What is in reach is **the consumer's process** — a
length confusion in the SubjectPublicKeyInfo split, a read past the end of a `GBytes`, a bad size
in the `C_GetAttributeValue` protocol. The asset at risk belongs to the browser or the mail client,
not to this project, which is exactly why it has to be written down here.

**4. Lifecycle in somebody else's process.** `C_Initialize` may be called after `fork()`,
`C_Finalize` may be called while another thread is inside a call, and the library may be
`dlclose()`d. The module **claims no fork safety**, and the claim is honest rather than a defence:
a consumer that forks after initialising gets a worker thread that does not exist in the child,
which is a hang rather than a compromise, but it is this module's defect and the portal boundary
does not absorb it. Unload and re-initialise are covered by `test-module`; fork is not.

**What answers this, and what does not.** `tests/fuzz-der.c` drives the TLV reader, the DigestInfo
parser, `portal_objects_new()` on arbitrary certificate DER, and the attribute protocol with
hostile templates — as a libFuzzer target where clang is available, and always as a corpus replay
binary `meson test` runs under ASan and UBSan. Opt-in loading (below) keeps the code out of
processes that never asked for it. What does **not** answer it is the argument at the top of this
section: "the application could already call the portal itself" is about the portal's assets and
says nothing about the consumer's.

**What it still refuses, and why.** Not to defend a boundary, but so that a consumer cannot be
misled about what this token is:

- every write to a token — `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_CreateObject`,
  `C_DestroyObject`, `C_SetAttributeValue`, all key generation, all wrap/unwrap, all derivation,
  RNG — answers `CKR_FUNCTION_NOT_SUPPORTED`. A service that mediates *use* must not appear to
  offer *administration*;
- `CKF_RW_SESSION` is refused with `CKR_TOKEN_WRITE_PROTECTED`; SO login with
  `CKR_USER_TYPE_INVALID`;
- the private key has **no `CKA_VALUE`** to read — an attribute this module defines on its own
  synthetic object, though PKCS#11 defines none for an RSA private key [[S15](SOURCES.md)]:
  that attribute and the RSA secret factors answer
  `CKR_ATTRIBUTE_SENSITIVE`. `CKA_SENSITIVE` is `TRUE` and `CKA_EXTRACTABLE` is `FALSE`, which is
  what the token behind the portal reports and what a consumer must be told;
- only the granted leaf certificate, its public key and its private key are objects. The
  intermediates in `chain_der` are deliberately not, so that a URI naming `type=cert` on this
  token is unambiguous;
- object handles carry a generation counter, so a handle from a released grant is invalid rather
  than ambiguous;
- mechanisms are an allow-list and their parameters are checked before the call, not forwarded:
  RSA-PSS `hashAlg`/`mgf`/`sLen`, OAEP `hashAlg`/`mgf`/label length. The portal checks them again
  against the modulus, which is the only place the modulus size is known;
- the PKCS#11 v3 interface table is implemented rather than left absent, so `C_GetInterface` offers
  the same functions as `C_GetFunctionList` and not a different set;
- only `C_GetFunctionList`, `C_GetInterfaceList` and `C_GetInterface` are exported from the shared
  object, so that an application loading several PKCS#11 modules cannot have one module's `C_Sign`
  resolve to another's.

**A search has to name the credential before a chooser appears.** The window opens at
`C_FindObjectsInit`, so which searches may open one is a security question and not an ergonomic
one. It used to be "any search naming a class this token has", which is wrong in a way that only a
real handshake shows [[S19](SOURCES.md)]: GnuTLS verifying a **server's** certificate chain
issues
`C_FindObjectsInit` for `CKO_CERTIFICATE` with `CKA_ISSUER`, `CKA_SUBJECT` or a trust category
through **every configured p11-kit module**, so a sign-in page that had asked for nothing raised a
chooser for this token seconds after it loaded. Measured against a live identity provider on
2026-09-05.

A credential is now acquired only for a search that can mean nothing else: `CKA_LABEL` equal to the
contract's object label, a non-empty `CKA_ID`, or `CKA_CLASS == CKO_PRIVATE_KEY` (with `CKA_SIGN`
or `CKA_DECRYPT` if the consumer adds them). Issuer, subject, serial, trust-category and
class-only searches, and empty templates, answer **no objects** while there is no grant and never
prompt. Once a grant exists they match like any other search — the gate decides when a window may
open, not what the token holds. `portal_template_intent()` in `src/module/objects.c` is the whole
of it, `tests/test-module.c` is the table as assertions, and `tools/module-smoke.sh` phase 0 counts
`grant-created` across a token-only `p11tool --list-all-certs` and a `pkcs11-tool --list-objects`
to prove neither raised one. `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` moves class-only enumeration
back onto the acquiring side for NSS experiments and nothing else.

**There is no PIN on this side.** The token sets `CKF_PROTECTED_AUTHENTICATION_PATH`, so a TLS
stack does not ask for one; `C_Login` returns `CKR_OK` without doing anything, and **any PIN bytes
an application passes are ignored and never forwarded** — there is nothing here for them to unlock,
and the portal's interface has no field one could travel in. The real PIN is collected by the
backend, in the backend's own window, at the first `Sign`.

**Logging.** `G_MESSAGES_DEBUG=pkcs11-portal-certificate` and nothing else. Counts, mechanism
names, key type and size, and grant outcomes. Never a signature, never DER, never application data,
never a PKCS#11 URI, and there is no PIN to leak.

**The recursion rule.** This module must never be loaded by xdg-desktop-portal or by this backend:
the backend enumerates p11-kit's modules, and this one answers by calling the portal that calls the
backend. Three fences, because `pkcs11.conf(5)` states plainly that neither `enable-in` nor
`disable-in` is a security feature [[S5](SOURCES.md)]: `certificate_module_is_portal_module()` in
`src/tokens/discovery.c` (applied to configured modules *and* to an explicit `--module` path), the
module's own refusal to run in a process whose executable is named `xdg-desktop-portal` or
`xdg-desktop-portal-certificate`, and the installed module file's `enable-in:` allowlist, which
names two consumers and neither portal process.

**What it does not fix.** The application still learns which certificate it was given and can use
the key for anything the grant permits, for as long as the grant lives —
[0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) failure mode 10 is untouched,
and `purpose` still constrains selection and consent language rather than proving what a signature
was used for. Rate limiting is still in neither half.

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

A grant's lifetime is fixed at acquisition and there is no renewal: the frontend clamps it to
3600 s and enforces it on the monotonic clock, so a clock change cannot prolong one.

### What was implemented and then removed: delegation down the process tree

`AcquireCredential` grew a `delegate_to_children` (`b`) option, and a grant whose holder passed it
answered a later `AcquireCredential` **from a descendant of the holder's process** without asking
the user again. This backend's part was `delegated: true` alongside `preselect_certificate`: bind
that certificate and show no window. It was the only relaxation of "a grant needs a window"
anywhere in this interface, and it is gone from the proposal. Two reasons, either of which is
enough:

- **it could never fire for a Flatpak caller.** `XdpAppInfo`'s pidfd for a Flatpak app is the
  *bwrap instance's* and is identical for every process in that instance, so two peers inside one
  sandbox are never in a descendant relationship. The branch's tests passed only because the
  synthetic Flatpak app-info used by tests had been changed to carry the caller's own pidfd.
- **ancestry alone crosses application boundaries.** A host process holding a delegable grant that
  runs `flatpak run com.other.App` produces a descendant, and that unrelated application would have
  received a derived credential with no prompt.

The pidfd argument for the walk was also wrong: a pidfd holds the `struct pid`, not the numeric
pid's reservation, so "neither end can have been recycled" did not follow.

It is archived on the frontend's `experimental/certificate-webauthentication+delegation` branch.
The cost is the two choosers one WebKitGTK handshake raises, three seconds apart, asking the
identical question. The replacement worth designing is a grant that belongs to the **app-info
identity** rather than to the D-Bus peer: inside a Flatpak every process shares that identity, so
the helper process would get the grant with no new mechanism and no process-tree walk at all.

### What a facade would still force

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
- `expires_at` always applies, and nothing extends a grant: a longer one is a fresh consent.

The fd-lifetime rules the
[USB portal documents](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Usb.html)
[[S39](SOURCES.md)]
— usable until released, until the connection closes, until the device is removed, or until the
portal revokes them — are the precedent and are deliberately mirrored.

## Selection memory

Three things must never be conflated:

1. **remember which certificate was selected** — deferred;
2. **token login caching** — hardware and driver behaviour this service does not control and must not
   present as a feature;
3. **remembered authorisation to use the key** — deliberately absent.

**There is no selection memory on the interface.** The frontend's first proposal has no
permission-store row, no `allow_selection_memory` option and no `remember_selection` result, so
this backend has no checkbox to draw and never touches the permission store. When it comes back it
belongs in the frontend's permission store, keyed on something narrower than the app id alone —
the earlier shape remembered one certificate per application across every purpose and filter —
and it must still **preselect** and never skip the trusted consent step or a PIN. There is no
"remember PIN" and there never will be.

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
  What remains open is that the frontend does not actually do this yet, and that the rule this
  turns on is narrower than it was first written down as. The forbidden thing is **believing a
  caller about a third party's identity**: an app id passed in a field, by a peer that could have
  put anything there, is identity laundering and is not to be built. It is *not* forbidden to
  delegate across a process boundary at all — authenticated IPC where the frontend derives each
  peer's identity itself, or a capability the frontend issues to a named peer and later recognises,
  would both satisfy the rule. Neither is built, and in-process is simply the cheapest way to
  satisfy it. See
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
  from the bus before any sender is *accepted*, rather than trusted from a watcher's cache, because
  `NameOwnerChanged` is not ordered against the messages of the process that lost the name. A
  *refusal* is decided from the cache with no bus call, so that a stranger cannot force a
  synchronous round trip on the main thread per message. What remains is that the answer is a
  snapshot: the name can change hands between the check and the work the call authorises. It also
  means one call from a successor portal can be refused before this process has processed the
  change; the frontend retries, and the alternative is a bus call per hostile message. Sessions belonging to a previous owner are invalidated as soon as this backend
  notices the change, and a deployment that wants more can deny this backend's name in D-Bus policy
  to everything but the portal's uid.
- **Hardened-desktop assumptions.** How much level-2 and level-3 identity is worth depends on
  `ptrace` scope, compositor input isolation and `/proc` hardening, none of which this service
  controls or can detect reliably.

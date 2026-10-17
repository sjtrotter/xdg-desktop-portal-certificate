# Security model

The experimental implementation has no independent security review. Hardware evidence covers one
PIV card in one reader, including [TESTING.md](TESTING.md) tiers 3.1–3.4 on 2026-09-04.
The implementation checklist distinguishes controls from requirements and untested assumptions.

The [architecture](ARCHITECTURE.md#responsibilities) assigns identity and policy to
xdg-desktop-portal and token interaction to this backend; [README.md](../README.md) summarizes
status. The [impl contract](IMPL-INTERFACE.md) separates those processes. Frontend controls
refer to the fork's `experimental/integration` branch.

[PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md#contract) defines the public bus contract and
experimental export conditions.

## Implementation checklist

### Implemented and exercised

| Control | Implementation and coverage |
|---|---|
| Only the owner of `org.freedesktop.portal.Desktop` can call methods, including both impl `Close()` methods | `src/certificate-impl.c`, `reject_stranger()`; `src/request-impl.c`, `src/session-impl.c`; `tests/test-impl-dbus.c` uses a third connection |
| Acceptance resolves the bus owner; rejection uses the cache without a round trip | `certificate_impl_sender_is_frontend()`; `tests/test-impl-dbus.c` reproduces queued calls from a replaced frontend. Unique names are never reused; a successor can have one call refused before the watch updates |
| Sessions bind `app_id` and prohibit identity-level increases | `lookup_session()`; `tests/test-impl-dbus.c` checks cross-app use and `unidentified` to `sandboxed` |
| Closed session paths can be reused | `handle_create_session()`; `tests/test-impl-dbus.c` creates, closes and recreates |
| Invalidated Session skeletons remain exported for idempotent `Close()` | `src/session-impl.c`; the frontend closes in response to invalidation |
| Wrong types, unknown enums and unknown security-relevant nested keys fail; defaults apply to absent fields | `parse_acquire_options()`, `src/tokens/filter.c`, `src/broker/mechanism.c`, `lookup_string()`; malformed-option tests in `test-impl-dbus.c` and parameter tests in `test-mechanism.c`, including `signature_encoding`, `mgf`, `mgf1_hash` and mismatched hashes |
| Export failure aborts a call before inserting a session | `src/certificate-impl.c`, `src/request-impl.c`, `src/session-impl.c` |
| Chooser displays supplied identity and backend-owned purpose text | `src/core/chooser.c`, `src/core/chooser-format.c`, `build_identity()` in `src/ui/chooser.c`; private-bus runs display `unidentified` |
| Externally sourced display text is sanitized and capped, including combining-mark runs | `certificate_display_text()` in `src/certificate.c`; `test-redact.c`. Applies to app names and ids, subjects, issuers, token labels, readers and `reason` |
| Expired certificates remain selectable and have textual warnings | `src/tokens/filter.c`, `src/core/chooser-format.c`, `src/ui/chooser.c`; `test-filter.c` |
| One candidate still requires consent | `src/certificate-impl.c` has no chooser-bypass path |
| Reacquisition rebinds the device and discards old login and key handles | `certificate_device_open()` in `src/broker/device.c`; `test-broker-regrant.c` verifies against the new certificate and `test-broker-device.c` checks device state |
| Frontend departure cancels windows and answers pending calls `owner_gone` | `cancel_transactions()` in `src/certificate-impl.c`; `test-impl-dbus.c` |
| PIN handling stays outside Certificate interfaces | `src/core/pin.c` takes a login callback. GTK collects locally; system prompting delivers an encrypted exchange from the shell. See PIN handling below |
| Prompt selection is explicit and logged | `certificate_pin_set_prompt_kind()` in `src/ui/pin-backends.c`, `src/ui/pin-gtk.c`, `src/ui/pin-system.c`; `--pin-prompt=auto|gtk|system`, `pin-prompt-selected detail=...`; `test-pin-system.c` and `tools/ui-smoke.sh --pin-prompt=system` |
| Only `main()` selects the system prompter by default | `pin_prompt_kind` defaults to `gtk` for library and test use |
| No remember-PIN control | GTK has no control; system path uses `gcr_prompt_set_choice_label(NULL)` [[S56](SOURCES.md)]. `test-pin-system.c` checks empty choice label and `password-new=false` |
| Login timeout hides the prompt and abandons late success | `on_login_timeout()`, `CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT`; 60 s default, `--login-timeout 0` disables; `/pin-system/login-timeout`. The caller still waits for the module to return |
| Owned PIN pages are aligned, locked where possible, non-dumpable and wiped | `XccSecret` in `src/core/secret.c`: `mlock()`, `MADV_DONTDUMP`, `explicit_bzero()`. Wipe precedes completion; lock failure warns once without refusing login |
| Worker owns the submitted PIN page | `src/core/pin.c` transfers `XccSecret` without copying; `test-cancellation.c` checks the worker's PIN after window cancellation |
| In-flight login cancellation hides UI and defers completion until worker return | `pin_prompt_finish()`; `test-cancellation.c` under ASan |
| Cancelled successful login is logged out | Abandon callback and `do_abandon()` in `src/broker/operations.c`; `test-cancellation.c` checks both abandoned and normal login |
| Core dumps and ordinary same-UID attach are disabled | `harden()` in `src/main.c`: `PR_SET_DUMPABLE(0)`, `RLIMIT_CORE 0`; `--debug-allow-core` disables this for development and is absent from installed activation |
| Bus-name replacement requires opt-in | `--allow-replacement` and `--replace` are separate; installed service passes neither. See [IMPL-INTERFACE.md](IMPL-INTERFACE.md) and [TESTING.md](TESTING.md) §3.8 |
| PINs are never persisted | No keyring entry, configuration key or retention option |
| Protected authentication path uses a null PIN and no editable field | `src/ui/pin-gtk.c`, `src/ui/pin-system.c`; system tests check zero password rounds |
| Empty PINs consume no login attempt | `xcc_secret_set_length()` and `certificate_pin_prompt_hold()`; `/pin-system/empty-answer-never-reaches-the-card` checks one login for two prompt rounds |
| Retry flags are reread after every refusal, without invented counts | `certificate_pin_prompt_retry_hint()`, `certificate_tokens_refresh_flags()`; system tests check warning text |
| `FINAL_TRY` warns before typed input; protected-path login requires one Continue | `src/core/pin.c`, GTK warning label, system prompt warning; policy and system tests cover both paths |
| Shell dismissal ends interaction after PIN submission too | `on_gcr_prompt_close()`; `/pin-system/shell-cancel-after-the-pin-was-submitted` checks cancellation and abandonment |
| Card administration is absent; every PIN attempt requires user action | No `C_InitToken`, `C_InitPIN` or `C_SetPIN` surface. These and repeated incorrect PINs are the threats named by Ueno on 2023-06-23 in [#662](https://github.com/flatpak/xdg-desktop-portal/issues/662). Host applications with direct card access remain able to perform them |
| Prompter disappearance completes the interaction | System open, password and confirmation callbacks handle gcr's `G_IO_ERROR_CANCELLED`; three vanish cases in `test-pin-system.c` |
| One prompt permits at most three attempts | `PIN_MAX_ATTEMPTS`; `/pin-system/attempt-cap`. No per-caller rate limit |
| Retries require user action | `src/core/pin.c`; `test-broker-device.c` preserves `PIN_INCORRECT` |
| Prompts are serialized process-wide; operations on one session share a prompt | Queue in `src/core/pin.c`, waiter list in `src/broker/operations.c` |
| Shared prompt lifetime follows live session waiters | `waiter_cancelled_idle()`, `login_cancellable` in `src/session-impl.h`; cancelling one operation leaves others waiting, cancelling the last closes UI; `test-cancellation.c` |
| Login happens at first private-key use | `src/broker/operations.c`; UI smoke tests |
| Mechanisms and parameters are checked against the key | `src/broker/mechanism.c`, `test-mechanism.c`; PSS `emLen >= hLen + sLen + 2` uses 64-bit arithmetic to avoid 32-bit overflow near `G_MAXUINT32`; `test-discovery-limits.c` covers bounds |
| Signing requires the named hash's digest length | `src/broker/mechanism.c`, `test-mechanism.c` |
| OAEP ciphertext is exactly one modulus long and label is at most 256 bytes | Internal decryption code; `test-mechanism.c`, `test-broker-device.c` |
| Tokens are resolved by manufacturer, model, serial and label | `certificate_tokens_open_session()` in `src/tokens/discovery.c`; slot number alone is insufficient |
| Tokens without serials are refused during acquisition | `finish_acquire()` in `src/certificate-impl.c` |
| Grant expiry uses a monotonic clock | `src/session-impl.c`; closed, expired and cancelled state is checked before and under the device lock; `test-broker-regrant.c` checks clock behavior |
| Detected token removal invalidates that token's grants | `on_token_event()` in `src/certificate-impl.c` |
| Frontend disappearance or replacement closes its grants | `on_frontend_vanished()`, `set_frontend_owner()` |
| Shutdown signals `backend_gone` and flushes; owner replacement closes silently | `src/main.c`, `src/certificate-impl.c`; `test-impl-dbus.c`. Successor knows no old sessions; pending calls get `owner_gone`, which is not a signal reason |
| Invalidation validates five reasons | `src/session-impl.c`: `expired`, `token_removed`, `policy`, `backend_gone`, `error`; unknown internal value logs a critical and sends `error` |
| Logging accepts structured fields and escapes/caps external values | `src/redact.h`, `src/redact.c`; `test-redact.c` checks PIN-URI truncation and newline injection |
| Full serials are excluded from logs and all serials from `token_display` | `src/redact.c`, `src/certificate-impl.c` |
| Runtime PKCS#11 calls run off the main thread | `src/broker/`, `src/tokens/discovery.c`, `src/certificate-impl.c`, `src/session-impl.c`; includes capabilities and asynchronous release via `certificate_impl_session_release_device_async()` |
| Requests share one cancellation source | `src/request-impl.c`, `src/certificate-impl.c`; `Close()` cancels it, cancelled operations answer `1`; `test-cancellation.c` |
| Inventory stays behind consent | `on_enumerated()` always opens the chooser, including empty results; forbidden interaction and no display answer uniformly; capabilities report backend support |
| Discovery does not log in | `src/tokens/discovery.c`, `test-broker-device.c` |
| Hardware-only selection is the default | `token_skip_reason()`, `CKF_HW_SLOT` [[S11](SOURCES.md)]; `--allow-software-tokens` or explicit `--module` permits software tokens; `--list-tokens` prints skipped reasons. Loaded modules supply these flags, so this is not isolation |
| Windows follow desktop color scheme | `follow_colour_scheme()` reads GSettings because process hardening prevents portal identification; see PIN handling |
| Worker-visible reference counts are atomic | `src/core/pin.c`, `src/core/chooser.c`, `src/broker/operations.c`: `g_atomic_int_inc`, `g_atomic_int_dec_and_test` |
| Scratch-directory deletion requires containment and a project marker | `fixture_check()` in `tools/lib.sh`; existing unmarked directories are refused. Full path, ownership and mode rules are in [TESTING.md](TESTING.md) |

Shutdown has synchronous exceptions. `certificate_impl_shutdown()` waits up to two seconds for
release workers and logs if the wait expires. Before that, `certificate_tokens_stop_watch()`
joins a presence thread that can be sleeping for its two-second poll interval or blocked in a
module call. Total shutdown time is unbounded. Session finalization also closes synchronously;
asynchronous close holds a reference until completion, preventing a finalizer/worker race.

### Missing controls and evidence

| Item | Limit |
|---|---|
| Served PKCS#11 facade | Unimplemented; no `OpenPkcs11Endpoint`. Consumers use the client module ([0011](decisions/0011-client-side-pkcs11-module.md)); future acceptance criteria are under Grant scoping |
| Multiple grants per module process | One credential per process; [0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) failure mode 8 remains open |
| Rate limiting | Neither frontend nor backend counts requests by caller or time; the prompt's three-attempt cap cannot provide that. The client module suppresses reacquisition for 10 seconds after any chooser cancellation, including an empty list |
| Per-operation signing consent | Consent is per grant for every purpose; a separate signing confirmation is unimplemented |
| Chain construction | Empty chain and `leaf_only` |
| Stronger host access policy | No shipped D-Bus policy separating the portal from other same-UID processes |
| Guaranteed wipe of every widget copy | GTK uses secure entry memory where supported but makes no guarantee for input-method or layout copies; the system path moves those copies to the shell |
| Interrupting `C_Login` | PKCS#11 provides no cancellation; the attempt proceeds and completion waits |
| `Decrypt` | No method exposes it. Internal RSA-OAEP code uses indistinguishable errors and a 32-attempt grant budget (`CERTIFICATE_MAX_DECRYPTS_PER_GRANT`); `test-broker-decrypt.c` covers it. PKCS#1 v1.5 decryption is refused [[S49](SOURCES.md), [S50](SOURCES.md)] |
| Hardware breadth | Tiers 3.1–3.4 passed on one PIV card/reader on 2026-09-04. One-PIN-per-grant, wrong PIN and `FINAL_TRY`, removal during an operation, PIN-pad readers and additional cards remain unrun |

## Boundary and threat model

Sandboxed callers with containment-framework identities can be confined to the portal instead of
holding direct `--socket=pcsc` access [[S43](SOURCES.md)]. Ordinary host callers gain an
explicit, attributable, revocable consent path. Both services run as the user. Depending on
hardening, hostile host processes may inspect memory, manipulate environment and runtime files,
inject input or impersonate desktop context. Compositor isolation,
`ptrace` scope and `/proc` restrictions are external assumptions.

Assume adversarial callers and malformed external data. A signing capability permits impersonation
for its lifetime even when the card's key cannot be extracted. A PIN establishes user presence
and card authentication; consent additionally identifies the caller, purpose, scope and duration.
`purpose` filters certificates and supplies consent language but cannot attest later signature use.
[ADR 0007](decisions/0007-brokered-operations-are-the-core.md) records the brokered contract.

| Asset | Exposure |
|---|---|
| Card key usage | Signatures as the user while a grant lives |
| PIN | Card use by someone also holding the physical card |
| Retry counter | Card blocking and denial of service |
| Trusted dialog | Spoofed or inconsistent UI can mislead consent |
| Certificate/token inventory | Employer, issuance and potentially clearance information; chooser required even when empty, uniform noninteractive answers, token-independent capabilities |
| Attribution | Loss of caller-specific audit and revocation information |

## Caller identity

The frontend establishes identity through `xdp_invocation_get_app_info()` [[S37](SOURCES.md)].
Sandbox identities come from the containment framework; host identity normally comes from
standardized cgroups. The host Registry lets a peer associate a desktop-file app id, but is
subject to deprecation according to the
[API reference](https://flatpak.github.io/xdg-desktop-portal/docs/api-reference.html), rather than
its [interface page](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.host.portal.Registry.html)
[[S40](SOURCES.md)]. Executable paths and `/proc/$pid/exe` are hints, not authenticated identities.

| Level | Display requirement |
|---|---|
| `sandboxed` | Containment-framework identity, labelled with sandbox status |
| `host` | Derived desktop label, with an explicit unverified warning |
| `unidentified` | "An unidentified application", with the strongest warning |

Identity is derived once per transaction and forwarded as arguments. No application option can
supply it. There is no `app_display_name`; the backend may derive a name from `app_id`.
The backend accepts only the current frontend owner; [IMPL-INTERFACE.md](IMPL-INTERFACE.md)
describes checks and races. Grants bind to their initiating unique D-Bus connection.

Unverified ids cannot be sufficient keys for future persistent authorization or selection memory.
Unidentified callers must give explicit consent with their uncertainty displayed. Caller and
global rate limits remain requirements, with no implementation.

## Trusted dialog

The backend renders frontend-established facts. The chooser must display app id and optional
derived name, identity level and warning, backend-owned purpose, operation class, certificate
subject and issuer, validity and a fingerprint or short identifier in details, token and reader,
grant duration or operation-only scope, whether later operations may proceed without another
prompt, and a separately labelled application-provided `reason`.

Only established identity occupies the trusted application position. App text, token labels and
certificate subjects cannot replace it. The current operation is signing; decryption would need
its own consent language. `reason` is the application's explanatory text, not a verified
statement. A client-authentication destination may be mentioned there, but the backend sees no
TLS connection and cannot verify it. There is no `context` option or selection memory.

[Accessibility criteria](PUBLIC-INTERFACE.md#accessibility-criteria) apply to the chooser and
PIN interaction.

## PIN handling

Neither Certificate interface transports PINs. PINs must never enter their GVariants, error
messages, URIs or logs. The frontend never receives them. Backend-owned buffers exist only
through login and are wiped on every exit path, including success, failure, cancellation, timeout
and window destruction. No emitted URI contains `pin-value` or `pin-source`; received URI text
is truncated before logging.

### PIN entry and transport

With gcr-4, `--pin-prompt=auto|gtk|system` selects the entry implementation. `auto` uses the
system prompter when `org.gnome.keyring.SystemPrompter` is owned or activatable, otherwise GTK.
The journal records `pin-prompt-selected detail=gtk|system`. Without gcr-4, `gtk` and `auto`
use GTK; `system` is rejected with a usage error (64).

| Property | `gtk` | `system` |
|---|---|---|
| Entry owner | Backend `GtkPasswordEntry` | Desktop shell through `GcrSystemPrompt` [[S55](SOURCES.md)] |
| PIN transfer | Local to backend | gcr ephemeral Diffie-Hellman secret exchange over D-Bus; encrypted on the bus, then copied from gcr secure memory into backend-owned pages |
| Application parenting | `xdg_foreign` or X11 XID where available | `caller-window` is sent with portal scheme stripped; GNOME Shell ignores it and draws a session-modal dialog |
| Display needed in backend | Yes | No for PIN entry; acquisition still needs a chooser |

The system path moves entry, input method and layout copies into the shell. It still delivers the
PIN to this backend because `C_Login` requires it. gcr's copy belongs to `GcrPrompt`; closing
and releasing it on hide, cancel or timeout releases that copy even while a worker is blocked.
The worker owns a separate page and needs no live widget or prompt object. A requested system
prompter that cannot be reached fails with `no_display` and a journal reason; there is no silent
GTK fallback after selection.

Common code in `src/core/pin.c` controls attempt limits, protected-path confirmation, flag
refresh, queueing, deferred cancellation, timeouts and abandonment. Entry implementations collect characters and
render warnings without deciding whether an attempt is spent.

The gcr 4.4 double-completion risk is this project's source analysis and test result;
no upstream report is recorded [[S57](SOURCES.md)]. `perform_close()` takes a pending round
and completes it from an idle. A still-pending `PerformPrompt` call failing later can complete
that result again in `on_perform_prompt_complete()`. `on_call_timeout()` can trigger both.
`src/ui/pin-system.c` passes no `GCancellable` to gcr and claims each `GAsyncResult` with an
object flag before accessing backend state. gcr retains that result through both completions;
the second is ignored with `pin-prompt-round-completed-twice`. The
`/pin-system/close-racing-a-transport-error` test leaves a round unanswered, closes it, then
fails transport and checks the log.

### Memory and process hardening

Owned PIN pages use `mlock()` where the resource limit permits, `MADV_DONTDUMP` and
`explicit_bzero()`. An `mlock()` failure is warned once at message level and login remains
available; swap exclusion is then unproven. `src/core/secret.c` owns storage;
`src/core/pin.c` transfers the submitted page to the worker, which wipes it after login returns.
GTK's `GtkPasswordEntryBuffer` uses secure memory, zeroes on free and uses non-pageable memory
where the platform allows it. GTK does not guarantee the lifetime of input-method, text-widget
or Pango copies. The entry is cleared after copying into backend memory. Neither path claims
that exactly one PIN copy exists.

`PR_SET_DUMPABLE(0)` and `RLIMIT_CORE 0` disable core dumps and ordinary same-UID `ptrace`
attach. `/proc/self/*` becomes root-owned; the settings portal cannot inspect `/proc/$pid/root`
to identify the process. The backend sets `GDK_DEBUG=no-portals` and `ADW_DISABLE_PORTAL=1`
before GTK initialization to avoid failed Settings calls. `gdb` attach also fails.
`--debug-allow-core` disables hardening for development and must stay out of installed service
files. A tracer attached before hardening, `CAP_SYS_PTRACE`, or different kernel policy remains
outside this mitigation.

Color-scheme behavior was measured on Fedora 44 with `prefer-dark`: portal fallbacks alone gave
a light window under hardening and a dark one with `--debug-allow-core`. The backend retains
hardening and reads `org.gnome.desktop.interface color-scheme` through GSettings/dconf, feeds
`adw_style_manager_set_color_scheme()` and follows changes. If the schema is absent,
libadwaita's choice applies. `ADW_DEBUG_COLOR_SCHEME` overrides it for tests; `--verbose`
logs `colour-scheme detail=dark|light`.

### Login, retries and cancellation

The broker logs into its own session at first private-key use. PKCS#11 shares login among an
application's sessions, without transferring that state across a forwarding boundary. Tokens or
middleware may cache authentication outside this service. `C_Logout` is issued at grant end;
the backend cannot guarantee that card, firmware or driver forgets authentication.

Keys with `CKA_ALWAYS_AUTHENTICATE` require a fresh PIN interaction and
`C_Login(CKU_CONTEXT_SPECIFIC)` after operation initialization for each use. The PIN is not
cached. PIN cancellation or failure closes the device session to discard the initialized
operation.

A protected authentication path (`CKF_PROTECTED_AUTHENTICATION_PATH`) uses a null PIN and an
instructional dialog without an editable field [[S12](SOURCES.md)]. The token or reader collects
the secret. Entry starts automatically unless `FINAL_TRY` is set; then one explicit Continue
starts the reader and Cancel spends no attempt. Repeated Continue replies cannot restart login.

Retry warnings use `CKF_USER_PIN_COUNT_LOW`, `CKF_USER_PIN_FINAL_TRY` and
`CKF_USER_PIN_LOCKED`. Flags are reread after each refusal; remaining counts are never invented.
The specification allows tokens to report flags false and does not specify update timing
[[S13](SOURCES.md)]. Typed PIN prompts show the final-try warning from the start of the input
round, including after a refusal refreshes the flags. Unlock submits directly. GTK places a
warning-styled label above the entry and announces it when it appears; gcr uses the system
prompt's warning and accessibility. Count-low wording is also shown upfront. Only protected-path
final tries require a confirmation round. A different process can spend an attempt between flag
read and login, so this is best effort.

An empty PIN is rejected before submission and the prompt repeats. At most three attempts are
offered per prompt. Incorrect PINs permit user-initiated retries within that limit; protected-path
login ends the interaction after an incorrect PIN because the reader owns entry. Locked PINs,
cancellation, token removal and other device failures, including ambiguous transport failures,
end the interaction. A fresh application request can start a new prompt and spend another
attempt. PIN prompts are serialized; concurrent operations on one session share the initial
user login. Cancelling a waiter leaves other waiters active; cancelling the last hides the
prompt. Keys with `CKA_ALWAYS_AUTHENTICATE` prompt separately for each operation.

With no usable display or forbidden interaction, calls fail with `no_display` or
`interaction_required`. No path reads a PIN from stdin. A headless trusted-agent protocol
would need separate configuration and review.

A submitted `C_Login` cannot be withdrawn. Cancellation hides the prompt but completion waits
for its worker. `--login-timeout` (60 s, `0` disables) hides it, logs `pin-timeout` and records
`CERTIFICATE_PKCS11_ERROR_LOGIN_TIMEOUT`; the caller still waits for module return. Late success
is abandoned by worker-thread logout. A timed-out or cancelled attempt is still spent.

## Grant scoping

A grant binds one certificate and key, a caller, permitted operations and mechanisms, and a
bounded lifetime. The frontend's `check_grant()` in `desktop-portal/certificate.c` checks
existence, liveness, owner and allowed operations/mechanisms before calling the backend. The
backend checks app id, non-increasing identity, expiry, mechanism and parameters against the key,
and uses its own device session. Rate limits and per-operation signing consent are missing.

A grant is a signing capability. During its lifetime the portal signs any digest the application
sends with the granted key, using a permitted mechanism. The portal cannot tell a TLS
CertificateVerify from a document signature, and nothing binds the grant to a server or origin;
`purpose` selects candidates and consent wording only. A compromised application that holds a
grant can produce arbitrary signatures with that key until the grant expires. This is accepted for
version 1 ([#12](https://github.com/sjtrotter/xdg-desktop-portal-certificate/issues/12)): what the
portal protects is the PIN, card administration, other keys, and time. The frontend sets the
lifetime: 300 seconds by default, at most 3600. Deployments that need confirmation per signature
should not raise the lifetime; a per-operation confirmation option is future work.

A served facade is unimplemented; [ADR 0011](decisions/0011-client-side-pkcs11-module.md)
defines the client module. A future fd-returning facade would have to:

- Expose one synthetic slot/token and only the granted leaf, keys and explicitly selected chain.
- Map synthetic handles to broker-owned objects and reject fabricated, stale or foreign handles.
- Permit read-only sessions; reject `CKF_RW_SESSION` and SO login; treat user login as a
  PIN-free authorization transition.
- Refuse token/PIN administration, object creation/copy/deletion/mutation, key generation,
  wrapping/unwrapping, derivation unless explicitly required, RNG seeding and operation-state transfer.
- Restrict attribute access, mechanisms and validated parameters, including RSA-PSS hash/MGF/salt.
- Gate signing and encryption/decryption on the grant; validate all lengths and operation state.
- Rate-limit and terminate on expiry, revocation or removal.
- Apply the same restrictions to v3 interface tables and v2 function lists.

That facade would run in a separate backend child without a PIN, access the card through the
broker, and require RPC fuzzing. The backend would create its socket; the frontend would check
caller/grant, relay the fd and retain no reference. Every entry point needs an explicit rule;
filtering `C_FindObjects` alone cannot prevent access via handles, templates or other operations.

## Client-side PKCS#11 module

[`libpkcs11-portal-certificate.so`](../src/module/) lives in the consumer. It holds a session-bus
connection, worker thread and private `GMainContext`, at most one grant handle, and selected
certificate DER. It holds no private key, real-token session or card handle. PIN bytes passed
by the application are ignored and never forwarded. The module grants only capabilities the
same application could request directly through `org.freedesktop.portal.experimental.Certificate1`.
Portal assets remain protected by frontend and broker validation.

The consumer's assets also need protection. A browser loading the module adds DER parsing,
an attribute protocol, a D-Bus client and a worker beside its own secrets. Treat portal replies
as malformed input even when the sender is authenticated. Card-derived `certificate_der`,
`chain_der`, `key_type`, `key_curve` and `supported_mechanisms` reach `src/module/objects.c`
and `src/module/der.c`. Length or attribute-protocol errors can corrupt the consumer.

TLS servers control certificate challenges, acceptable issuers and signing parameters; those
inputs reach `src/module/mechanism.c` and `portal_digestinfo_parse()` through GnuTLS/NSS,
possibly repeatedly without user action. Fork safety is unsupported
([0011](decisions/0011-client-side-pkcs11-module.md)); unload and reinitialization have tests.

`tests/fuzz-der.c` exercises TLV, DigestInfo, arbitrary certificate objects and hostile attribute
templates. It always builds as a Meson corpus replay; clang can also build a libFuzzer target.
Replay uses ASan/UBSan only in a sanitizer build:

```console
$ meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false
$ meson test -C build-asan
```

Opt-in module loading limits exposure. The module returns:

- `CKR_FUNCTION_NOT_SUPPORTED` for token writes, administration, key generation, wrap/unwrap,
  derivation and RNG operations.
- `CKR_TOKEN_WRITE_PROTECTED` for read-write sessions and `CKR_USER_TYPE_INVALID` for SO login.
- `CKR_ATTRIBUTE_SENSITIVE` for private `CKA_VALUE` and RSA secret factors; public attributes
  in the same template can still be returned. The synthetic key has `CKA_SENSITIVE=TRUE`
  and `CKA_EXTRACTABLE=FALSE`. RSA private `CKA_VALUE` is a module-defined extension [[S15](SOURCES.md)].

Only the leaf, public key and private key are objects; `chain_der` intermediates are excluded to
keep certificate URIs unambiguous. Handles carry a grant-generation counter; a stale handle
never names a replacement object.
Grant invalidation retires all existing PKCS#11 sessions with `CKR_SESSION_HANDLE_INVALID`,
including pending searches, signatures and decryptions. New sessions can acquire only through
the usual search-intent gate. Mechanism checks include PSS `hashAlg`/`mgf`/`sLen` and OAEP `hashAlg`/`mgf`/label, with backend modulus checks.
V3 interface tables offer the same functions as the v2 list. The shared object exports only
`C_GetFunctionList`, `C_GetInterfaceList` and `C_GetInterface` to avoid inter-module symbol
resolution.

### Search intent

Credential acquisition at `C_FindObjectsInit` requires the contract's `CKA_LABEL`, a
`CKA_ID` issued during this module initialization, or `CKA_CLASS == CKO_PRIVATE_KEY`.
`CKA_SIGN`, `CKA_DECRYPT` and persistent `CKA_TOKEN` modifiers do not change intent. Without a grant, issuer, subject, serial,
trust-category, class-only and empty searches return no objects and never prompt. With a grant,
normal template matching applies. Unknown or malformed IDs cannot trigger acquisition, even
with the contract label. `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` or
`x-init-reserved: enumerate=1` in the p11-kit module file permits class-only acquisition.
A cancelled chooser suppresses acquisition for ten seconds across all templates in the process.
`portal_template_intent()` and `test-module.c` define this gate;
`tools/module-smoke.sh` phase 0 checks token-only `p11tool --list-all-certs` and
`pkcs11-tool --list-objects` produce no `grant-created` events.

The 2026-09-05 live run measured GnuTLS server-chain verification searches reaching this module
before a client-certificate challenge [[S19](SOURCES.md)]. That is evidence from one system;
GnuTLS's PKCS#11-backed trust configuration and trusted-provider selection determine where such
searches run. Search intent must prevent them from asking for credentials.

The token sets `CKF_PROTECTED_AUTHENTICATION_PATH`. The first successful `C_Login(CKU_USER, ...)`
returns `CKR_OK` without a PIN; a repeated login returns `CKR_USER_ALREADY_LOGGED_IN`.
Real login occurs through backend PIN interaction on first `Sign`. Debug logging uses
`G_MESSAGES_DEBUG=pkcs11-portal-certificate`: counts, mechanisms, key type/size and outcomes,
without signatures, DER, application data or URIs.

The module must never load inside either portal executable. Discovery checks configured modules
and explicit `--module` paths with `certificate_module_is_portal_module()`; the module refuses
both executable names; its `enable-in:` allowlist names two consumers and neither portal.
p11-kit documents that allow/deny names are not security features [[S5](SOURCES.md)].
The application still learns the granted certificate and can use permitted signing for any
message; [0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) failure mode 10 applies.

## Card removal and grants

Detected removal cancels operations, closes every grant on the token and emits
`SessionInvalidated(..., "token_removed")`; the frontend emits owner-only `GrantInvalidated`
and closes the Session. Discovery polls every two seconds and requires two consecutive changed
observations. Invalidation can lag by seconds; removal and reinsertion between polls can be missed.

The client module advertises `CKF_REMOVABLE_DEVICE`. On the next session lookup, slot-info
query, nonblocking slot-event poll or session open after a grant ends, it retires all existing
PKCS#11 sessions. `C_GetSessionInfo` and supported operations on those handles return
`CKR_SESSION_HANDLE_INVALID` permanently. This applies to every `GrantInvalidated` reason,
portal `Session.Closed` and local `expires_at` expiry; all can invalidate cached object handles.
The next credential search in a new session requires fresh consent. Issued IDs and the
cancelled-chooser throttle survive this transition.

While the portal remains available, `CKF_TOKEN_PRESENT` stays set and new sessions can open
immediately. NSS detects removal/reinsertion through the defunct session on its next actual
presence poll, clears token caches and increments its slot series. Its one-second presence
cache can delay that poll; no timed absence window or sleeps are used by the module.
`C_WaitForSlotEvent(CKF_DONT_BLOCK)` reports one event per retired grant; blocking waits remain
unsupported. Token label and serial do not change across grants.

Real-token session errors can also reveal removal at the next backend operation. A grant with
no first operation has no token session yet, so an undetected removal/reinsertion can leave it
live. Opening the device rechecks manufacturer, model, serial and label; a different card is
refused. After detected removal, reselection is required even for identical label and slot.
A future facade must poison its endpoint and report a device/token error without rebinding.

## Grant lifetime and delegation

[PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md#lifetime) defines grant expiry and the backend
teardown backstop.

Process-tree delegation is not on the interface. Every acquisition requires a consent window.
[ADR 0011](decisions/0011-client-side-pkcs11-module.md) records limitations and the candidate
of app-info-scoped ownership.

A possible future endpoint model must handle a browser's separate network process without
keeping authority alive after the authorizing request ends. Its requirements are one owner
connection allowed to release the grant, explicitly delegated holders, termination on owner
release or when all holders leave, a short acquisition-to-connection orphan grace period, and
an expiry that holders cannot extend. This endpoint model remains unimplemented.
The [USB fd lifetime rules](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Usb.html)
[[S39](SOURCES.md)] provide a precedent: release, connection closure, removal or revocation ends use.

## Selection memory

Certificate preselection is deferred. Token login caching is device/driver behavior outside this
service; remembered authorization and PIN retention are absent. The current interface has no
permission-store row, `allow_selection_memory`, `remember_selection` or backend checkbox.
Future memory belongs in the frontend permission store, keyed more narrowly than app id alone
across all purposes and filters. It must only preselect and cannot bypass consent or PIN prompts.

## Logging

The frontend records caller decisions and backend selection; the backend records card events.
Sign operation logs in [`src/broker/operations.c`](../src/broker/operations.c) include the
session handle and the caller's optional `operation_id` for correlation with the frontend
journal. An absent operation id is logged as `(none)`.
PIN grant logs carry the same session handle.
[`src/redact.c`](../src/redact.c) escapes control characters and caps each id at 128 input
bytes, followed by `...` when truncated.
Allowed fields are counts, stable reason codes, purposes, supplied identity and level, ids,
mechanism names, token presence and timings. Full
serials, subjects, PINs, URIs, labels, key ids, signed data, plaintext and `reason` contents are
excluded. Library error text is truncated before embedded URIs, which can contain `pin-value`.
Structured logging entry points restrict fields without a free-form format string. Verbose mode
adds diagnostic events without sensitive data.

## Pre-consent residuals

Enumeration duration differs with and without a token; no artificial delays are added.
Middleware enumeration failures remain visible as response `2`/`device_error`; failed
middleware can therefore differ from successful enumeration before consent.
Tokens without serials remain refused with `device_error` after selection.
Candidate and match counts remain in the journal; dialog-only absence details never reach callers.

## Open problems

Propagating an original caller's identity through an intermediary is no longer a goal: applications
load the module themselves and no service acquires credentials on their behalf
([#14](https://github.com/sjtrotter/xdg-desktop-portal-certificate/issues/14),
[ARCHITECTURE.md](ARCHITECTURE.md#scope-limits)). Caller-supplied third-party app ids cannot
establish identity.

Endpoint loading, concurrency and fd lifetime remain questions for a served facade; the client
module already serves PKCS#11 consumers. [SPIKES.md](SPIKES.md) S3 lists remaining browser tests.
Purpose attestation remains impossible. The impl boundary adds no Unix privilege separation; see the
[threat model](#boundary-and-threat-model).

The frontend-owner check in [IMPL-INTERFACE.md](IMPL-INTERFACE.md#frontend-only-access) is a
snapshot. Ownership can change between lookup and authorized work; old sessions close when the
backend observes the change. A uid-only D-Bus policy cannot separate same-UID applications;
stronger enforcement requires a distinct principal or sandbox policy.

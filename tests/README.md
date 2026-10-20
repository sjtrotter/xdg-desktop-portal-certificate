# Tests

The service build registers 34 tests with gcr-4 and 33 without in
[meson.build](meson.build). Run them with `meson test -C build`.
SoftHSM-dependent cases skip without a fixture; display-dependent cases skip when
GTK cannot initialize. [Testing commands](../docs/TESTING.md) cover setup, sanitizer builds,
frontend export conditions, smoke tests and hardware runs.

## Registered tests

| Test | Coverage | Needs |
|---|---|---|
| `filter` | Purpose, EKU, key usage, issuer DN, PIV slot and key-algorithm matching against fixture certificates; expired and not-yet-valid handling; portal-module recursion rejection by name and explicit path | No hardware |
| `mechanism` | Portal-to-`CKM_*` mapping, DigestInfo construction, digest length, raw/DER ECDSA, PSS MGF/hash/salt validation, wrong-typed optional strings, OAEP parameters and sign/decrypt mechanism separation | No hardware |
| `redact` | URI, `pin-value` and `pin-source` truncation; display sanitizing; newline journal-injection refusal; verbose log-domain filtering and `G_MESSAGES_DEBUG` overrides | No hardware |
| `discovery-limits` | Attribute-length bounds and RSA-PSS arithmetic limits, including 32-bit overflow boundaries; short object batches continue through zero; object budget accepts the boundary, rejects overflow and never-zero searches, and finalizes on error; invalid batch counts are refused | No hardware |
| `discovery-errors` | Certificate, private-key and public-key search limits reach acquisition as `device_error`; every search is finalized and its session closed | No hardware, display or bus |
| `token-watch` | Consecutive presence observations per token; unrelated reader flapping cannot delay removal or addition; slot order, baseline resets, serial-less tokens and duplicate-event suppression | No hardware, display or bus |
| `chooser` | Neutral module wording and purpose-specific native wording; app and token text cannot inject lines, ANSI escapes or direction overrides; length limits and textual expiry warnings | No display |
| `chooser-policy` | Empty and no-match insertion, removal, revision checks, `tokens_reading` transitions retaining candidates, structured validity/key fields and cancellation with late replies | No display or bus |
| `pin-policy` | Scripted PIN submission, wrong-PIN retries and attempt cap, refreshed retry flags, typed and protected-path final try, cancellation, stale secrets, empty/oversized input and `NO_DISPLAY` | No display or bus |
| `secret` | Secret lengths and embedded NULs, full-capacity wiping, lock-failure warning and ownership | No hardware, display or bus |
| `session` | Monotonic deadline and teardown grace, close and allowed invalidation reasons | No hardware, display or bus |
| `broker-device` | Discovery without login, `C_OpenSession`, `C_Login`, RSA v1.5/PSS and ECDSA with verification against returned certificate; `CKA_ALWAYS_AUTHENTICATE` key generation and two verified signatures with separate context logins; wrong PIN preserved; device rebinding discards login/key; RSA-OAEP round trip and ciphertext-length refusal | SoftHSM; `openssl(1)` for OAEP; skips missing prerequisites |
| `broker-decrypt` | Distinct internal decryption failures produce the same external error; grant budget counts attempts | SoftHSM, otherwise skips |
| `broker-regrant` | Private legacy-session rebinding discards login and verifies signatures against the new certificate; expiry clock and session/operation log fields. This bypasses the SDK's one-acquisition rule | SoftHSM with RSA and EC, otherwise skips |
| `impl-dbus` | Toolkit bus isolation against a controlled document-portal owner and singleton release; all methods and both `Close()` methods reject strangers; app-id binding, non-increasing identity, path reuse, malformed options, result types, string `reason` for every SDK signing failure, internal token-presence vardict, no `Decrypt`, shutdown reasons, queued calls from replaced frontend and frontend loss | Private `GTestDBus` |
| `cancellation` | In-flight login keeps worker PIN intact and answers once after completion; cancellation before UI and during device work; abandonment runs only for cancelled success; one cancelled waiter leaves shared prompt alive | Display for some cases, SoftHSM for others; run under ASan |
| `module` | DigestInfo accepted spellings and malformed inputs, TLS 1.0/1.1 concatenation refusal, DER length/tag bounds, mechanism list intersection, three synthetic objects, sensitive and public attributes in one template, size queries and small buffers, ID/template matching, issued-ID search intent, enumeration opt-in, URI contract | No bus |
| `module-portal` | Installed shared object's function table and D-Bus client: chooser lock release, finalization and reinitialization during waits, late replies, refused requests, shared chooser, session closure, configuration through p11-kit, grant release and reselection, issued-ID acquisition, cancellation across templates, local method and Response timeouts, remote transport failures, reason-to-PKCS#11 mapping for signing and decryption, caller-provided lengths, grant invalidation/expiry retiring sessions, slot events and stale handles, frontend loss/replacement and restart recovery on caller threads, lazy capability refresh and failed-probe backoff and recovery, typed 3.0 stubs and concurrent interface discovery | Mock portal on private `GTestDBus`; local method timeout requires `-m slow` |
| `module-lifecycle` | Owner signals queued during `C_Finalize`; weak references check private-context and shared-connection release | Private `GTestDBus`; module sources linked with teardown wrappers |
| `core-api` | SDK transactions with scripted token and UI boundaries; two grants retain token login when one closes; logout refreshes key handles; already-logged-in success and bounded reauthentication; queued joins after cancelled login; no login after expiry or closure; stalled device work leaves cancellation and expiry responsive; worker login snapshots are rechecked; overlapping and repeated acquisitions fail; late cancellation releases an undelivered grant; PIN-pad cancellation and provider `NO_DISPLAY` retain their reasons; removal during signing invalidates without a poll event; stale-grant closure preserves a fresh login; generic-purpose PIN wording; dispatched `tokens_reading` revisions and candidate snapshots | No display or bus |
| `pin-bridge-core`, `pin-bridge-service` | Both PIN reply bridges preserve `NO_DISPLAY` and cancellation; generic errors and finished-prompt replies | No display or bus; service variant requires the service build |
| `fuzz-der` | Corpus replay of TLV, DigestInfo, certificate objects and hostile attribute templates in `fixtures/fuzz-corpus` | Service build; sanitizers only when configured |
| `sdk-install` | Staged installation and C/C++ consumers using only installed public headers and library | C/C++ compilers and staging tools; no display, bus or hardware |
| `sdk-headers` | Installed headers, C/C++ ABI prefixes, original offsets and minimum sizes, appended metadata and available ILP32 compiler modes | C/C++ compilers; no display, bus or hardware |
| `sdk-symbols` | Complete public/private exports and symbol versions, plus `NODELETE` | ELF inspection tools; no display, bus or hardware |
| `sdk-core-only` | Separate `-Dservice=false --auto-features=enabled` build with no GTK, libadwaita or gcr dependency lookups | Meson, Ninja and core build dependencies |
| `sdk-stride` | Producer-sized chooser rows and issuer spans, partial/extended layouts, bounds and the `tokens_reading` size guard | No display, bus or hardware |
| `sdk-token-metadata` | Original and absent token metadata, plus original SoftHSM metadata when available | SoftHSM portion skips without a fixture |
| `sdk-link-args` | C and C++ SDK consumers retain saved linker flags, paths with spaces and sanitizer flags | No compiler, display or bus |
| `tools-lib` | Effective per-interface `portals.conf` resolution across config directories, preservation of `none`, Certificate override, private-only Secret disabling; fixture marker, symlink, ancestor ownership and mode checks | No hardware |
| `tools` | E2E usage exit codes and delivered cancellation, synchronous trigger commands, phase-0 consumer exits and chooser counts, Firefox module destination and frontend branch references | Python and shell stubs; no hardware, display or bus |
| `cli` | Help lists `--pin-prompt`; `gtk` and `auto` accept both argument forms; `system` requires gcr-4 and otherwise exits 64 with a usage error | No hardware, display or bus |
| `pin-system` | Concurrent broker signatures each initialize, prompt and log in with `CKU_CONTEXT_SPECIFIC`; queued context cancellation preserves shared login and prompts again after the last token session closes; prompt selection and supplied display fields; no remember/new-password choice; wrong-PIN warning on the same prompt; empty PIN refusal; three-attempt cap; cancel and external close; shell cancel after submission; prompter loss during open/password/confirmation; open failure through the core provider bridge retains `NO_DISPLAY` without login; gcr double-completion race; upfront typed-PIN final-try warnings at open and after flag refresh; protected-path final-try Continue; retry flags without invented counts; login timeout and abandonment; null-PIN path without password rounds | gcr-4; scripted prompter on private `GTestDBus`, no operator shell or display |

Decryption tests exercise the [internal implementation](../docs/IMPL-INTERFACE.md#decryption-implementation).
[Chooser requirements](../docs/IMPL-INTERFACE.md#interaction-and-consent) hold by construction;
display-helper tests leave keyboard and screen-reader navigation unproven.

## Integration scripts

| Script | Coverage |
|---|---|
| [dev-stack.sh](../tools/dev-stack.sh) | Real frontend/backend and end-to-end client on a private bus or under `--live` |
| [ui-smoke.sh](../tools/ui-smoke.sh) | Chooser and PIN windows under Xvfb, driven by xdotool; `--pin-prompt=system` uses `certificate-test-prompter` on the private bus |
| [module-smoke.sh](../tools/module-smoke.sh) | PKCS#11 consumers: non-acquiring searches, p11tool enumeration, pkcs11-tool signing verified with OpenSSL, GLib/GnuTLS mutual TLS |
| [nss-smoke.sh](../tools/nss-smoke.sh) | Direct `modutil` loading, `certutil -K` without a password callback, certificate listing with/without enumeration opt-in, `tstclnt` mutual TLS; needs nss-tools and its unsupported-tools binary |
| [firefox-flatpak.sh](../tools/firefox-flatpak.sh) | Live browser experiment with pcsc socket and device access removed |

The 2026-09-04 GnuTLS mutual-TLS handshake is software-token evidence: it ran against SoftHSM
under Xvfb ([recorded evidence](../docs/SPIKES.md#recorded-evidence)).

Use the [sanitizer build](../docs/TESTING.md#sanitizer-build) for cancellation and parser checks.
A return-value assertion alone can miss a lifetime error. No sustained fuzzing result is recorded;
clang can build the separate `fuzz-der-libfuzzer` executable when libFuzzer is available.

## Certificate fixtures

Certificates are generated with `certtool` and checked in as PEM so parser changes are tested
against fixed input. The nine fixtures are `client-auth-rsa`, `email-ec`, `no-eku-rsa`,
`server-auth-only`, `encipherment-only`, `expired-client-auth`, `not-yet-valid`,
`email-encipherment-only` and `email-sign-and-encipher`. Absence of EKU differs from an empty
extension. The email pair covers `emailProtection` with encipherment only and with both
signature and encipherment usage, using certtool output rather than mocked parsing.

## Frontend conformance and remaining coverage

On `experimental/certificate`, `tests/templates/certificate.py` supplies a python-dbusmock
backend and `tests/test_certificate.py` runs with host and Flatpak identities. It covers happy
paths, cancellation in both directions, invalid options, result clamping and owner-only
`GrantInvalidated`. Current test counts and results belong to that branch. `impl-dbus` tests
this backend against a fake frontend. Display sanitizing is automated; trusted placement still
requires looking at the dialog.

Conformance requires documented request/session paths, pre-call subscription using handle
tokens, at most one terminal response, no success after close, strict security-relevant option
validation, caller-owned grants, monotonic expiry and idempotent device teardown. The [security checklist](../docs/SECURITY.md#missing-controls-and-evidence) records the
per-operation signing-consent gap; its tests are also missing. Backend discovery works through `dev-stack.sh`
without a separate assertion on its "Providing portal" log line; config precedence is also a
frontend responsibility.

A future served facade needs a hostile driver exercising every
[facade security requirement](../docs/SECURITY.md#grant-scoping), including broad templates,
and RPC fuzzing. These checks remain conditional on an endpoint proposal.
[Module refusal coverage](../docs/SPIKES.md#s1-object-and-operation-scoping) is also incomplete.

## Hardware coverage

Recorded results include WebKitGTK on 2026-09-04/05, including a live Entra ID sign-in.
Hardware tests need real readers/cards and, for retry tests, a card that can be unblocked.
Remaining [hardware checks](../docs/TESTING.md#37-removal-and-other-hardware-checks) are gates
in [ROADMAP.md](../docs/ROADMAP.md) and [SPIKES.md](../docs/SPIKES.md).

Software-token results establish cryptography and protocol behavior. Hardware-specific timing,
retry counters and middleware failures require separate evidence; the Remmina discovery work
obtained its edge cases from hardware runs.

The GNOME fork also ran in a live GNOME 50 session with one PIV card, OpenSC and an SCR 331
reader: test-client signing, Flathub Firefox sign-in, chooser hotplug, wrong PIN through the
final-try warning and Shell system prompting. KDE has SoftHSM container coverage only, with
no live-session or card run. PIN-pad and Cancel-on-final-try checks remain unrun.

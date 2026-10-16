# Tests

`meson test -C build` runs the tests registered in [meson.build](meson.build): 15 with gcr-4,
14 without. SoftHSM-dependent cases skip without a fixture; display-dependent cases skip when
GTK cannot initialize. [Testing commands](../docs/TESTING.md) cover setup, sanitizer builds,
frontend export conditions, smoke tests and hardware runs.

## Registered tests

| Test | Coverage | Needs |
|---|---|---|
| `filter` | Purpose, EKU, key usage, issuer DN, PIV slot and key-algorithm matching against fixture certificates; expired and not-yet-valid handling; portal-module recursion rejection by name and explicit path | No hardware |
| `mechanism` | Portal-to-`CKM_*` mapping, DigestInfo construction, digest length, raw/DER ECDSA, PSS MGF/hash/salt validation, wrong-typed optional strings, OAEP parameters and sign/decrypt mechanism separation | No hardware |
| `redact` | URI, `pin-value` and `pin-source` truncation; display sanitizing; newline journal-injection refusal | No hardware |
| `discovery-limits` | Attribute-length bounds and RSA-PSS arithmetic limits, including 32-bit overflow boundaries | No hardware |
| `chooser` | App and token text cannot inject lines, ANSI escapes or direction overrides; length limits and textual expiry warnings | No display |
| `broker-device` | Discovery without login, `C_OpenSession`, `C_Login`, RSA v1.5/PSS and ECDSA with verification against returned certificate; wrong PIN preserved; device rebinding discards login/key; RSA-OAEP round trip and ciphertext-length refusal | SoftHSM; `openssl(1)` for OAEP; skips missing prerequisites |
| `broker-decrypt` | Distinct internal decryption failures produce the same external error; grant budget counts attempts | SoftHSM, otherwise skips |
| `broker-regrant` | Reacquisition on a live impl session rejects intervening operations, discards login and verifies subsequent signatures against the new certificate; expiry clock behavior | SoftHSM with RSA and EC, otherwise skips |
| `impl-dbus` | All methods and both `Close()` methods reject strangers; app-id binding, non-increasing identity, path reuse, malformed options, result types, internal token-presence vardict, no `Decrypt`, shutdown reasons, queued calls from replaced frontend and frontend loss | Private `GTestDBus` |
| `cancellation` | In-flight login keeps worker PIN intact and answers once after completion; cancellation before UI and during device work; abandoned success logs out, normal success does not; one cancelled waiter leaves shared prompt alive | Display for some cases, SoftHSM for others; run under ASan |
| `module` | DigestInfo accepted spellings and malformed inputs, TLS 1.0/1.1 concatenation refusal, DER length/tag bounds, mechanism list intersection, three synthetic objects, sensitive and public attributes in one template, size queries and small buffers, ID/template matching, search intent, refusal fingerprints ignoring `CKA_CLASS`, URI contract | No bus |
| `module-portal` | Installed shared object's function table and D-Bus client: chooser lock release, finalization and reinitialization during waits, late replies, refused requests, shared chooser, session closure, timeout cancellation and caller-provided lengths | Mock portal on private `GTestDBus` |
| `fuzz-der` | Corpus replay of TLV, DigestInfo, certificate objects and hostile attribute templates in `fixtures/fuzz-corpus` | Always built; sanitizers only when configured |
| `tools-lib` | Effective per-interface `portals.conf` resolution across config directories, preservation of `none`, Certificate override, private-only Secret disabling; fixture marker, symlink, ancestor ownership and mode checks | No hardware |
| `pin-system` | Prompt selection and supplied display fields; no remember/new-password choice; wrong-PIN warning on the same prompt; empty PIN refusal; three-attempt cap; cancel and external close; shell cancel after submission; prompter loss during open/password/confirmation; gcr double-completion race; final-try confirmation including protected path; retry flags without invented counts; login timeout and abandonment; null-PIN path without password rounds | gcr-4; scripted prompter on private `GTestDBus`, no operator shell or display |

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

On `experimental/integration`, `tests/templates/certificate.py` supplies a python-dbusmock
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

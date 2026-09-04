# Tests

**What is here now**, all of it run by `meson test -C build`:

| Suite | What it covers | Needs |
|---|---|---|
| `filter` | the purpose rules and `certificate_filter`, against seven real certificates in `fixtures/` | nothing |
| `mechanism` | the portal-mechanism-to-`CKM_*` mapping, its parameter validation, the DigestInfo construction, the `MGF1-<hash>` spelling **and everything it rejects**, a mismatched `mgf1_hash`, every optional string parameter refused when it is present with the wrong type, the `CK_RSA_PKCS_OAEP_PARAMS` mapping and the per-operation mechanism split, and the raw-to-DER ECDSA re-encoding | nothing |
| `chooser` | the consent window's display helpers, which is where a hostile desktop-file `Name=` or a hostile card label would do its work: no second line, no ANSI escape, no direction override, everything capped, "expired" carried as a **word** | nothing |
| `redact` | that no `pkcs11:` URI, `pin-value` or `pin-source` survives the redactor, and that caller-supplied text cannot draw chrome | nothing |
| `broker-device` | `C_OpenSession`, `C_Login`, `C_Sign` and a verification of the signature against the certificate the token returned, for RSA PKCS#1 v1.5, RSA-PSS and ECDSA; an **RSA-OAEP round trip** against a ciphertext `openssl pkeyutl` produced; a ciphertext of the wrong length refused before the card is asked; the wrong PIN reported as `PIN_INCORRECT`; discovery without logging in | a SoftHSM fixture, or it **skips itself**; `openssl(1)` for the OAEP half |
| `broker-decrypt` | the two properties that make `Decrypt` safe to offer: two different internal failures reported to the caller in identical words, and the per-grant decryption budget spent by attempts rather than successes | a SoftHSM fixture, or it **skips itself** |
| `broker-regrant` | a second `AcquireCredential` on a live session, all the way through the broker: the operation between the two grants is refused rather than signed with the old grant's key, the login does not carry over, and the signature afterwards **verifies against the new certificate** | a SoftHSM fixture with both an RSA and an EC key, or it **skips itself** |
| `impl-dbus` | the D-Bus boundary on a private `GTestDBus`: a stranger calling every method **including `Request.Close()` and `Session.Close()`**, a session used with the wrong `app_id`, an identity level trying to rise, a session path reused after close, sixteen malformed option sets, `Decrypt` taking `RSA_OAEP` only, the token-presence vardict carrying exactly two keys, the shutdown reason being one the interface names, the D-Bus type of every key in the results vardict, a frontend **replaced while its call is already in the backend's queue** (the race is reproduced, not waited for), and the frontend vanishing while a call is in flight | nothing |
| `pin-system` | the OTHER PIN prompt: the whole prompt state machine driven against gcr's own system prompter, stood up on a private `GTestDBus` bus by `pin-prompter.c` so that nothing reaches the operator's shell. `--pin-prompt=auto` resolving to `system` because the name is on the bus; the application, purpose, token and reader reaching the prompt; **no "remember" choice, ever**; a wrong PIN coming back as a warning on the prompt that is already up rather than a second prompt; the three-attempt cap; cancel from the prompter and `Request.Close()` from outside; the `FINAL_TRY` second confirmation **and that refusing it leaves the card unasked**; the token's flags in the warning **with no number in it**; the login timeout and the abandon that follows it; a protected-authentication-path token asking for nothing at all. It is the only place any of those rules is checked without a person at a keyboard | nothing; skipped entirely in a build without gcr-4 |
| `cancellation` | cancelling while `C_Login` is in flight — the answer must wait for the worker, arrive once, and find the PIN buffer intact — cancelling before the window is up, cancelling **while the device call is in progress**, a cancelled login that succeeded anyway being logged out again (and a normal one not being), and one of two callers behind a shared PIN window cancelling **on its own** while the window stays up for the other. **Run it under ASan**; see `../docs/TESTING.md` | a display for four of the six, a SoftHSM fixture for two |

and outside `meson test`, because they need a bus and a display:

| | |
|---|---|
| `../tools/dev-stack.sh` | a real frontend and a real backend on a private bus, and the end-to-end client against them |
| `../tools/ui-smoke.sh` | the same **with the windows**, in a headless X server, driven by `xdotool`. The only automated test that opens the chooser and the PIN prompt. `--pin-prompt=system` runs the whole stack through the system-prompt path instead, with `certificate-test-prompter` owning the prompter name on the private bus |

`../docs/TESTING.md` has the commands, including the ones that need a card and the sanitized build
(`meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false`). The cancellation suite
is the one that needs it: a lifetime bug on a cancel path passes every assertion on a lucky
allocator.

The fixture certificates are generated by `certtool` and checked in as PEM, because a test that
regenerates its own inputs cannot fail when the parser changes. They are: `client-auth-rsa`,
`email-ec`, `no-eku-rsa` (no extended key usage extension *at all*, which is a different fact from
an empty one), `server-auth-only`, `encipherment-only`, `expired-client-auth` and `not-yet-valid`.

The rest of this file is the plan the tests were written against, kept because the items still
marked "not written" are the ones that matter next.

**Half of tier 1 already exists, in the frontend's repository.** The xdg-desktop-portal branch
`experimental/certificate-webauthentication` ships `tests/templates/certificate.py` (a
python-dbusmock backend) and `tests/test_certificate.py` (40 passing cases, each run once as
`AppInfoHost` and once as `AppInfoFlatpak`), covering the happy path, cancellation from both
directions, five invalid-option cases, backend over-claiming being clamped, and the experimental
gate. Everything below that says "the frontend against a fake backend" is that suite. What is left
for this repository is the other direction — **this backend against a fake frontend** — plus
everything that needs a card.

Three tiers, in the order they become possible.

## 1. Offline, no hardware, runs in CI

Everything that does not need a card. This tier should be large, because most of the security
argument lives in it.

- **Interface conformance.** Request and session object paths built exactly as documented, so a
  caller can subscribe before calling; `handle_token` and `session_handle_token` handling; exactly
  one terminal `Response` per request; `Close()` producing no later success; unknown options
  rejected rather than ignored.
- **The frontend against a fake backend.** *Upstream's, and largely written* — see above. What it
  does not yet cover, and the branch says so: `TokenAdded`/`TokenRemoved`/`GrantInvalidated`
  forwarding, the `SessionInvalidated` → `GrantInvalidated` conversion, and selection memory being
  read back on a second `AcquireCredential`.
- **This backend against a fake frontend.** *Still not written as a suite*, and it is now the most
  valuable missing piece: that a sender which does not own `org.freedesktop.portal.Desktop` is
  refused; that the `app_id` and `app_identity_level` the backend was given are the ones it
  renders, with no display name invented from anything the caller supplied; that the
  caller-supplied `reason` never reaches the trusted identity position. The **sanitising** half of
  that last one is covered by `test-redact.c`; the **rendering** half is only covered by looking at
  the window.
- **Backend discovery**, from this side: that the installed `.portal` file names the interface the
  installed binary actually implements, and that `tools/dev-stack.sh` gets from a cold private bus
  to "Providing portal org.freedesktop.portal.experimental.Certificate". *Done, by
  `tools/dev-stack.sh` itself, though nothing asserts on the log line yet.* `portals.conf`
  precedence is upstream's to test.
- **Filter logic** (`src/tokens/filter.h`) against fixture certificates: EKU, key usage, issuer DN
  matching, PIV slot, key algorithm. Plus the two non-negotiable rules — expired certificates are
  *offered and marked*, and a single candidate still gets a chooser. *Done, `test-filter.c`, except
  the second rule, which is true by construction: there is no code path that skips the chooser.*
- **Redaction** (`src/redact.h`). The important test is the negative one: a fixture library error
  string carrying a `pkcs11:` URI with a `pin-value` attribute must be truncated before the URI, and
  no logging entry point may accept a free-form format string. *Done, `test-redact.c`.*
- **Grant lifetime state machine.** The frontend's, not this backend's: owner release,
  `expires_at`, renewal refusing to expand permissions, one atomic terminal state, idempotent
  release. What is testable here is that `Session.Close()` tears down the device state exactly once.
- **Consent policy table** — which purpose requires per-operation consent, and that `decrypt` is
  never covered by a `client_auth` grant. *Not written, and not implemented either: consent is
  currently per grant for every purpose, with the PIN prompt at first use. Per-operation consent for
  `signing` is a gap, not a decision.*
- **Mechanism parameter validation**, above all RSA-PSS hash/MGF/salt combinations, including
  mismatched and out-of-range values. *Done, `test-mechanism.c`.*

## 2. Facade hostility tests (a software token is enough)

**Blocked on there being a facade to test.** `OpenPkcs11Endpoint` is on neither interface — the
frontend branch deferred it — so nothing can reach `src/export/facade.h`. Kept because this list is
the acceptance criteria for that follow-up.

Against `src/export/facade.h`, driven by a deliberately hostile PKCS#11 client. Every one of these
must be **refused**, and each is a test rather than a comment:

`C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_SetAttributeValue`, `C_GenerateKey`,
`C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`, `C_SeedRandom`, `C_InitToken`,
`C_InitPIN`, `C_SetPIN`, SO login, `CKF_RW_SESSION`, a fabricated object handle, a handle belonging
to another grant, `C_FindObjects` with a template matching everything, `C_GetAttributeValue` for
sensitive attributes, a mechanism outside the allow-list, and operation-state export/import.

Plus: the **PKCS#11 v3 `C_GetInterface`** path is filtered as thoroughly as `C_GetFunctionList` —
filtering only the v2 table leaves an unfiltered way back in — and the RPC surface is **fuzzed**.

## 3. Hardware, run by a human

Not CI. These need real cards, real readers, and a card the author is willing to block. They are the
publication gates in [../docs/ROADMAP.md](../docs/ROADMAP.md) and the spikes in
[../docs/SPIKES.md](../docs/SPIKES.md):

- one real GnuTLS mutual-TLS handshake through brokered `Sign`;
- one real WebKitGTK client-certificate handshake (joint with `xdg-desktop-portal-webauth`);
- wrong PIN, and the final retry, with the count only shown when the token reports it;
- a protected-authentication-path reader, with no PIN field drawn;
- card removal during signing, between `C_SignInit` and `C_Sign`, and during the PIN prompt;
- reinsertion of the same card, and of a different card with the same label in the same slot;
- two readers, two cards, two concurrent grants;
- caller disconnect mid-handshake with a delegated subprocess still connected.

Tier 1's fake backend and fake frontend are the two most valuable pieces of test infrastructure in
the project. The fake backend exists, upstream, in `tests/templates/certificate.py`; the fake
frontend still does not exist and is the next thing to write here. Everything about the split that could be wrong
is cheap to test with them and expensive to discover with a card in a reader.

**A test that has only been run against a software token has not been run.** The Remmina work this
project builds on found every one of its edge cases on hardware, and none of them was predictable
from the specification.

# Tests

There are none **here**, because there is no implementation here. This file records what the tests
will have to be, so that the design is written with them in mind rather than retrofitted around
them.

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
- **This backend against a fake frontend.** The half nobody has written. That a sender which does
  not own `org.freedesktop.portal.Desktop` is refused; that the `app_id` and `app_identity_level`
  the backend was given are the ones it renders, with no display name invented from anything the
  caller supplied; that the caller-supplied `reason` never reaches the trusted identity position.
- **Backend discovery**, from this side: that the installed `.portal` file names the interface the
  installed binary actually implements, and that `tools/dev-stack.sh` gets from a cold private bus
  to "Providing portal org.freedesktop.portal.experimental.Certificate". `portals.conf` precedence
  itself is upstream's to test.
- **Filter logic** (`src/tokens/filter.h`) against fixture certificates: EKU, key usage, issuer DN
  matching, PIV slot, key algorithm. Plus the two non-negotiable rules — expired certificates are
  *offered and marked*, and a single candidate still gets a chooser.
- **Redaction** (`src/redact.h`). The important test is the negative one: a fixture library error
  string carrying a `pkcs11:` URI with a `pin-value` attribute must be truncated before the URI, and
  no logging entry point may accept a free-form format string.
- **Grant lifetime state machine.** The frontend's, not this backend's: owner release,
  `expires_at`, renewal refusing to expand permissions, one atomic terminal state, idempotent
  release. What is testable here is that `Session.Close()` tears down the device state exactly once.
- **Consent policy table** — which purpose requires per-operation consent, and that `decrypt` is
  never covered by a `client_auth` grant.
- **Mechanism parameter validation**, above all RSA-PSS hash/MGF/salt combinations, including
  mismatched and out-of-range values.

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
frontend does not and should be written first here. Everything about the split that could be wrong
is cheap to test with them and expensive to discover with a card in a reader.

**A test that has only been run against a software token has not been run.** The Remmina work this
project builds on found every one of its edge cases on hardware, and none of them was predictable
from the specification.

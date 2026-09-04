# Tests

There are none, because there is no implementation. This file records what the tests will have to
be, so that the design is written with them in mind rather than retrofitted around them.

Three tiers, in the order they become possible.

## 1. Offline, no hardware, runs in CI

Everything that does not need a card. This tier should be large, because most of the security
argument lives in it.

- **Interface conformance.** Request and session object paths built exactly as documented, so a
  caller can subscribe before calling; `handle_token` and `session_handle_token` handling; exactly
  one terminal `Response` per request; `Close()` producing no later success; unknown options
  rejected rather than ignored.
- **The frontend against a fake backend.** A test backend that implements the impl interface and
  can be told to misbehave. This tier should be large, because it is where the split earns its
  keep: that `app_id` is derived once and passed as an argument; that a backend returning a longer
  `expires_at`, extra mechanisms, or operations the purpose forbids is **clamped and logged**, not
  believed; that `Close()` reaches the backend's `Request` before the caller is told anything; that
  a backend vanishing invalidates every grant with `backend_gone`; that a caller naming another
  caller's session gets `NotPermitted` and no hint about whether the path existed.
- **The backend against a fake frontend.** That a sender which does not own the frontend's
  well-known name is refused; that the app id and identity level the backend was given are the ones
  it renders; that caller-supplied `reason` and `context` never reach the trusted identity
  position.
- **Backend discovery.** `.portal` file parsing, `portals.conf` precedence including
  `DESKTOP-portals.conf`, `none`, `*`, a named backend that is not installed, and the documented
  fallback order.
- **Permission store.** Resource-id construction; that an unverified or empty app id never keys an
  entry; that a stored selection preselects and never suppresses the chooser or the PIN.
- **Filter logic** (`backends/gtk/src/tokens/filter.h`) against fixture certificates: EKU, key usage, issuer DN
  matching, PIV slot, key algorithm. Plus the two non-negotiable rules — expired certificates are
  *offered and marked*, and a single candidate still gets a chooser.
- **Redaction** (`shared/redact.h`). The important test is the negative one: a fixture library error
  string carrying a `pkcs11:` URI with a `pin-value` attribute must be truncated before the URI, and
  no logging entry point may accept a free-form format string.
- **Grant lifetime state machine.** Owner release, all-holders-gone, orphan grace expiry,
  `expires_at`, renewal refusing to expand permissions, one atomic terminal state, idempotent
  release.
- **Consent policy table** — which purpose requires per-operation consent, and that `decrypt` is
  never covered by a `client_auth` grant.
- **Mechanism parameter validation**, above all RSA-PSS hash/MGF/salt combinations, including
  mismatched and out-of-range values.

## 2. Facade hostility tests (a software token is enough)

Against `backends/gtk/src/export/facade.h`, driven by a deliberately hostile PKCS#11 client. Every one of these
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
- one real WebKitGTK client-certificate handshake (joint with `webauth-service`);
- wrong PIN, and the final retry, with the count only shown when the token reports it;
- a protected-authentication-path reader, with no PIN field drawn;
- card removal during signing, between `C_SignInit` and `C_Sign`, and during the PIN prompt;
- reinsertion of the same card, and of a different card with the same label in the same slot;
- two readers, two cards, two concurrent grants;
- caller disconnect mid-handshake with a delegated subprocess still connected.

Tier 1's fake backend and fake frontend are the two most valuable pieces of test infrastructure in
the project and should be written first: everything about the split that could be wrong is cheap to
test with them and expensive to discover with a card in a reader.

**A test that has only been run against a software token has not been run.** The Remmina work this
project builds on found every one of its edge cases on hardware, and none of them was predictable
from the specification.

# 7. Brokered operations are the core; the PKCS#11 facade is compatibility

Date: 2026-09-03
Status: accepted (for the sketch)

## Context

[0006](0006-failure-modes-of-naive-p11kit-forwarding.md) established that handing a consumer a
forwarded PKCS#11 module does not scope anything, and that real scoping needs a synthetic facade the
broker implements. That leaves the question of which one is the **contract** and which is the
concession.

Two shapes were on the table.

**A module endpoint as the contract.** Existing TLS stacks consume it unchanged. That is a large
adoption advantage and it was the original design.

**Brokered operations as the contract.** `AcquireCredential` returns a grant; `Sign` and optionally
`Decrypt` perform the work in the service. Consumers need integration work.

## Decision

**Credential selection plus brokered operations is the core contract. The PKCS#11 facade is an
experimental compatibility transport, requested explicitly, delivered in a later milestone.**

### Why the broker wins on security

A module endpoint hands over a **generic cryptographic interface whose calls carry almost no
trustworthy semantic context**. Once a client holds a sign-capable PKCS#11 session, "client
authentication" is indistinguishable from arbitrary signing, and the grant becomes a standing
capability rather than a sequence of events.

Brokered operations can enforce what a session cannot:

- **per-operation consent**, where the purpose demands it — `signing` shows what is being signed;
- **precise accounting**: an operation counter, a single-use option, rate limits;
- **revocation that takes effect immediately**, including mid-handshake;
- **mechanism allow-listing with parameter validation** — RSA-PSS hash, MGF and salt length checked
  against the mechanism and the key rather than forwarded;
- **auditability**: who signed what, when, under which grant, without logging the content;
- **policy** that can change without a client-side module reload.

### What the broker does not buy

**It does not attest purpose.** A `Sign(data)` call cannot prove its input came from a TLS handshake.
The caller can lie about anything the caller supplies. The broker's advantage is accounting, policy,
revocation and consent — **not** semantic attestation. Anyone who reads `purpose` as a guarantee has
misread it, and the interface says so in those words.

### Why the facade still has to exist

Because the reach argument from [0001](0001-mediate-via-scoped-pkcs11-forwarding.md) is still true.
GnuTLS, NSS and OpenSSL want a `CK_FUNCTION_LIST`, and asking every consumer to restructure its TLS
code around a D-Bus signing call is asking for adoption that will not come. The facade is how a
consumer that cannot integrate gets served — at the cost of a security-sensitive PKCS#11
implementation and a weaker per-operation story.

### The split, concretely

- **Core:** `AcquireCredential`, `Sign`, `Decrypt` (later), `RenewGrant`, `ReleaseGrant`,
  `GetCapabilities`, `TokenAdded`/`TokenRemoved`/`GrantInvalidated`.
- **Compatibility:** `OpenPkcs11Endpoint(grant_id, options) → {endpoint_fd, certificate_uri,
  private_key_uri, endpoint_version}`, **experimental**, milestone 2.
- **Never both automatically.** The caller asks for the capability it can actually use, and
  `GetCapabilities` says whether this implementation has it, so callers negotiate instead of probing
  by failing.
- **A URI is not a capability.** `certificate_uri` and `private_key_uri` are returned only *with* an
  endpoint that resolves them, never alone. No `pin-value`, no `pin-source`, ever.
- **The endpoint is a file descriptor, not a path** — a path is discoverable, races on the
  filesystem, and needs a bind mount to cross a sandbox.
- **Build the signing API into the first security model.** Add the module bridge when a demonstrated
  consumer requires it, which for phase 2 means `webauth-service` and only if
  [SPIKES.md](../SPIKES.md) S3 passes.

## Consequences

- **Phase 1 ships without the facade** and is useful only to consumers willing to integrate. That is
  a slower adoption curve, deliberately chosen over a faster one built on a false scoping claim.
- **Firefox and Chromium are not MVP consumers.** "NSS can load PKCS#11" does not make them solved:
  their sandboxing, module lifecycle, browser UI and client-certificate selection paths all differ,
  and each needs explicit integration by its own maintainers. Listing them as beneficiaries is
  honest; listing them as consumers would not be.
- **The interface has two tiers of stability**, and `GetCapabilities` plus `endpoint_version` exist so
  that the experimental tier can change without breaking the core.
- **This is the ADR to revisit if adoption stalls.** If nobody will integrate a signing call, the
  facade stops being a concession and becomes the product — and the security model gets worse in a
  way that must then be documented rather than quietly accepted.

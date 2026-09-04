# 6. Failure modes of naive p11-kit forwarding

Date: 2026-09-03
Status: accepted (for the sketch) — this decision **corrects** [0001](0001-mediate-via-scoped-pkcs11-forwarding.md)

## Context

This project's founding claim was:

> The service returns a PKCS#11 endpoint **scoped to the granted certificate and key**, already
> logged in, produced with p11-kit's remote-module mechanism (`p11-kit server` exporting a module
> over a Unix socket, `p11-kit-client.so` loading it in the consumer). Consumers' existing TLS stacks
> then work unchanged.

**That claim is false**, and an independent review took it apart. This ADR records the ten failure
modes, because they are the reason the architecture changed and because a future contributor will
otherwise rediscover the original idea and think it obvious.

## The ten failure modes

**1. Stock p11-kit exposes the selected *token*, not the selected *object*.**
`p11-kit server` accepts one or more **token** URIs — `p11-kit server --provider /path/module.so
pkcs11:token=…` — and the implementation installs a token filter. There is no documented
certificate-or-key object capability. On a PIV card, "scoped to the token" means the whole card.
[p11-kit manual](https://p11-glue.github.io/p11-glue/p11-kit/manual/p11-kit.html),
[server.c](https://github.com/p11-glue/p11-kit/blob/master/p11-kit/server.c).

**2. The consumer, not the service, owns the forwarded sessions.**
TLS libraries open their own sessions and call `C_Login` when the private key is used. A session the
chooser service opened and logged into is not the session created later across a new remote
connection.

**3. Pre-login is not a portable delegation mechanism.**
PKCS#11 defines login state as shared among the sessions of **an application**, not universally
across arbitrary applications or module instances. Whether a particular card or driver caches login
device-wide is implementation behaviour and must never become an API contract.
[PKCS#11 v3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html).

**4. A standard remote module is still a general PKCS#11 interface.**
p11-kit's own remoting documentation demonstrates forwarded tokens being used to generate and copy
objects. **Transport does not impose policy.** Rejecting dangerous entry points and constraining
searches, handles, mechanisms and sessions requires a separate filtering module.
[p11-kit remoting](https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html).

**5. Runtime module discovery may simply fail.**
A PKCS#11 URI identifies a token or object. It cannot name a Unix socket and it cannot register a
provider. The documented GnuTLS/OpenSSL path needs `p11-kit-client.so` configured **plus**
`P11_KIT_SERVER_ADDRESS` — process-level configuration, poorly matched to per-request grants.

**6. WebKit's TLS may happen in another process.**
Setting an environment variable, or registering a module, after WebKit's network process has started
may have no effect there. Handing over a `GTlsCertificate` object does not prove a fresh provider
can be found later, in a different process, when the key is actually used.

**7. Caller lifetime cannot simply mean D-Bus lifetime.**
The PKCS#11 client may be a browser network subprocess with its own socket connection. Killing the
grant when the UI process's D-Bus connection disappears can terminate a valid handshake; keeping it
alive for the subprocess permits use after the initiating request ended.

**8. Multiple simultaneous grants collide.**
`p11-kit-client.so` conventionally finds one endpoint through one `P11_KIT_SERVER_ADDRESS`. Two
certificates, two origins or two concurrent requests in one process need either several dynamically
loaded module instances or a multiplexing broker with grant-aware virtual slots.

**9. Token-scoped forwarding defeats the consent claim.**
A PIV card holds authentication, signing, key-management and card-authentication keys. If the
consent dialog says "this certificate" and the endpoint exposes the token, the dialog is lying.

**10. `purpose` is not enforceable through ordinary forwarding.**
A service cannot determine that a `C_Sign` is part of a TLS handshake rather than a PDF signature or
arbitrary data. EKU and key usage constrain certificate **selection**; they prove nothing about the
semantics of later operations. This one is not fixed by the facade either — it is fixed by saying so,
everywhere `purpose` appears.

## Decision

**Do not ship token-scoped forwarding described as object scoping.** State plainly, in the README,
the interface documentation and the introspection XML, that stock forwarding is **insufficient
isolation**.

Object and operation scoping requires a **broker-controlled synthetic PKCS#11 facade**: one synthetic
slot and token, only the granted leaf certificate and keys and explicitly selected chain
certificates, synthetic handles mapped to broker-owned handles, read-only sessions only, no SO login,
refusal of `C_InitToken`/`C_InitPIN`/`C_SetPIN`/`C_CreateObject`/`C_CopyObject`/`C_DestroyObject`/
`C_SetAttributeValue`/key generation/wrap/unwrap/derivation/RNG seeding/operation-state export, a
mechanism allow-list with parameter validation including RSA-PSS, rate limits, invalidation on
removal and expiry, and filtering of the **PKCS#11 v3 interface tables** as well as the v2 function
list.

**That facade is substantial, security-sensitive engineering — not plumbing.** It is a PKCS#11
implementation facing a hostile peer over a wire protocol, it belongs in its own process, and it is
the first thing that should be fuzzed. It is budgeted at 5–9 person-weeks on its own in
[ROADMAP.md](../ROADMAP.md).

## Consequences

- The core contract moves to brokered operations: [0007](0007-brokered-operations-are-the-core.md).
- The facade becomes an **experimental, opt-in, milestone-2** feature behind `OpenPkcs11Endpoint` and
  `GetCapabilities`.
- [SPIKES.md](../SPIKES.md) S1 and S3 exist to test failure modes 1–6 and 8 before anything is built.
- Failure mode 7 rewrote the lifetime model into owner-plus-delegated-holders.
- Failure mode 10 has no technical fix and appears as an honesty requirement in
  [INTERFACE.md](../INTERFACE.md), [SECURITY.md](../SECURITY.md) and the XML.
- Failure mode 6 is why S3 is the gate on publishing this repository at all, and why the likely real
  architecture is **one permanently registered broker module with synthetic grant-bound slots**
  rather than a new module per grant.

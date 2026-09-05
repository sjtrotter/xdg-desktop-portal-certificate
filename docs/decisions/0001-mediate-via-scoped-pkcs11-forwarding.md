# 1. Mediate credential use — and what "scoped" has to mean

Date: 2026-09-03
Status: **superseded in part** by [0006](0006-failure-modes-of-naive-p11kit-forwarding.md) and
[0007](0007-brokered-operations-are-the-core.md)

## Context

The founding idea of this project was an analogy. `org.freedesktop.portal.Camera` does not hand an
application `/dev/video0`; it hands back a
[PipeWire remote file descriptor](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Camera.html)
[[S38](../SOURCES.md)] and the application's ordinary media stack works. So: do not hand an
application the card. Hand it
something *scoped*, and let its ordinary TLS stack work.

The alternative considered was a **signing API** — the service holds the key and the application
asks for signatures — and it was initially rejected, on the grounds that it breaks every consumer.
GnuTLS, NSS and OpenSSL do not want a signature; they want a `CK_FUNCTION_LIST` they can drive
through a handshake with the exact mechanism, padding and message that handshake requires. A signing
API means reimplementing the PKCS#11 half of each TLS stack, per stack, and being wrong about
RSA-PSS parameters, TLS 1.3 `CertificateVerify` contexts and ECDSA encoding forever.

That reasoning about *reach* was right. The conclusion drawn from it was wrong, in two ways that an
independent review found.

## What was wrong

The original decision assumed the scoped thing could be produced by
[p11-kit's remoting mechanism](https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html) —
`p11-kit server` exporting a certificate-and-key-scoped, already-logged-in module. **It cannot.**
`p11-kit server` takes **token** URIs; its unit of exposure is a token [[S1](../SOURCES.md)]. It
forwards the general PKCS#11 interface, including object creation and key generation
[[S2](../SOURCES.md), [S4](../SOURCES.md)]. Login state does not cross the boundary
[[S14](../SOURCES.md)]. And `p11-kit-client.so` is found through process-level configuration —
`P11_KIT_SERVER_ADDRESS`, or a `server-address:` field in a `.module` file, both read once at
module initialisation — which does not accommodate concurrent per-request grants
[[S3](../SOURCES.md)]. The ten failure
modes are in [0006](0006-failure-modes-of-naive-p11kit-forwarding.md).

The second error was treating "a module endpoint" as strictly safer than "a signing API". It is not.
A sign-capable PKCS#11 session **is** a signing capability, with less accounting: it cannot be
counted, expired per operation, consented to per operation, or revoked mid-handshake as cleanly.
The security advantage runs the *other* way; the module's advantage is reach.

## Decision

**Mediate rather than hand over** — that part stands, and it is the analogy that still holds. Refine
it into two statements:

1. **The core contract is credential selection plus brokered operations.** The service selects, the
   service holds the key, the service signs. [0007](0007-brokered-operations-are-the-core.md).
2. **Any PKCS#11 surface is a broker-controlled synthetic facade**, requested explicitly by a
   consumer that needs it, never the real token forwarded, and never described as scoped unless it
   actually enforces object and operation scoping at every entry point.

"Scoped" is a claim about enforcement, not about a command line. A design that hides objects during
enumeration and forwards everything else is not scoped; it is a filtered directory listing on a
shared drive.

## Consequences

- The Camera analogy survives but is weaker than it looked: PipeWire is a mediation layer designed
  for mediation, and PKCS#11 is a device API designed for the device's owner to use.
- The project is larger. The facade is a security-sensitive PKCS#11 implementation, not plumbing.
- The reach argument is now a *milestone*, not a foundation. Phase 1 ships brokered signing, which
  works for consumers willing to integrate; phase 2 attempts the facade, which works for consumers
  that cannot.
- The interface reflects the split: `Sign` is core, `OpenPkcs11Endpoint` is opt-in and experimental,
  and `GetCapabilities` exists so callers do not probe by failing.

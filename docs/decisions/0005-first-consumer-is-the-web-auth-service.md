# 5. The first consumer is the web authentication service

Date: 2026-09-03
Status: accepted (for the sketch)

## Context

A service like this needs a consumer before it needs a specification. Without one it is an interface
nobody has had to implement against, which is how APIs acquire features no user needs and miss the
one thing every user needs.

The available candidate is `webauth-portal` — the sibling design sketch in the author's
`entra-token-helper` repository (working title `webauth-portal`; the repository itself is still
named `entra-token-helper`), interface `io.github.sjtrotter.portal.WebAuthentication1` on the same
`io.github.sjtrotter.portal.Desktop` bus name this project's own frontend claims. Like this project,
it has restructured into a portal frontend (`webauth-portal-frontend`) and a portal backend
(`webauth-portal-gtk`); it is the **backend** that performs one interactive web authentication
transaction in a WebKitGTK window it owns, and therefore the backend that calls this service, as an
ordinary client of this service's public interface. Entra ID sign-in on a smart-card tenant redirects
to `certauth.<authority>`, which challenges for a TLS client certificate that lives on a PIV card. It
has that requirement today, from real hardware, in a real tenant.

It is also the project that would otherwise have had to build this. Its own
`docs/decisions/0007-certificate-adapter.md` is the mirror of this decision, made from the other
side: choosing a certificate and unlocking it
with a PIN is not a *web* problem, and putting the only good implementation inside a web
authentication service reproduces one layer up exactly the situation both projects exist to end.

## Decision

**`webauth-portal`'s GTK backend, `webauth-portal-gtk`, is the first and, for phase 1, only
consumer.** The interface is designed against its needs, and the two sketches are written in
parallel so the protocol between them is negotiated while both are still cheap to change.

Concretely, it calls `AcquireCredential` with `purpose: client_auth`, the issuer list from the TLS
`CertificateRequest`, and the challenging origin in `context`; it uses **brokered `Sign`** where its
TLS stack permits, and the experimental `OpenPkcs11Endpoint` where it does not; and it releases the
grant — that is, closes the `Session` that is the grant — on every exit path.

**It keeps its in-process certificate handling behind an internal adapter until
[SPIKES.md](../SPIKES.md) S3 passes.** Neither project may become a hard dependency of the other
before there has been one real WebKitGTK client-certificate handshake through this service. Until
then this repository is an experiment, not a dependency.

## What this consumer proves, and what it does not

**Proves:** that a service-owned chooser and PIN prompt can serve an application that is not the one
the code was written in; that the grant lifetime model survives a real handshake; and — through S3 —
whether the module-loading path works at all, which is the single most valuable thing any consumer
could establish.

**Does not prove:** that the interface is general. One consumer is not evidence of a reusable
interface, and a consumer that is a sibling project by the same author is weaker evidence still.
Phase 3 requires a second, unrelated consumer before anything is proposed upstream, and that
requirement exists precisely because this one does not count for much.

## Open problem: delegation

`webauth-portal-gtk` asks on behalf of an RDP client, which asked on behalf of a user. This service
sees only its immediate D-Bus peer — and now that both projects have restructured into a
frontend/backend shape, that peer is unambiguously the *backend* process, not some single
`webauth-service`.

Version 1 shows the immediate peer and **nothing else**, honestly: the dialog names
`webauth-portal-gtk`, not Remmina. That is worse for the user, who cares about Remmina, and it is the
only thing the service can actually verify. Passing an **attested** original caller through one hop
is a protocol neither project has, and inventing one that amounts to "the caller told us who its
caller was" would be worse than the honest version — it would put unverifiable text in the trusted
identity position, which [SECURITY.md](../SECURITY.md) forbids.

`webauth-portal`'s own window names the origin and its own caller, so between the two windows the
user has the information. That is a mitigation, not a solution while the two portals run as separate
processes.

**The resolution, once both are in portal shape, is a shared frontend.** With both sketches now
built to the upstream shape, one process hosting both `io.github.sjtrotter.portal.Smartcard1` and
`io.github.sjtrotter.portal.WebAuthentication1` — the proposed `incubating-portal-frontend`, see
[0008](0008-build-to-the-upstream-shape.md) — already holds the app id it derived for the web
authentication request before it ever calls into the smart-card side, so it can pass that *original*
`app_id` through in-process instead of as the untrusted `reason` text a cross-process call is limited
to today. **That only holds because the two portals then run in one trusted process.** Across two
processes — this service and a separately-running `webauth-portal-frontend` — passing an app id
across the boundary would need attestation neither project has, and doing it without attestation
would be exactly the identity-laundering this document lists as forbidden above. It is not to be
done that way. Until the shared frontend exists, this remains an open problem rather than a design.

## Consequences

- **A hard packaging dependency in one direction, deferred.** Once S3 passes, AVD sign-in with a PIV
  card requires this service to be installed. The failure is clean — the challenge is declined and
  the transaction ends with `certificate_service_unavailable` — but it is a failure, and there is
  deliberately no built-in fallback chooser on the other side.
- **Two spikes instead of one**, and S3 is joint. Neither project can finish it alone.
- **A protocol to agree between two sketches** — the option names, the scoping guarantees, the grant
  lifetime, the delegation question. Negotiating it now, between two documents, is the cheapest it
  will ever be.
- **Trust flows both ways.** This service decides whether `webauth-portal-gtk` may ask for a
  certificate at all; and `webauth-portal-gtk` must pass through enough about its own caller for that
  decision to be made as honestly as the delegation problem allows.

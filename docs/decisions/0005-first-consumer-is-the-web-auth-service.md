# 5. The first consumer is the web authentication service

Date: 2026-09-03
Status: accepted (for the sketch), amended by [0010](0010-backend-only-frontend-lives-upstream.md)

## Context

A service like this needs a consumer before it needs a specification. Without one it is an interface
nobody has had to implement against, which is how APIs acquire features no user needs and miss the
one thing every user needs.

The available candidate is the sibling design sketch in the author's `entra-token-helper`
repository, which since [0010](0010-backend-only-frontend-lives-upstream.md) is
`xdg-desktop-portal-webauth`: an out-of-tree backend for
`org.freedesktop.impl.portal.experimental.WebAuthentication`. Its frontend, like this project's,
is the xdg-desktop-portal branch `experimental/certificate-webauthentication`. It is the
**backend** that performs one interactive web authentication transaction in a WebKitGTK window it
owns, and therefore the backend that calls the Certificate portal, as an ordinary client of the
public `org.freedesktop.portal.experimental.Certificate` interface on
`org.freedesktop.portal.Desktop`. Entra ID sign-in on a smart-card tenant redirects
to `certauth.<authority>`, which challenges for a TLS client certificate that lives on a PIV card.
It has that requirement today, from real hardware, in a real tenant — an observation from this
project's own runs ([TESTING.md](../TESTING.md) §2.55 and the live sign-in of 2026-09-05), not a
documented behaviour anyone else has verified here.

It is also the project that would otherwise have had to build this. Its own
`docs/decisions/0007-certificate-adapter.md` is the mirror of this decision, made from the other
side: choosing a certificate and unlocking it
with a PIN is not a *web* problem, and putting the only good implementation inside a web
authentication service reproduces one layer up exactly the situation both projects exist to end.

## Decision

**`xdg-desktop-portal-webauth` is the first and, for phase 1, only consumer.** The interface is designed against its needs, and the two sketches are written in
parallel so the protocol between them is negotiated while both are still cheap to change.

Concretely, it calls `AcquireCredential` with `purpose: client_auth` and the issuer list from the
TLS `CertificateRequest`; it uses **brokered `Sign`** where its TLS stack permits; and it releases
the grant — that is, closes the `Session` that is the grant — on every exit path.

> **Amendment (0010).** Two details of that sentence were overtaken by the branch's XML. There is
> no `context` option: the challenging origin can only travel in `reason`, which is
> application-supplied text and is displayed as such. And `OpenPkcs11Endpoint` is not in the
> interface at all — it was deliberately deferred as a follow-up, so brokered `Sign` is currently
> the only path, and the consumer has no endpoint to fall back to.

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

> **Largely resolved (0010).** Both interfaces now live in one frontend process —
> xdg-desktop-portal, on one branch — which is exactly the "shared frontend" resolution this
> section describes as hypothetical below. The frontend derives the app id once for the web
> authentication request and holds it in-process; nothing untrusted touches it in between. The
> caveat below survives unchanged and is the reason this section is kept: the fix works *only*
> in-process, and passing an unattested app id across a bus is still forbidden. What has not been
> written is the code inside the frontend that actually forwards it, so read what follows as the
> problem it was, and the shape of the fix that is now available.

`xdg-desktop-portal-webauth` asks on behalf of an RDP client, which asked on behalf of a user. The
Certificate portal sees only its immediate D-Bus peer, which is that backend process.

Version 1 shows the immediate peer and **nothing else**, honestly: the dialog names the web
authentication backend, not Remmina. That is worse for the user, who cares about Remmina, and it is the
only thing the service can actually verify. Passing an **attested** original caller through one hop
is a protocol neither project has, and inventing one that amounts to "the caller told us who its
caller was" would be worse than the honest version — it would put unverifiable text in the trusted
identity position, which [SECURITY.md](../SECURITY.md) forbids.

The web authentication backend's own window names the origin and its own caller, so between the two windows the
user has the information. That is a mitigation, not a solution while the two portals run as separate
processes.

**The resolution is a shared frontend, and there now is one.** A single process hosting both
`org.freedesktop.portal.experimental.Certificate` and
`org.freedesktop.portal.experimental.WebAuthentication` already holds the app id it derived for the
web authentication request before it ever calls into the certificate side, so it can pass that
*original* `app_id` through in-process instead of as the untrusted `reason` text a cross-process
call is limited to. **That only holds because the two portals run in one trusted process.** Across
two processes, passing an app id across the boundary would need attestation neither side has, and
doing it without attestation would be exactly the identity-laundering this document lists as
forbidden above. It is not to be done that way, ever, and the in-process fix must not be described
as though it generalises.

## Consequences

- **A hard packaging dependency in one direction, deferred.** Once S3 passes, AVD sign-in with a PIV
  card requires this service to be installed. The failure is clean — the challenge is declined and
  the transaction ends with `certificate_service_unavailable` — but it is a failure, and there is
  deliberately no built-in fallback chooser on the other side.
- **Two spikes instead of one**, and S3 is joint. Neither project can finish it alone.
- **A protocol to agree between two sketches** — the option names, the scoping guarantees, the grant
  lifetime, the delegation question. Negotiating it now, between two documents, is the cheapest it
  will ever be.
- **Trust flows both ways.** This backend, and the policy in front of it, decide whether the web
  authentication backend may ask for a certificate at all; and that backend must pass through
  enough about its own caller for the decision to be made as honestly as the delegation problem
  allows.

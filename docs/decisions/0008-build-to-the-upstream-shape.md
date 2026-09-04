# 8. Build to the upstream shape now: a portal frontend and a portal backend

Date: 2026-09-03
Status: accepted (for the sketch), overriding the review advice recorded below

## Context

[0003](0003-own-namespace-before-freedesktop.md) established that this project ships under
a project-controlled name and copies xdg-desktop-portal's *patterns* without claiming its
namespace. Until now that meant one pattern: the `Request` transaction. Everything else was
one process — one service that resolved the caller's identity, applied policy, drew the
chooser, held the PKCS#11 session and performed the signature.

[ARCHITECTURE.md](../ARCHITECTURE.md) argued for that explicitly, and the argument is worth
restating rather than quietly deleting, because it was not a bad one:

> **No frontend/backend split.** There is no `org.freedesktop.impl.portal.*` ABI here.
> Imitating a portal's names confers none of a portal's properties while doubling the D-Bus
> surface, the activation and crash handling, the versioning obligations, the packaging and
> the transaction lifetime bugs. Internally the seam exists — transaction layer →
> chooser/PIN interface → GTK4 implementation — as a C vtable, which is where the split
> goes if it is ever earned.

The review that shaped this repository said the same thing more bluntly: a frontend/backend
split is **premature for v0**, the project has no consumers and no spike results, and the
first thing to do is find out whether the facade can exist at all
([SPIKES.md](../SPIKES.md) S1 and S3). Doubling the process count before answering that is
the classic way to spend a month on plumbing for a design that turns out to be impossible.

The author has decided to do it anyway, and this ADR records that decision, its reasons,
and the costs it accepts.

## Decision

**Build the frontend/backend split now, in the shape xdg-desktop-portal uses, under our own
namespace.**

- `frontend/` owns `io.github.sjtrotter.portal.Certificate` and exports
  `io.github.sjtrotter.portal.Certificate1`. It establishes the caller's app id, validates
  the purpose and options, applies policy, permissions, lifetime ceilings and rate limits,
  owns the `Request` and `Session` objects and the grant registry, selects a backend from
  installed `*.portal` files, and calls that backend with `app_id` attached.
- `backends/gtk/` owns `io.github.sjtrotter.impl.portal.Certificate.gtk` and implements
  `io.github.sjtrotter.impl.portal.Certificate1`. It draws the chooser and the PIN prompt,
  discovers tokens, holds the PKCS#11 session, performs `Sign` and `Decrypt`, and serves
  the experimental facade whose endpoint fd the frontend relays.
- The impl interface is private to the frontend, by the same means upstream uses plus an
  explicit sender check ([IMPL-INTERFACE.md](../IMPL-INTERFACE.md)).
- Names remain ours. **We still do not ship under `org.freedesktop.*`**; 0003 is unchanged.
  [UPSTREAMING.md](../UPSTREAMING.md) maps every name and file to what it would become.

## Why, given the advice against it

**1. Avoid a second rewrite.** The one-process design was not a smaller version of the
portal design; it was a different one. Identity derivation, consent-window ownership, grant
storage and policy all sit on different sides of the line. Doing it later means rewriting
the parts of the system that carry the security argument, at the point where there are
finally users to break.

**2. Exercise the impl boundary early — it is where the security property lives.** The
single most important claim this project makes is that *the window naming an application is
drawn by a process that did not have to guess which application it was*. In one process
that claim is a code-review promise. Across the impl boundary it is a signature:
`AcquireCredential(handle, session_handle, app_id, parent_window, options)`. The backend
cannot derive an app id even by accident, because it is not talking to the application.
Building it now means every subsequent design decision is made with that constraint present
rather than added to it afterwards.

**3. Exercise the permission store early.** Remembered certificate selection belongs in
`org.freedesktop.impl.portal.PermissionStore`, keyed by app id, listed and revoked in the
desktop's own UI. That is only coherent when there is a frontend that owns the app id.
A one-process design would have grown a private store, and a private store the user's
revocation UI cannot see is a worse answer that would have been hard to walk back.

**4. Make the upstream patch a rename rather than a redesign.** [UPSTREAMING.md](../UPSTREAMING.md)
is the test of that claim, and writing it found that roughly half of the frontend is
plumbing xdg-desktop-portal already has — which is a *good* result: it means the portal fits
the plumbing. It also found three things that are not renames (who opens the device,
`Sign` returning a `Request`, `ReleaseGrant` duplicating `Session.Close`), and those are
now questions to ask maintainers rather than surprises to discover during review.

**5. A second desktop stops being a fork.** A KDE chooser and PIN prompt is a second
backend package with its own `.portal` file, selected by `portals.conf`. Under the vtable
plan it was a second implementation inside one binary, which is the arrangement that
produces a GTK service with a neglected Qt code path.

## Costs, accepted with open eyes

Every cost the earlier argument listed is real and is now being paid:

- **Two D-Bus services** to activate, supervise, version and package, plus a third process
  per facade endpoint. Three processes for one signature, in the facade case.
- **A second interface to design, document and keep compatible**, which is the interface
  with the least review and the most churn ahead of it.
- **Transaction-lifetime bugs get a new home.** Two `Request` objects and two `Session`
  objects per interaction; a `Close()` that must reach the backend before the caller is
  told anything; a backend that can die mid-grant, which is why `backend_gone` exists.
- **A round trip on every prompt**, and on every `Sign` — unmeasured, and flagged in
  [UPSTREAMING.md](../UPSTREAMING.md) as something that may force a fast path.
- **The spike results are still unknown.** This does not make S1 or S3 more likely to pass.
  If the facade cannot exist, the split will have been built for a smaller project than the
  one it was designed for — though note that the brokered-`Sign` core, which is what
  survives an S1 failure, needs the split *more* than the facade does, because it is the
  part with the consent dialog in it.
- **Ten fewer person-days on the spike**, roughly, which is a real trade against the one
  thing [SPIKES.md](../SPIKES.md) says matters most.

## Per-project bus names during incubation

Each incubating frontend now claims its own bus name and object path, rather than both
frontends claiming a shared `io.github.sjtrotter.portal.Desktop` stand-in for the real
singleton `org.freedesktop.portal.Desktop`. This project's frontend owns
**`io.github.sjtrotter.portal.Certificate`** at **`/io/github/sjtrotter/portal/Certificate`**,
and exports `io.github.sjtrotter.portal.Certificate1`. The sibling `entra-token-helper`
repository's frontend owns **`io.github.sjtrotter.portal.WebAuthentication`** at
**`/io/github/sjtrotter/portal/WebAuthentication`**, exporting
`io.github.sjtrotter.portal.WebAuthentication1`. Backend impl bus names follow the same
pattern: this project's backend owns `io.github.sjtrotter.impl.portal.Certificate.gtk`,
mirroring `org.freedesktop.impl.portal.desktop.gtk`'s per-project shape during incubation; at
acceptance it merges into the real gtk backend's bus name.

That is not a workaround for a name collision; it is the correct shape for two independent,
unreviewed prototypes that happen to share a machine — both incubating frontends install and
run side by side, and neither has to fail to acquire a name the other already holds.

**At acceptance, the question disappears.** Both interfaces move onto
`org.freedesktop.portal.Desktop` at `/org/freedesktop/portal/desktop`, hosted by
xdg-desktop-portal itself, and the per-project incubating bus names and object paths vanish
along with the frontends that held them. Acceptance is a rename, nothing else, for either
project.

**It does not, by itself, fix the delegation gap** described in
[0005](0005-first-consumer-is-the-web-auth-service.md) and [ARCHITECTURE.md](../ARCHITECTURE.md),
and that gap no longer has anything to do with which bus name either frontend claims. This
project derives the app id of *its* caller, which when the sibling's backend calls in as an
ordinary client is `webauth-portal-gtk`, not the application that started the sign-in — so the
chooser names the wrong thing, and the original app id can only be passed along as untrusted
text. That is solved only when both interfaces run inside **one trusted frontend process**,
sharing one address space and one derived identity — which happens automatically at
acceptance. A shared incubating frontend built *before* acceptance would also close the gap
early, and is worth exploring, but it is one option among others rather than a required next
step; nothing about the per-project bus names above depends on it happening.

Passing an unattested app id across the process boundary as a stopgap ahead of any such shared
frontend is **not to be done**: a caller asserting someone else's identity with nothing to back
the assertion is exactly the identity-laundering [SECURITY.md](../SECURITY.md) forbids, and it
is not a smaller version of the shared-frontend fix — it is the thing that fix exists to avoid
needing.

## Consequences

- [ARCHITECTURE.md](../ARCHITECTURE.md)'s process-model section is replaced, and says
  plainly that its earlier position was overridden and by what reasoning.
- [INTERFACE.md](../PUBLIC-INTERFACE.md) splits into a public interface and an impl
  interface, because there are now two.
- `Sign` and `Decrypt` become `Request`-shaped, and a grant becomes a `Session`. Both are
  upstream conventions the one-process design had no reason to adopt.
- The grant registry is the frontend's and the token session is the backend's. Documented
  in [ARCHITECTURE.md](../ARCHITECTURE.md#who-does-what), because a split with an ambiguous
  ownership line is worse than no split.
- **This is the ADR to revisit if the spikes fail.** If S1 and S3 both fail, what is left is
  a brokered-signing service with one backend and no facade, and it is worth asking then
  whether two processes still earn their keep. The answer is probably still yes — the
  consent window is the thing being protected — but it should be asked rather than assumed.

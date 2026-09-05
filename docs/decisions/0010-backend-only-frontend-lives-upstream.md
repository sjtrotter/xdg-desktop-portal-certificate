# 10. Be a backend only: the frontend lives in xdg-desktop-portal

Date: 2026-09-04
Status: accepted (for the sketch); supersedes the *packaging* half of
[0008](0008-build-to-the-upstream-shape.md) and retires the incubating frontend

## Context

[0008](0008-build-to-the-upstream-shape.md) decided to build a portal frontend and a
portal backend now, in xdg-desktop-portal's shape but under project-controlled names, so
that acceptance upstream would be "a rename rather than a redesign". That decision was
right about the *shape* and wrong about the *route*, and the reason it was wrong is
simply that the author did not yet know how new portals actually get developed.

The evidence is in the xdg-desktop-portal tree and in
[PR #1889](https://github.com/flatpak/xdg-desktop-portal/pull/1889), "Introduce
Credentials portal (experimental)". A new portal is not incubated in a separate
repository under a separate namespace and then proposed as a finished thing. It is
developed **in the frontend's own tree**, under an `experimental` namespace, gated off by
default. Sebastian Wick, on that PR, 2026-01-28:

> As for the interface name, let's call it something like
> `org.freedesktop.portal.experimental.Credentials`. It should also not be exposed by
> default and have a environment variable to turn it on (e.g.
> `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=credentials`).

So there is a sanctioned way to write an unfinished portal frontend, it is inside
xdg-desktop-portal, and the names it uses are `org.freedesktop.portal.experimental.*` and
`org.freedesktop.impl.portal.experimental.*` — not because acceptance has been granted,
but because that is the namespace upstream set aside for exactly this state.

Against that, a separately-namespaced frontend in this repository was worse in every
direction. It reimplemented `Request`, `Session`, app-id derivation, permission-store
access and `.portal` discovery that xdg-desktop-portal already has and that
[UPSTREAMING.md](../UPSTREAMING.md) always said would be deleted. It could never be
reviewed by the people whose review matters, because it was not in their tree. And it
made this repository claim a public bus name that no application had any reason to trust.

## Decision

**Move the frontend into a branch of xdg-desktop-portal, and delete it from here. This
repository is an out-of-tree backend and nothing else.**

- The frontend is `xdg-desktop-portal`, branch
  `experimental/certificate-webauthentication`, commits `3f46e3c..661e441`, with
  `703fb22 certificate: Add an experimental Certificate portal` as the one that matters
  here. It defines both
  `org.freedesktop.portal.experimental.Certificate` (public) and
  `org.freedesktop.impl.portal.experimental.Certificate` (impl), implements the
  `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` gate, and ships a python-dbusmock backend and
  a pytest suite for both.
- This repository builds **one binary**, `xdg-desktop-portal-certificate`, owning
  `org.freedesktop.impl.portal.desktop.certificate` and exporting
  `/org/freedesktop/portal/desktop`.
- `data/org.freedesktop.impl.portal.experimental.Certificate.xml` is a **verbatim copy**
  of the branch's file and must track it. The interface is not this repository's to
  change.
- `data/certificate.portal` installs into the **real**
  `${datadir}/xdg-desktop-portal/portals`, because that is where the frontend looks and
  there is nowhere else it could find it. See "What this changes about the old 'never
  advertise' rule" below.
- `frontend/` is deleted. `shared/` folds into `src/`, because there is only one side
  left for it to be shared between.

## What this changes about the old "never advertise to the real portal" rule

The previous layout installed its `.portal` file into `${datadir}/certificate-portal/portals`
and said, in several places, that an unaccepted prototype must never advertise itself to
the real xdg-desktop-portal. That rule was correct **for a frontend**: a second process
claiming to be a portal, with its own bus name and its own portals.conf search path, has
no business inserting itself into the real portal's configuration.

We no longer ship a frontend, so the rule no longer has a subject. What is left is a
backend, and an out-of-tree backend that does not install into
`${datadir}/xdg-desktop-portal/portals` is a backend that can never be selected. Both
reference points do exactly this: `xdg-desktop-portal-gtk` installs `gtk.portal` there,
and `xdg-desktop-portal-termfilechooser` installs `termfilechooser.portal` there and
tells the user to name it in `portals.conf`.

The honest caveat, kept rather than dropped: **the interface named in that file is
experimental and gated upstream.** A stock xdg-desktop-portal has never heard of
`org.freedesktop.impl.portal.experimental.Certificate`, will not match this file against
any interface it knows, and will ignore it. A frontend that does know it still exports
nothing unless it was started with `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate`.
Installing the file is therefore inert on a machine without the branch — which is what
makes it safe, and is not the same claim as "this is a supported portal".

## Consequences

- **[0008](0008-build-to-the-upstream-shape.md)'s split is preserved, not reversed.**
  Everything it argued for — that app id is derived by one process and passed to another
  as an argument, that the window naming an application is drawn by a process that did
  not have to guess which application it was, that a second desktop is a second package
  rather than a fork, that policy is the frontend's and the device is the backend's — is
  exactly what this repository is now built against. What changed is who ships the other
  half.
- **0008's "Per-project bus names during incubation" section is moot**, and is marked as
  such there in one line rather than rewritten away. There is no incubating frontend to
  give a bus name to.
- **[0003](0003-own-namespace-before-freedesktop.md) is amended, not overturned.** The
  impl interface name is now dictated by the frontend branch, and
  `org.freedesktop.impl.portal.experimental.*` is the namespace upstream set aside for
  unfinished portals. Using it is not a claim of acceptance. The backend bus name follows
  the ordinary out-of-tree backend convention, `org.freedesktop.impl.portal.desktop.<backend>`.
- **The interface changed shape in the move, and the branch won every disagreement.**
  `CreateSession` is a `Request` on the public side rather than a method returning a
  session path; the impl `GetCapabilities` carries `app_id` like every other impl call;
  `OpenPkcs11Endpoint` is not in the interface at all; there is no `context` option and
  no `app_display_name`. Those are recorded in [UPSTREAMING.md](../UPSTREAMING.md) and in
  [PUBLIC-INTERFACE.md](../PUBLIC-INTERFACE.md), and this repository's documents follow
  the XML rather than the other way round.
- **The delegation gap gets an obvious answer, in-process.**
  [0005](0005-first-consumer-is-the-web-auth-service.md) and 0008 both said the web-auth
  service naming the wrong application in this project's chooser is only solved when both
  interfaces live in one trusted frontend process. Both interfaces are now in one frontend
  process — xdg-desktop-portal, on the same branch — so the fix that was described as
  arriving "automatically at acceptance" is available early.

  **An earlier version of this line said trustworthy delegation can happen *only*
  in-process. That is wrong, and it should not be repeated.** What is forbidden is
  narrower and more precise: **trusting a caller's assertion about somebody else's
  identity**. A frontend that hands its own certificate side the app id it derived itself
  is the cheapest way to avoid that, because nothing is asserted and nothing crosses a
  boundary — but it is not the only way. Authenticated IPC, where the frontend derives the
  peer's identity itself rather than believing a field, would do it; so would a
  capability the frontend issues to a named peer and later recognises, which is one of the
  two candidate designs [0011](0011-client-side-pkcs11-module.md) records for the
  two-chooser problem. None of those is built. The rule to carry forward is "never believe
  a caller about a third party", not "never cross a process".
- **The spikes get cheaper.** [SPIKES.md](../SPIKES.md) S5 asked whether the
  frontend/backend boundary survives contact with a running system. Half of it is now
  answered by the branch's `tests/test_certificate.py`, which covers cancellation across
  two hops, a backend that over-claims being clamped, and the experimental gate.
- **The branch is ours until it is accepted.** Moving the frontend into xdg-desktop-portal's
  tree buys review in the right place and reuse of `Request`, `Session` and app-id
  derivation. It does **not** transfer maintenance: an unmerged branch is this author's to
  rebase, to keep green and to redesign when upstream asks. Any sentence in this repository
  that reads as though the frontend became somebody else's problem is describing the
  intended end state, not today.
- **This repository is smaller and its claims are narrower.** It no longer documents a
  public interface as though it owned one. [PUBLIC-INTERFACE.md](../PUBLIC-INTERFACE.md)
  is a pointer to the branch's XML with a summary, and the authority is the XML.
- **What remains before any of it could be a pull request** is in
  [UPSTREAMING.md](../UPSTREAMING.md): the "new portals" issue upstream asks for,
  the `Assisted-by:` trailer convention the branch write-up notes, and
  `OpenPkcs11Endpoint` as a follow-up.

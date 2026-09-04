# Upstreaming: what this becomes, and what changes

Status: EXPERIMENTAL. Nothing here has been proposed to anyone, and
[ROADMAP.md](ROADMAP.md) phase 3 says why the conversation has not started. This document
exists so that the answer to "how much would have to change?" is a table rather than a
guess.

**The claim this repository is built on:** if this design is ever accepted,
[what changes is the names and where the frontend lives](decisions/0008-build-to-the-upstream-shape.md).
Not the process model, not the interface shape, not the request and session plumbing, not
which side establishes the app id. That is the entire reason the split exists now instead
of later.

The claim is testable, and this document is the test. Anything that would have to change
beyond a rename is listed under [Open items](#open-items-things-that-are-not-just-a-rename)
rather than hidden.

## Interface names

| Ours (incubating) | Upstream, if accepted |
|---|---|
| `io.github.sjtrotter.portal.Certificate1` | `org.freedesktop.portal.<Name>` |
| `io.github.sjtrotter.impl.portal.Certificate1` | `org.freedesktop.impl.portal.<Name>` |
| `io.github.sjtrotter.portal.Request` | `org.freedesktop.portal.Request` (already exists; ours disappears) |
| `io.github.sjtrotter.portal.Session` | `org.freedesktop.portal.Session` (already exists; ours disappears) |
| `io.github.sjtrotter.impl.portal.Request` | `org.freedesktop.impl.portal.Request` (already exists; ours disappears) |
| `io.github.sjtrotter.impl.portal.Session` | `org.freedesktop.impl.portal.Session` (already exists; ours disappears) |
| `io.github.sjtrotter.portal.Certificate` (bus name) | `org.freedesktop.portal.Desktop` (already exists; ours disappears) |
| `io.github.sjtrotter.impl.portal.Certificate.gtk` (bus name) | `org.freedesktop.impl.portal.desktop.gtk` (already exists; our interface joins it) |
| `/io/github/sjtrotter/portal/Certificate` | `/org/freedesktop/portal/desktop` |
| `io.github.sjtrotter.portal.Certificate1.Error.*` | `org.freedesktop.portal.Error.*`, or the portal's own |

**`<Name>` may not stay `Certificate`.** [0009](decisions/0009-name-it-certificate.md) settled
the incubating interface on `Certificate` because the conceptual boundary is a client
certificate or a cryptographic credential — the backing key may be a TPM, a software token, a
phone or a remote HSM — rather than any one device, and because `Credentials` was rejected as a
name: it collides with the `org.freedesktop.portal.Credentials` proposal that
[linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) is
already making for FIDO2 and passkeys. Whether `Certificate` is also the name maintainers
accept, or whether certificate-backed signing instead becomes a credential *type* under that
other proposal, is a question for the conversation in
[0003](decisions/0003-own-namespace-before-freedesktop.md) and [ROADMAP.md](ROADMAP.md) phase
3 — not one this project can settle unilaterally, and it happens **before** any name is
frozen.

## Files

Upstream reorganised its tree: what the older documentation calls `src/` is now
`desktop-portal/` (one file per portal, plus `xdp-request.c`, `xdp-session.c`,
`xdp-permissions.c`, `xdp-portal-config.c`) and `shared/` (`xdp-app-info*.c`), with the
interface XML in `data/`. The mapping below targets the tree as it is.

| Ours | Upstream, if accepted |
|---|---|
| `frontend/src/certificate.h` (+ its future `.c`) | `xdg-desktop-portal/desktop-portal/<name>.c`, `<name>.h` |
| `frontend/src/request.h` | *deleted* — `desktop-portal/xdp-request.c` already does this |
| `frontend/src/session.h` | *deleted* — `desktop-portal/xdp-session.c` already does this |
| `frontend/src/app-info.h` | *deleted* — `shared/xdp-app-info*.c` already does this |
| `frontend/src/permission-store.h` | *deleted* — `desktop-portal/xdp-permissions.c` already does this |
| `frontend/src/portal-impl.h` | *deleted* — `desktop-portal/xdp-portal-config.c` already does this |
| `frontend/src/grant-registry.h` | kept, as portal-specific state inside `<name>.c` |
| `frontend/data/io.github.sjtrotter.portal.Certificate1.xml` | `xdg-desktop-portal/data/org.freedesktop.portal.<Name>.xml` |
| `frontend/data/io.github.sjtrotter.portal.Certificate.service.in` | *deleted* — the name already exists |
| `frontend/data/portals.conf.example` | *deleted* — `portals.conf` already exists |
| `backends/gtk/data/io.github.sjtrotter.impl.portal.Certificate1.xml` | `xdg-desktop-portal/data/org.freedesktop.impl.portal.<Name>.xml` — **note it moves to the frontend repository**, see below |
| `backends/gtk/src/certificate.h` (+ `.c`) | `xdg-desktop-portal-gtk/src/<name>.c`, `<name>.h` |
| `backends/gtk/src/request.h`, `session.h` | *deleted* — `xdg-desktop-portal-gtk/src/request.c`, `session.c` already do this |
| `backends/gtk/src/ui/`, `tokens/`, `broker/`, `export/` | kept, as `xdg-desktop-portal-gtk/src/<name>*.c` or a backend package of its own |
| `backends/gtk/data/gtk.portal.in` | *merged* — one more entry in xdg-desktop-portal-gtk's `Interfaces=` line |
| `backends/gtk/data/io.github.sjtrotter.impl.portal.Certificate.gtk.service.in` | *deleted* — the name already exists |
| `shared/redact.h` | split: the frontend's rules join xdg-desktop-portal's logging, the backend's stay with the backend |
| `meson.build` (umbrella) | *deleted* — two repositories, two builds |

The lines that say *deleted* are the point. Roughly half of the frontend is plumbing that
xdg-desktop-portal already has; building it now is how we find out whether our portal fits
that plumbing, and the answer so far is that it does, with the exceptions below.

## What actually changes at acceptance

1. **Names.** Everything in the first table, mechanically.
2. **The frontend's home.** `frontend/` stops being a service and becomes a portal inside
   `xdg-desktop-portal`: its `main.c`, its bus name, its service file and its own
   `Request`/`Session`/`app-info`/`permission-store`/`portal-impl` code all go away,
   replaced by the frontend that is already there.
3. **The backend's packaging.** `backends/gtk/` either merges into
   `xdg-desktop-portal-gtk` or stays a separate backend package; either way its `.portal`
   file names an `org.freedesktop.impl.portal.*` interface instead of ours.

That is the whole list, and it is deliberately short.

## Open items: things that are not just a rename

Written down because a claim like the one above is only credible with its exceptions
attached.

- **Where the impl XML lives.** Upstream keeps `org.freedesktop.impl.portal.*.xml` in
  *xdg-desktop-portal*, and backends consume it from the `xdg-desktop-portal.pc`
  interfaces directory — xdg-desktop-portal-gtk's `data/meson.build` reads exactly that.
  We ship it with the backend, because while the interface is ours and unstable there is
  no frontend repository to put it in. At acceptance it moves.
- **Who opens the device.** For Camera and USB the *frontend* opens the device — a
  PipeWire remote, an `open()`ed fd — and the backend only draws the permission dialog.
  We follow ScreenCast and RemoteDesktop instead, where the backend owns the device and
  hands back a descriptor, because a PKCS#11 session is a login state with handles
  attached rather than a file descriptor, and the process that draws the PIN prompt has to
  be the process that holds it. **This is the first thing to raise with maintainers.**
- **`Sign` and `Decrypt` return a `Request`.** That follows upstream's rule for anything
  that can prompt, but it means a TLS handshake's inner loop is a round trip plus a signal
  rather than a method call. Nobody has measured it. If it is too slow, the answer is
  probably a non-interactive fast path that fails with `InteractionRequired` when a prompt
  would be needed — which is a design change, not a rename.
- **`ReleaseGrant` duplicates `Session.Close()`.** Both are documented, both do the same
  thing. A reviewer may well ask for one to go, and the answer should be yes.
- **`GrantInvalidated` duplicates `Session.Closed`.** Same, with the same answer.
- **The `backend_gone` reason has no upstream analogue** that we could find. Upstream
  portals mostly assume the backend is there. Ours cannot: a grant is backed by a PKCS#11
  session in the backend's process, and a backend restart kills it.
- **The permission-store table name and resource-id format** are ours, and are the kind of
  thing maintainers have opinions about.
- **Two `Request` objects per interaction is upstream's model**, and it costs a
  round trip on every prompt. It is recorded here only so that nobody "optimises" it into
  a direct application-to-backend call, which would hand the application its own app id.

## What does not change, and must not

- The application talks to the frontend and only the frontend.
- The app id is established by the frontend and passed to the backend as an argument.
- The PIN exists only in the backend's process, and never on any bus.
- Selection memory is preselection, never authorisation, and lives in the permission
  store.
- The facade is experimental, opt-in, synthetic, and refuses every administrative and
  key-management entry point.
- `purpose` constrains selection and consent language and attests nothing.

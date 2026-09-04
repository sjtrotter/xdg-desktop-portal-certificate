# The implementation interface — `io.github.sjtrotter.impl.portal.Smartcard1`

Status: EXPERIMENTAL, and **more** unstable than the public interface, deliberately. Upstream
treats the `org.freedesktop.impl.portal.*` interfaces as an internal contract between a frontend
and the backends of the same release, versioned but not promised to applications. This one is the
same, with less of a track record.

**This interface is not for applications.** It is what the frontend
(`smartcard-portal-frontend`) calls on a backend it selected — for the reference backend in this
repository, `smartcard-portal-gtk` on bus name `io.github.sjtrotter.impl.portal.desktop.gtk`,
object `/io/github/sjtrotter/portal/desktop`. Declared in
[`../backends/gtk/data/io.github.sjtrotter.impl.portal.Smartcard1.xml`](../backends/gtk/data/io.github.sjtrotter.impl.portal.Smartcard1.xml).

The public interface applications do call is [PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md). Which
side is responsible for what is the table in [ARCHITECTURE.md](ARCHITECTURE.md#who-does-what).
What each name becomes if this is ever accepted upstream is [UPSTREAMING.md](UPSTREAMING.md).

## The conventions, all borrowed

Every one of these is xdg-desktop-portal's, and none of them is an improvement on it:

- **Interactive methods take `handle`, `app_id` and `parent_window`, and return
  `(u response, a{sv} results)`.** The frontend picks the `handle` path; the backend exports an
  `io.github.sjtrotter.impl.portal.Request` there for the duration of the interaction. Compare
  [`org.freedesktop.impl.portal.Usb.AcquireDevices`](https://github.com/flatpak/xdg-desktop-portal/blob/main/data/org.freedesktop.impl.portal.Usb.xml).
- **The app id is an argument.** The backend never derives it, never asks the bus who is calling,
  never reads `/proc`. If it did, the answer would be "the frontend".
- **The impl `Request` has `Close()` and no `Response` signal.** The result comes back as the
  method's return value. Exactly one object — the frontend's `Request` — is responsible for the
  at-most-one-terminal-response rule.
- **Long-lived state hangs off an `io.github.sjtrotter.impl.portal.Session`** at the path the
  frontend chose, with `Close()` and `Closed`.
- **File descriptors may cross this boundary.**
  [`org.freedesktop.impl.portal.RemoteDesktop.ConnectToEIS`](https://github.com/flatpak/xdg-desktop-portal/blob/main/data/org.freedesktop.impl.portal.RemoteDesktop.xml)
  returns one; [`org.freedesktop.impl.portal.Secret.RetrieveSecret`](https://github.com/flatpak/xdg-desktop-portal/blob/main/data/org.freedesktop.impl.portal.Secret.xml)
  takes one.
- **Backends declare themselves in a `.portal` file** and are selected by `portals.conf`, per
  [writing a new backend](https://flatpak.github.io/xdg-desktop-portal/docs/writing-a-new-backend.html)
  and [portals.conf](https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html).

## Methods

| Method | Shape | Notes |
|---|---|---|
| `CreateSession(o handle, o session_handle, s app_id, a{sv} options) → (u, a{sv})` | non-interactive | Creates the backend-side state for a grant. Fails early when there is no p11-kit, no reader, no display. |
| `AcquireCredential(o handle, o session_handle, s app_id, s parent_window, a{sv} options) → (u, a{sv})` | **interactive** | Discovery, filtering, and **the chooser**. |
| `Sign(o handle, o session_handle, s app_id, s parent_window, a{sv} options) → (u, a{sv})` | **interactive** | The signature, and the PIN prompt if this is the first private-key use. |
| `Decrypt(...)` | **interactive** | As `Sign`. Not in v1. |
| `OpenPkcs11Endpoint(o session_handle, s app_id, a{sv} options) → (h, s, s, u)` | non-interactive, fd out | Starts the facade helper and returns its socket. **Experimental.** |
| `GetCapabilities(a{sv} options) → a{sv}` | non-interactive | What this backend can do on this hardware. The frontend intersects it with policy. |
| `TokenAdded(a{sv})`, `TokenRemoved(a{sv})` | signals | To the frontend. The frontend decides who else hears. |
| `SessionInvalidated(o session_handle, s reason)` | signal | The hardware behind a grant went away: `token_removed`, `device_error`, `backend_shutdown`. |

### What the frontend sends that the public interface does not have

These are the fields that exist *because* of the split, and they are the reason it is worth its
cost:

| Key | Why |
|---|---|
| `app_id` | Established by the frontend from Flatpak metadata, Snap mediation, host cgroups, or a Registry-style claim. Empty string when unidentified. |
| `app_display_name` | What the chooser should call the application, in the frontend's words. |
| `app_identity_level` | `verified_sandboxed` \| `derived_host` \| `unidentified`. **The backend must display this.** An application name shown without saying how it was established is a lie by omission. |
| `lifetime` | Seconds the frontend has *decided* to allow, after applying its ceiling — not the caller's request. |
| `preselect_certificate` | A stable certificate id the frontend read from the permission store. Preselection only. |

### What the backend returns that the frontend does not simply pass on

`certificate_id` (the key a permission-store entry would use) and `remember_selection` (what the
user said). The frontend decides whether to store anything, because the key is the app id and the
app id is the frontend's. A backend never writes the permission store.

The frontend also **intersects** everything else: `supported_mechanisms` against its allow-list,
`permitted_operations` against what the purpose permits, `expires_at` against the ceiling. A
backend that returns more than it was allowed to does not get more; it gets clamped, and logged by
reason code.

## Why an application cannot call this

This is the question a reviewer asks first, and the honest answer has three parts.

**1. The mechanism upstream actually relies on.** The impl bus names are not something an
application has any reason to hold, they are not proxied into sandboxes by the portal machinery,
and a Flatpak's D-Bus policy does not grant them: a sandboxed application talks to
`org.freedesktop.portal.Desktop` through the proxy and cannot see
`org.freedesktop.impl.portal.desktop.gtk` at all. The same is true here, with our names.

**2. The check this backend adds on top.** Every impl method compares the sender against the
unique name that currently owns `io.github.sjtrotter.portal.Desktop`, and refuses anything else
with `NotPermitted`, logged by reason code
(`backends/gtk/src/smartcard.h`, `smartcard_impl_sender_is_frontend`). Upstream backends do not
all do this. It is cheap, and the failure it prevents — an unsandboxed application calling
`AcquireCredential` with an `app_id` of its own invention, and getting a consent dialog that names
somebody else — would destroy the entire consent model rather than degrade it.

**3. What none of that fixes.** On a conventional desktop, an unsandboxed process running as the
user may be able to interfere with either service by means that have nothing to do with D-Bus
names: `ptrace`, environment manipulation, runtime files, input injection. The split does not
change that, and [SECURITY.md](SECURITY.md) says so in the same words it used before the split.
What the split *does* fix is the case that used to be unfixable: one service both deriving an
application's identity and drawing the window that asserts it.

A deployment that wants more can add a D-Bus policy rule denying the backend's name to everything
but the frontend's uid, or run the backend on a private socket the frontend passes to it. Neither
is in v1, both are recorded here so that "we could tighten this" is written down rather than
assumed.

## What the backend must never do

Repeated here because it is the whole contract:

- **Derive the caller's identity.** It arrives as an argument.
- **Decide policy.** Purpose validity, lifetime ceilings, operation sets, rate limits: frontend.
- **Write the permission store.** The key is the app id.
- **Widen anything.** A backend returns what it can do; the frontend decides what is allowed.
- **Trust the caller directly.** The only legitimate caller is the frontend, and it is checked.

And what it must always do: display the app id **with** its honesty level, render the purpose in
its own words, keep caller-supplied `reason` and `context` out of the trusted identity position,
and re-validate every mechanism and parameter even though the frontend already did. Two checks
against a hostile caller is the correct number.

# The implementation interface — `org.freedesktop.impl.portal.experimental.Certificate`

Status: EXPERIMENTAL, and **more** unstable than the public interface, deliberately. Upstream
treats the `org.freedesktop.impl.portal.*` interfaces as an internal contract between a frontend
and the backends of the same release, versioned but not promised to applications. This one is the
same, with less of a track record and an `experimental` infix that says so on the wire.

**This interface is not for applications.** It is what xdg-desktop-portal calls on a backend it
selected — here, `xdg-desktop-portal-certificate` on bus name
`org.freedesktop.impl.portal.desktop.certificate`, object path `/org/freedesktop/portal/desktop`.

## The XML this repository ships is a copy, and it must track its source

[`../data/org.freedesktop.impl.portal.experimental.Certificate.xml`](../data/org.freedesktop.impl.portal.experimental.Certificate.xml)
is a **verbatim copy**, apart from a header comment saying so, of

```
xdg-desktop-portal, branch experimental/certificate-webauthentication, commit 703fb22
data/org.freedesktop.impl.portal.experimental.Certificate.xml
```

The interface belongs to the frontend. This repository does not get to change it, and a
divergence between the two files is not a difference of opinion — it is a backend that no longer
implements the interface it claims in `data/certificate.portal`. To update: copy the branch's file
again and change the commit id in the header.

Upstream keeps `org.freedesktop.impl.portal.*.xml` in xdg-desktop-portal itself and backends
consume it from that project's pkg-config interfaces directory —
`xdg-desktop-portal-gtk/data/meson.build` reads exactly that. This copy exists only because the
branch is unmerged and no released xdg-desktop-portal ships the file. When the branch lands, the
copy is deleted and the file comes from the interfaces directory like every other backend's.

The public interface applications call is [PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md), which is
itself a pointer to the branch. Which side is responsible for what is the table in
[ARCHITECTURE.md](ARCHITECTURE.md#who-does-what). What is left before any of this could be a pull
request is [UPSTREAMING.md](UPSTREAMING.md).

## The conventions, all borrowed

Every one of these is xdg-desktop-portal's, and none of them is an improvement on it:

- **Interactive methods take `handle`, `session_handle`, `app_id` and `parent_window`, and return
  `(u response, a{sv} results)`.** The frontend picks the `handle` path; the backend exports an
  `org.freedesktop.impl.portal.Request` there for the duration of the interaction. Compare
  [`org.freedesktop.impl.portal.Usb.AcquireDevices`](https://github.com/flatpak/xdg-desktop-portal/blob/main/data/org.freedesktop.impl.portal.Usb.xml).
- **The app id is an argument.** The backend never derives it, never asks the bus who is calling,
  never reads `/proc`. If it did, the answer would be "xdg-desktop-portal".
- **The impl `Request` has `Close()` and no `Response` signal.** The result comes back as the
  method's return value. Exactly one object — the frontend's `Request` — is responsible for the
  at-most-one-terminal-response rule.
- **Long-lived state hangs off an `org.freedesktop.impl.portal.Session`** at the path the
  frontend chose, with `Close()` and `Closed`.
- **Backends declare themselves in a `.portal` file** and are selected by `portals.conf`, per
  [writing a new backend](https://flatpak.github.io/xdg-desktop-portal/docs/writing-a-new-backend.html)
  and [portals.conf](https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html).

## Methods

| Method | Shape | Notes |
|---|---|---|
| `CreateSession(o handle, o session_handle, s app_id, a{sv} options) → (u, a{sv})` | non-interactive | Creates the backend-side state for a grant. `options` is unused and `results` is empty. Fails early when there is no p11-kit, no reader, no display. |
| `AcquireCredential(o handle, o session_handle, s app_id, s parent_window, a{sv} options) → (u, a{sv})` | **interactive** | Discovery, filtering, and **the chooser**. |
| `Sign(o handle, o session_handle, s app_id, s parent_window, a{sv} options) → (u, a{sv})` | **interactive** | The signature, and the PIN prompt if this is the first private-key use. |
| `Decrypt(...)` | **interactive** | As `Sign`, with `ciphertext` in place of `data` and `plaintext` in place of `signature`. Not in v1. |
| `GetCapabilities(s app_id, a{sv} options) → a{sv}` | non-interactive | What this backend can do on this hardware. **Note the `app_id`** — see below. |
| `TokenAdded(a{sv})`, `TokenRemoved(a{sv})` | signals | To the frontend. The frontend decides who else hears. |
| `SessionInvalidated(o session_handle, s reason)` | signal | The hardware behind a grant went away: `token_removed`, `device_error`, `backend_shutdown`. The frontend turns it into `GrantInvalidated` and closes the Session. |

**`GetCapabilities` carries `app_id`, and that is a change** from what this repository used to
document. The old sketch had `GetCapabilities(a{sv}) → a{sv}` on both interfaces. The branch made
the impl side `GetCapabilities(s app_id, a{sv}) → a{sv}` because *every* impl call upstream carries
`app_id`; the public side is unchanged. A backend is not obliged to vary its answer by application,
but it is told which one is asking, and it is now impossible to implement the impl interface while
forgetting that the question has a subject.

**There is no `OpenPkcs11Endpoint`.** The earlier sketch had one on both interfaces, returning
`(h endpoint_fd, s certificate_uri, s private_key_uri, u endpoint_version)`. The branch left it out
of both, deliberately: an fd-returning method needs its own review, and the python-dbusmock backend
the frontend is tested against cannot produce a usable endpoint fd, so a first version with it would
have had no test. It is a follow-up. [`../src/export/facade.h`](../src/export/facade.h) still holds
the requirements, and they are still the acceptance criteria for that follow-up.

### What the frontend sends that the public interface does not have

These are the fields that exist *because* of the split, and they are the reason it is worth its
cost:

| Key | Why |
|---|---|
| `app_id` | Established by the frontend from `xdp_invocation_get_app_info()`. Empty string when unidentified. |
| `app_identity_level` | `verified_sandboxed` \| `derived_host` \| `unidentified`. **The backend must display this.** An application name shown without saying how it was established is a lie by omission. |
| `lifetime` | Seconds the frontend has *decided* to allow, after applying its 3600 s ceiling — not the caller's `requested_lifetime`. |
| `preselect_certificate` | A stable certificate id the frontend read from the permission store. Preselection only. |

**And two fields that are gone.** `app_display_name` is not on the branch interface: the backend
gets an app id and an identity level, and any human-readable name is its own to derive or to omit.
`context` — the destination-host hint — is not on either interface: the only caller-supplied text
that reaches a backend is `reason`.

### What the backend returns that the frontend does not simply pass on

`certificate_id` (the key a permission-store entry would use) and `remember_selection` (what the
user said). The frontend decides whether to store anything, in its `certificate` permission table
keyed on the app id, because the app id is the frontend's. A backend never writes the permission
store.

The frontend also **intersects** everything else: `supported_mechanisms` against its allow list
(`RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA`), `permitted_operations` against what the purpose permits,
and `expires_at` is not the backend's to send at all — it is frontend-generated. A backend that
returns more than it was allowed to does not get more; it gets clamped, and the branch has a test
for exactly that (`test_backend_results_are_clamped`).

## Why an application cannot call this

This is the question a reviewer asks first, and the honest answer has three parts.

**1. The mechanism upstream actually relies on.** The impl bus names are not something an
application has any reason to hold, they are not proxied into sandboxes by the portal machinery,
and a Flatpak's D-Bus policy does not grant them: a sandboxed application talks to
`org.freedesktop.portal.Desktop` through the proxy and cannot see
`org.freedesktop.impl.portal.desktop.certificate` at all. This is now literally the same mechanism
upstream relies on, rather than an analogue of it under our own names.

**2. The check this backend adds on top.** Every impl method compares the sender against the
unique name that currently owns `org.freedesktop.portal.Desktop`, and refuses anything else with
`NotPermitted`, logged by reason code
([`../src/certificate-impl.h`](../src/certificate-impl.h), `certificate_impl_sender_is_frontend`).
Upstream backends do not all do this. It is cheap, and the failure it prevents — an unsandboxed
application calling `AcquireCredential` with an `app_id` of its own invention, and getting a consent
dialog that names somebody else — would destroy the entire consent model rather than degrade it.

**3. What none of that fixes.** On a conventional desktop, an unsandboxed process running as the
user may be able to interfere with either process by means that have nothing to do with D-Bus
names: `ptrace`, environment manipulation, runtime files, input injection. The split does not
change that, and [SECURITY.md](SECURITY.md) says so in the same words it used before the split.
What the split *does* fix is the case that used to be unfixable: one service both deriving an
application's identity and drawing the window that asserts it.

A deployment that wants more can add a D-Bus policy rule denying this backend's name to everything
but the portal's uid. That is not in v1; it is recorded here so that "we could tighten this" is
written down rather than assumed.

## What the backend must never do

Repeated here because it is the whole contract:

- **Derive the caller's identity.** It arrives as an argument.
- **Decide policy.** Purpose validity, lifetime ceilings, operation sets, rate limits: frontend.
- **Write the permission store.** The key is the app id.
- **Widen anything.** A backend returns what it can do; the frontend decides what is allowed.
- **Trust the caller directly.** The only legitimate caller is xdg-desktop-portal, and it is checked.
- **Edit the interface XML in `data/`.** It belongs to the frontend.

And what it must always do: display the app id **with** its identity level, render the purpose in
its own words, keep the caller-supplied `reason` out of the trusted identity position, and
re-validate every mechanism and parameter even though the frontend already did. Two checks against
a hostile caller is the correct number.

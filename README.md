# xdg-desktop-portal-certificate

**This repository is an xdg-desktop-portal BACKEND.** It is not a portal, it owns no
public interface, and no application talks to it. It draws a certificate chooser and a PIN
prompt, discovers PKCS#11 tokens, and performs private-key operations when
xdg-desktop-portal asks it to.

**Status: EXPERIMENTAL design sketch. Nothing works yet, and the first thing to do is a
spike that may kill it.** This repository contains design documents, a repository
skeleton, and one stub binary that builds and prints usage. No card has ever been read by
this code, no PIN has ever been prompted for, and no cryptographic operation has ever been
brokered.

> **The directory is still called `smartcard-portal`.** That is a directory name and a
> URL, not a claim. The binary, the D-Bus names and everything else are
> `xdg-desktop-portal-certificate`; renaming the GitHub repository to match is a separate,
> later decision — see [0009](docs/decisions/0009-name-it-certificate.md), which is why the
> interface is named after the certificate rather than after the hardware, and
> [0010](docs/decisions/0010-backend-only-frontend-lives-upstream.md), which is why the
> repository is a backend.

## Where the other half is

```
  ┌─────────────┐                                     ┌──────────────────────────────────┐
  │ application │  org.freedesktop.portal.experimental │ FRONTEND                         │
  └─────────────┘  .Certificate  ────────────────────► │ xdg-desktop-portal               │
        ▲          on org.freedesktop.portal.Desktop   │ branch experimental/             │
        │                                              │   certificate-webauthentication  │
        │                                              │                                  │
        │          who is asking (app id, and how      │ identity · policy · permissions  │
        └── grant, │ well we know it) · option         │ request & session lifecycle ·    │
            sig    │ validation · lifetime ceiling ·   │ grants, expiry, clamping ·       │
                   │ permission store · grants         │ backend selection                │
                                                       └────────────┬─────────────────────┘
                     org.freedesktop.impl.portal        NOT for      │  app_id is an
                       .experimental.Certificate        applications │  ARGUMENT here
                     on org.freedesktop.impl.portal ────────────────►│
                       .desktop.certificate                          ▼
                                                       ┌──────────────────────────────────┐
                                                       │ BACKEND — THIS REPOSITORY        │
                                                       │ xdg-desktop-portal-certificate   │
                                                       │                                  │
                                                       │ chooser · PIN prompt ·           │
                                                       │ PKCS#11 session · Sign           │
                                                       └────────────┬─────────────────────┘
                                                                    ▼
                                                       p11-kit → OpenSC → pcscd → card
```

**A client talks to xdg-desktop-portal and to nothing else.** It never learns which backend
is installed, never holds a PKCS#11 handle, and never sees a PIN. The division is not
copied from xdg-desktop-portal any more — it *is* xdg-desktop-portal: `app_id` is derived
by the frontend and passed to this backend as an argument, so the process drawing the
window that names an application never had to guess which application it was.

The frontend is a local-only branch, `experimental/certificate-webauthentication`, commits
`3f46e3c..661e441`. It has been built and tested (40 pytest cases for this portal, all
green, against a python-dbusmock backend) and **has not been proposed to anyone**. Its
interfaces live in the `org.freedesktop.portal.experimental.*` namespace, which is what
upstream set aside for portals that are not finished — not a claim that this one has been
accepted. [docs/UPSTREAMING.md](docs/UPSTREAMING.md) has the whole picture, including what
remains before a pull request.

Read this paragraph before anything else:

> **The bad version of this idea is a certificate chooser wrapped around `p11-kit server`.** It
> gives the application far more access to the token than the consent dialog implies, and it does
> not solve PIN ownership at all. **The viable version is a cryptographic credential broker** —
> the service selects the credential, keeps the key, and performs the operations — **with a
> carefully restricted PKCS#11 compatibility facade** for consumers that can only speak PKCS#11.
> That is materially larger and riskier than it first looks: the facade is a security-sensitive
> PKCS#11 implementation, not plumbing. See
> [docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
> and [0007](docs/decisions/0007-brokered-operations-are-the-core.md). The facade is
> currently unreachable: the frontend branch deliberately left `OpenPkcs11Endpoint` off
> both interfaces, so brokered `Sign` is the only path there is.

## The problem

A smart card holds a private key that the user is willing to let *some* applications use, *some*
of the time, after proving they are present by entering a PIN. On Linux, an application that wants
to use it has exactly two options, and both are bad.

**Do it yourself.** Enumerate the PKCS#11 tokens, filter the certificates, draw a chooser, draw a
PIN dialog, handle a card pulled out mid-flow, handle p11-kit's trust tokens that hold no client
certificates, handle a token that reports empty by failing, handle the PIN retry counter you must
not spend. Almost nobody does this. It is why smart-card sign-in works in Firefox and in
approximately nothing else on the desktop.

**Get blanket access.** A Flatpak asks for [`--socket=pcsc`](https://docs.flatpak.org/en/latest/sandbox-permissions.html)
and is then talking to `pcscd` directly: every card, every reader, every slot, every APDU, for the
lifetime of the application, with no user-visible moment of consent. That is how Firefox and
Chromium Flatpaks do it today, because there is nothing else.

Both failures compound into a third: **there is no window the user can learn to trust.** The PIN
prompt is the moment a person authorises a hardware token to authenticate as them. Today that
prompt looks different in every application, is drawn by the application asking for it, and is
therefore trivially imitable.

## What other systems do

| | Mechanism | Who owns the PIN prompt |
|---|---|---|
| **Windows** | Card minidriver under the [Base CSP / smart card KSP](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture); applications use CNG and certificates appear in the store by propagation | The OS (the Base CSP/KSP layer owns PIN entry and caching) |
| **macOS** | [CryptoTokenKit](https://developer.apple.com/documentation/cryptotokenkit) driver publishes token keys into the Keychain; applications use ordinary Keychain/`SecKey` APIs | The system |
| **Linux** | PKCS#11 module loaded directly into every application that cares | Whichever application drew a dialog first |

The Linux row is the whole reason for this project. The interesting part of the other two rows is
not the cryptography — PKCS#11 and OpenSC already do that well. It is that **the credential is
used through an OS-brokered API, the consent decision and the PIN prompt belong to the system, and
the application never holds the key.** Note what those systems do *not* do: neither hands the
application a raw, general-purpose token interface and calls it mediation.

## The design, in one paragraph

xdg-desktop-portal brokers cryptographic credentials the way
[`org.freedesktop.portal.Camera`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Camera.html)
brokers cameras: it does not hand over the device. An application calls `AcquireCredential` naming
a purpose. The **frontend** works out who is asking and whether it may ask; **this backend** — not
the application — shows a chooser naming the application *the frontend identified*, how well it is
identified, the purpose in the backend's own words, and the candidate certificates on each token;
the frontend returns a **grant**: the chosen certificate as DER, its chain and chain status, the
key's type and mechanisms, the permitted operations, and an expiry. The application then asks the
frontend to **`Sign`** (and, if the grant allows it, `Decrypt`); the frontend checks the grant and
forwards; this backend prompts for the PIN in its own window, logs into its own PKCS#11 session,
performs the operation and returns the result.
The PIN never crosses D-Bus, the private key never leaves the card, and the application never holds
a PKCS#11 handle.

## Interfaces

**Public**, on `org.freedesktop.portal.Desktop` at `/org/freedesktop/portal/desktop` —
**defined by the frontend branch, not here**. Summarised in
[docs/PUBLIC-INTERFACE.md](docs/PUBLIC-INTERFACE.md), which points at
`data/org.freedesktop.portal.experimental.Certificate.xml` on the branch.

```
org.freedesktop.portal.experimental.Certificate      [EXPERIMENTAL, gated]

  CreateSession      (a{sv})                            → o handle      [Request]
                                      ↑ the session_handle comes back in the Response
  AcquireCredential  (o session, s parent_window, a{sv}) → o handle      [Request]
        options: handle_token, activation_token,
                 purpose: client_auth | signing | email | ssh   (required, no "any")
                 certificate_filter { issuers, key_usage, eku, token_label,
                                      piv_slot, key_algorithms }
                 operation_policy { sign, decrypt }
                 requested_lifetime (clamped to 3600), interaction_mode,
                 allow_selection_memory, reason (untrusted)
  Sign / Decrypt     (o session, s parent_window, a{sv}) → o handle      [Request]
  RenewGrant         (o session, a{sv})                  → t expires_at
  ReleaseGrant       (o session)
  GetCapabilities    (a{sv})                             → a{sv}
  signals: TokenAdded, TokenRemoved, GrantInvalidated
```

**Private**, frontend-to-backend, on `org.freedesktop.impl.portal.desktop.certificate` at the
same object path — described in [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md), declared in
[`data/org.freedesktop.impl.portal.experimental.Certificate.xml`](data/org.freedesktop.impl.portal.experimental.Certificate.xml),
which is a **verbatim copy of the branch's file and must track it**.
**Applications do not call this.**

```
org.freedesktop.impl.portal.experimental.Certificate

  CreateSession     (o handle, o session_handle, s app_id, a{sv}) → (u, a{sv})
  AcquireCredential (o handle, o session_handle, s app_id, s parent_window,
                     a{sv} options) → (u response, a{sv} results)
  Sign / Decrypt    (o handle, o session_handle, s app_id, s parent_window,
                     a{sv} options) → (u response, a{sv} results)
  GetCapabilities   (s app_id, a{sv} options) → a{sv}
  signals: TokenAdded, TokenRemoved, SessionInvalidated
```

Every impl call carries `app_id` — including `GetCapabilities`, which is one of the things
the move upstream changed. That is the whole point of the boundary.

## Building, and testing it on a dev machine

```console
$ meson setup build && ninja -C build
$ ./build/xdg-desktop-portal-certificate --help
```

That is all it does. It prints usage and exits 0; every verb returns exit 70, "not
implemented (design sketch)". Exit codes: `0` clean, `40` unavailable, `64` usage, `70`
internal / not implemented.

Two scripts drive the real thing, and neither touches your session bus unless you ask it
to:

```console
$ tools/dev-stack.sh
```

starts, on a **private bus** made by `dbus-run-session`: `xdg-permission-store` (the portal
refuses to start without it), this backend, and a development xdg-desktop-portal from the
branch with `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate` and an
`XDG_DESKTOP_PORTAL_DIR` pointing at a throwaway directory holding this repository's
`.portal` file and a `portals.conf` selecting it. Then it runs the trigger. Point it at
your build with `XDP_BUILD=/path/to/xdg-desktop-portal/build`.

```console
$ tools/trigger-certificate.sh          # version + capabilities + CreateSession
$ tools/trigger-certificate.sh version
$ tools/trigger-certificate.sh monitor  # watch the Response signals
```

calls the **public** interface with `gdbus`, exactly as an application would — on
`org.freedesktop.portal.Desktop`, never on this backend's name. Run it inside
`dbus-run-session` if you want it off the real bus. If the frontend was started without the
gate, every call fails with "no such interface"; that is the gate working.

Layout:

```
src/          the backend: main.c, the impl skeleton, ui/, tokens/, broker/, export/,
              redact.h
data/         the impl interface XML (a verbatim copy of the branch's), certificate.portal,
              the D-Bus service file
tools/        dev-stack.sh, trigger-certificate.sh
docs/         architecture, both interfaces, security, spikes, roadmap, upstreaming,
              decisions
```

Installed files: `$libexecdir/xdg-desktop-portal-certificate`,
`$datadir/xdg-desktop-portal/portals/certificate.portal` (the real directory — that is
where the frontend looks, and it is what every out-of-tree backend does),
`$datadir/dbus-1/services/org.freedesktop.impl.portal.desktop.certificate.service`, and
the interface XML in `$datadir/dbus-1/interfaces`. To select it explicitly, put this in
`portals.conf`:

```ini
[preferred]
org.freedesktop.impl.portal.experimental.Certificate=certificate
```

## Documents

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, the frontend/backend responsibility table, sequences, process model |
| [docs/PUBLIC-INTERFACE.md](docs/PUBLIC-INTERFACE.md) | a pointer to the branch's XML, and a summary |
| [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md) | the interface this backend implements, why the XML here is a tracking copy, and why applications cannot reach it |
| [docs/UPSTREAMING.md](docs/UPSTREAMING.md) | where the frontend branch is, what its XML forced this repository to change, and what remains before a PR |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, PIN handling, grant scoping, caller identity |
| [docs/SPIKES.md](docs/SPIKES.md) | the questions that decide whether this is buildable |
| [docs/ROADMAP.md](docs/ROADMAP.md) | phases, effort estimate, and its assumptions |
| [docs/decisions/](docs/decisions/) | why the shape is the shape |

## License

GPL-2.0-or-later. The chooser and PIN handling this project intends to build on is derived from
Remmina's RDP plugin, which is GPL-2.0-or-later; the reasoning, and the Apache-2.0 alternative that
would require a clean-room rewrite, are in [docs/decisions/0004-license.md](docs/decisions/0004-license.md).
Consumers only speak D-Bus, so the licence places no constraint on them.

## AI assistance

These documents and the skeleton were drafted with AI assistance — Anthropic Claude and OpenAI
Codex — under the author's direction, and the author is responsible for every claim in them. The
prior-art citations were checked against primary sources; the ones that could not be verified are
called out where they appear.

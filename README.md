# xdg-desktop-portal-certificate

A backend for an experimental xdg-desktop-portal interface that lets applications sign with a
certificate on a smart card without loading the card's driver or seeing the PIN. The user selects
a certificate and the application receives a time-limited grant. The backend requests the PIN
when a signing operation requires login. The private key stays on the card.

A PKCS#11 module in the same repository puts that grant behind the PKCS#11 API, so applications
that already speak PKCS#11 (Firefox, GnuTLS clients, WebKitGTK) can use the portal unchanged.
Such an application reaches the portal only when the module is loaded into it, and nothing
loads it automatically yet: in Firefox, load it from Security Devices; for Chrome, register it
in Chrome's NSS database (`tools/firefox-flatpak.sh` and `tools/chrome-flatpak.sh` print or do
the steps). Without the module, the browser never calls the portal.

The interface is experimental and not merged upstream. The frontend lives on a branch of a
fork of xdg-desktop-portal; see [Upstreaming](docs/UPSTREAMING.md).

## Components

| Part | Where | Role |
|---|---|---|
| Frontend | branch [`experimental/certificate`](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/certificate) of a fork of xdg-desktop-portal | identifies the caller, validates options, owns grants and their expiry |
| Backend | this repository, `src/` | discovers tokens, shows the chooser and PIN prompt, signs through PKCS#11 |
| PKCS#11 module | this repository, `src/module/` | loaded by applications; turns PKCS#11 calls into portal calls |

Applications call `org.freedesktop.portal.experimental.Certificate1` on
`org.freedesktop.portal.Desktop`. The frontend calls this backend's
`org.freedesktop.impl.portal.experimental.Certificate1` on
`org.freedesktop.impl.portal.desktop.certificate`. Both use the object path
`/org/freedesktop/portal/desktop`. The public methods are `CreateSession`,
`AcquireCredential`, `Sign` and `GetCapabilities`; closing the session ends the grant.

The frontend exports the interface only when a backend is configured and `Certificate1` is
listed in `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` in the frontend's environment
(comma separated, no spaces).
To select this backend in `portals.conf`:

```ini
[preferred]
org.freedesktop.impl.portal.experimental.Certificate1=certificate
```

## Try it

Build and test the backend:

```console
$ meson setup build
$ ninja -C build
$ meson test -C build
$ ./build/src/xdg-desktop-portal-certificate --list-tokens
```

`--list-tokens` prints the certificates on connected tokens without logging in. Only hardware
tokens are offered by default; `--allow-software-tokens` adds software tokens, and
`--module PATH` loads only the named PKCS#11 module.

Build dependencies are GLib/GIO 2.80+, GTK 4.14+, libadwaita 1.4+, p11-kit 0.23+ and
GnuTLS 3.6+. gcr-4 is optional
(`-Dgcr=auto`) and enables `--pin-prompt=system`, which uses the PIN prompt drawn by the desktop
shell. Without gcr-4, `--pin-prompt=gtk` and `auto` use the backend's GTK window;
`system` exits with a usage error (64). `-Dp11_module_path=` and `-Dp11_module_configs=` set
where the PKCS#11 module and its p11-kit configuration are installed.

For the toolkit-neutral SDK alone, use `meson setup build-sdk -Dservice=false`,
then `ninja -C build-sdk` and `meson install -C build-sdk`. This skips all GTK, libadwaita
and gcr dependency lookups, even with `--auto-features=enabled`, and installs only the
shared core, headers and pkg-config file. `service` defaults to `true`; the earlier
`-Dauto_features=disabled` shortcut also continues to select the SDK alone.
Link native desktop backends with `pkg-config --cflags --libs xdp-certificate-core-0`;
[SDK.md](docs/SDK.md) describes ownership, dispatch and ABI rules.

To run the whole stack on a private bus with a software token, build the frontend branch and
the backend, then run:

```console
$ tools/softhsm-fixture.sh
$ XDP_BUILD=/path/to/xdg-desktop-portal/build tools/dev-stack.sh --softhsm
```

Pick the certificate and enter the fixture PIN `123456`; the client checks the returned
signature. `tools/ui-smoke.sh` runs the same flow headless. [Testing](docs/TESTING.md) covers
prerequisites and runs with a real card.

The [single-prompt Firefox procedure](docs/TESTING.md#single-prompt-firefox-procedure) uses
the portal chooser and PIN prompt without Firefox's certificate picker.

## Status

| Feature | State | Notes |
|---|---|---|
| Token discovery, certificate parsing, `purpose` rules, `certificate_filter` | done | unit tests against fixture certificates |
| Chooser and PIN prompt | done | GTK window, or the shell's prompter through gcr-4 |
| Signing: `RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA` | done | all three against SoftHSM; per-signature PIN for `CKA_ALWAYS_AUTHENTICATE`; the RSA mechanisms against a PIV card |
| Token removal, `SessionInvalidated` | done | polled; never tested with a card pulled mid-operation |
| PKCS#11 module | done | one token and one credential per process; used by GnuTLS, NSS and WebKitGTK |
| Certificate chain | partial | `chain_status` is always `leaf_only` |
| Decryption | not exposed | `RSA_OAEP` code exists; neither interface has a `Decrypt` method |
| One grant shared by an application's processes | missing | each D-Bus peer gets its own grant |
| Proof of what a signature is for | missing | `purpose` limits selection and consent wording only |
| GNOME backend | implemented in the [fork](https://github.com/sjtrotter/xdg-desktop-portal-gnome/tree/experimental/certificate) | SoftHSM container coverage and a live GNOME 50 session with one PIV card; Shell system prompt or native dialog |
| KDE backend | implemented in the [fork](https://github.com/sjtrotter/xdg-desktop-portal-kde/tree/experimental/certificate) | SoftHSM container coverage only; no live-session or card run |
| Translations, packaging | incomplete | desktop adapters use their own translation catalogs; distribution packaging remains open |
| Independent security review | missing | |

The service build registers 34 Meson tests with gcr-4 (33 without), including a DER corpus
replay. ASan/UBSan requires a sanitizer build. [Test coverage](tests/README.md) lists prerequisites.

Sign operation logs include the session handle. Public calls log `operation=(none)` because
the frontend consumes `operation_id` and echoes it only to the caller. Direct impl or SDK
calls can supply an id for backend logs; see the [log field rules](docs/SECURITY.md#logging).

Hardware evidence, all with one PIV card, one reader, OpenSC, and GNOME 50 on Wayland:

- 2026-09-04: discovery, sign, cancel and a session-bus run through both PIN prompts
  ([Testing](docs/TESTING.md) tiers 3.1 to 3.4).
- 2026-09-05: a Microsoft Entra ID sign-in through the WebAuthentication portal, its
  client-certificate challenge answered by this portal, then an Azure Virtual Desktop session.
- 2026-09-06: Firefox with the module loaded from Security Devices signed in to a site that
  requires a client certificate.
- 2026-09-07: Firefox from Flathub with `--nosocket=pcsc --nodevice=all` reached the card only
  through the portal; the chooser named `org.mozilla.firefox` as a sandboxed caller.
- 2026-10-19: the GNOME fork's PIN dialog handled two wrong PINs, showed the final-attempt
  warning, then accepted the correct PIN and signed with the PIV card and SCR 331 reader.

The GNOME fork also ran in a live GNOME 50 session with that card: test-client signing,
Flathub Firefox sign-in, chooser hotplug and GNOME Shell's system PIN prompt.

Not yet run on hardware: one PIN per grant, Cancel on the final try, card removal during an
operation, a PIN-pad reader and a second card model. KDE live-session/card testing and the
OpenSSL 3 provider remain unrun.

## Known problems

- A WebKitGTK client-certificate handshake shows two choosers, because its UI and network
  processes are separate D-Bus peers and each needs a grant. Sharing a grant needs a frontend
  design ([ADR 0011](docs/decisions/0011-client-side-pkcs11-module.md)).
- Firefox's default selection setting adds its own certificate picker;
  [automatic selection](docs/TESTING.md#single-prompt-firefox-procedure) skips it.
- Firefox's NSS lists certificates by class alone; the module answers that search only with
  `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` or `x-init-reserved: enumerate=1` in its p11-kit
  module file. Direct NSS loading uses the environment switch. Enumeration may open a chooser
  ([search intent](docs/SECURITY.md#search-intent)).
- With no portal or backend running, `C_Initialize` succeeds and the module reports no slots.
- The shell's PIN prompter hands the PIN to this backend for `C_Login`; the backend keeps it in
  wiped, non-dumpable memory ([PIN handling](docs/SECURITY.md#pin-handling)).

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | components, responsibilities, sequences |
| [PUBLIC-INTERFACE](docs/PUBLIC-INTERFACE.md) | the interface applications call |
| [IMPL-INTERFACE](docs/IMPL-INTERFACE.md) | the backend interface and its validation rules |
| [SECURITY](docs/SECURITY.md) | threat model, PIN handling, grant scope, caller identity |
| [TESTING](docs/TESTING.md) | commands for every test tier, including real cards |
| [UPSTREAMING](docs/UPSTREAMING.md) | proposal status and remaining work |
| [ROADMAP](docs/ROADMAP.md), [SPIKES](docs/SPIKES.md) | planned work and feasibility evidence |
| [SOURCES](docs/SOURCES.md) | cited sources |
| [decisions](docs/decisions/) | architecture decision records |
| [CONTRIBUTING](CONTRIBUTING.md), [SECURITY policy](SECURITY.md) | working on the code, reporting vulnerabilities |

## Related repositories

- [xdg-desktop-portal-webauth](https://github.com/sjtrotter/xdg-desktop-portal-webauth): a
  WebAuthentication backend that used this portal for client certificates; development stopped
  2026-10-16.
- [entra-token-helper](https://github.com/sjtrotter/entra-token-helper): a Microsoft Entra ID
  token client built on the WebAuthentication portal.
- [xdg-desktop-portal fork](https://github.com/sjtrotter/xdg-desktop-portal): the frontend
  branches `experimental/certificate`, `experimental/webauthentication` and
  `experimental/integration`.

The proposal was announced on
[flatpak/xdg-desktop-portal#662](https://github.com/flatpak/xdg-desktop-portal/issues/662) and
[FreeRDP/FreeRDP#13328](https://github.com/FreeRDP/FreeRDP/pull/13328).

## License

LGPL-2.1-or-later, the license of xdg-desktop-portal and its GTK and GNOME backends, so code
can move between them ([ADR 0004](docs/decisions/0004-license.md)). `src/ui/external-window.c`
is adapted from libgxdp (LGPL-2.1-or-later) with its attribution kept. Applications that load
the PKCS#11 module load an LGPL library; applications that only use D-Bus are not affected.

## AI assistance

The code and documentation were written with AI assistance (Anthropic Claude, OpenAI Codex)
under the author's direction. The author is responsible for their content.

# xdg-desktop-portal-certificate

An xdg-desktop-portal **backend** for the experimental
`org.freedesktop.impl.portal.experimental.Certificate` interface, plus a **client-side PKCS#11
module** for applications that cannot call D-Bus. The backend discovers PKCS#11 tokens, draws the
certificate chooser and the PIN prompt, and performs private-key operations when
xdg-desktop-portal asks it to. The PIN never reaches the application, the private key never leaves
the card, and the application never holds a handle on the hardware token. The public portal
interface applications call is defined by a branch of xdg-desktop-portal itself, not by this
repository.

## Status

Experimental. Nothing here has been proposed upstream: no issue and no pull request. The author
posted two comments announcing the work on 2026-09-05, on flatpak/xdg-desktop-portal#662 and
FreeRDP/FreeRDP#13328.

| | State | |
|---|---|---|
| Token discovery, X.509 parsing, purpose rules, `certificate_filter` | Implemented | unit-tested against fixture certificates; `--list-tokens` prints what it found |
| Chooser and PIN prompt | Implemented | own GTK window, or the desktop shell's system prompter with gcr-4 (`--pin-prompt=auto\|gtk\|system`) |
| Brokered `Sign`: `RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA` | Implemented | all three verified against SoftHSM; `RSA_PKCS1_V1_5` and `RSA_PSS` also against a PIV card |
| Token insertion and removal watching, `SessionInvalidated` | Implemented | polled and debounced; never exercised with a card physically leaving a reader |
| Client-side PKCS#11 module | Implemented | one token, one credential per process; driven by GnuTLS, NSS and WebKitGTK |
| Test suites | Implemented | 13 meson suites with gcr-4, 12 without; an ASan/UBSan build and a DER corpus replay |
| Real hardware | Partial | see below |
| Chain building | Partial | `chain_status` is always `leaf_only`, and says so |
| Decryption | Not on the interface | the broker and the module contain `RSA_OAEP` code, and no interface exposes a `Decrypt` method for anything to call |
| One grant across an application's processes | Not implemented | a grant belongs to the D-Bus peer that acquired it, so one WebKitGTK handshake raises two choosers |
| The synthetic PKCS#11 facade (`OpenPkcs11Endpoint`) | Not implemented | on neither interface, and not being built; [0011](docs/decisions/0011-client-side-pkcs11-module.md) replaced it |
| Two concurrent grants in one process, rate limiting, fork safety in the module | Not implemented | `module.c` claims no fork safety |
| Attesting what a signature is *for* | Not implemented | `purpose` constrains selection and consent language and proves nothing about use |
| Flatpak, KDE, translation, packaging | Not implemented | installing the module inside a runtime, its ABI, and a browser's inner sandbox are unproven |
| Independent security review, a second maintainer, a second card stack | Not done | |

**The hardware evidence is one card.** One PIV card, one reader, OpenSC, GNOME 50 on Wayland.

- **2026-09-04**. [docs/TESTING.md](docs/TESTING.md) tiers 3.1–3.4: discovery, the private-bus
  happy path, cancel, and a run on the real session bus, through both PIN paths.
- **2026-09-05**. A live Microsoft Entra ID sign-in: the WebAuthentication portal window, the
  client-certificate challenge, WebKit's network process, the PKCS#11 module, this backend's
  chooser, the shell's PIN prompt, an RSA-PSS signature, and the authorization code returned to
  the caller. Later the same day the full chain reached an Azure Virtual Desktop session.
- **2026-09-06**. Firefox, fresh profile, module loaded from Security Devices with
  `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1`, signed in to a site requiring a client certificate.

Unrun: TESTING 3.5 (one PIN per grant), 3.6 (wrong PIN and `FINAL_TRY`), card removal during an
operation, a PIN-pad reader, a second card, a Flatpak runtime, KDE, and the OpenSSL 3 provider.

## How it works

```
  application ──── org.freedesktop.portal.experimental.Certificate ────┐
                   on org.freedesktop.portal.Desktop                   │
                                                                       ▼
                                                   ┌───────────────────────────────────┐
                                                   │ FRONTEND  xdg-desktop-portal      │
                                                   │ branch experimental/              │
                                                   │   certificate-webauthentication   │
                                                   │ app id · policy · permissions ·   │
                                                   │ grants, expiry, clamping ·        │
                                                   │ request and session lifecycle     │
                                                   └───────────────────┬───────────────┘
                                                                       │
                    org.freedesktop.impl.portal.experimental.Certificate│ app_id is an
                    on org.freedesktop.impl.portal.desktop.certificate  │ ARGUMENT here
                                                                       ▼
                                                   ┌───────────────────────────────────┐
                                                   │ BACKEND: THIS REPOSITORY          │
                                                   │ chooser · PIN prompt ·            │
                                                   │ PKCS#11 session · Sign            │
                                                   └───────────────────┬───────────────┘
                                                                       ▼
                                                        p11-kit → OpenSC → pcscd → card
```

An application calls `AcquireCredential` naming a purpose. The frontend works out who is asking
and whether it may ask; this backend shows a chooser naming the application the frontend
identified, how well it is identified, the purpose in the backend's own words, and the candidate
certificates. The grant that comes back holds the chosen certificate as DER, its chain status, the
key's type and mechanisms, the permitted operations and an expiry. The application then asks the
frontend to `Sign`; this backend prompts for the PIN in its own window (or hands the field to the
shell's prompter), logs into its own PKCS#11 session, and returns the signature.

Applications that reach TLS and S/MIME through PKCS#11 rather than D-Bus (WebKitGTK's network
process, Firefox, Thunderbird, LibreOffice) load `libpkcs11-portal-certificate.so`
([`src/module/`](src/module/)) instead. p11-kit loads it into the application's own process, where
it turns `C_Sign` into the portal's `Sign`. It links none of this backend. The application sees one
token, `Portal Certificate`, holding the one certificate the user picked; the token advertises
`CKF_PROTECTED_AUTHENTICATION_PATH`, so there is no PIN field in the application. The module is
opt-in by process name (`enable-in:` in `xdg-desktop-portal-certificate.module`) and is not a trust
boundary; the portal is. [0011](docs/decisions/0011-client-side-pkcs11-module.md) has the detail.

### Why not

- Why not wrap a chooser around `p11-kit server`, which hands the application the whole token and
  does not solve PIN ownership: [0006](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md).
- Why not forward PKCS#11 instead of brokering operations:
  [0007](docs/decisions/0007-brokered-operations-are-the-core.md).
- Why not serve a PKCS#11 endpoint from this process rather than shipping a module:
  [0011](docs/decisions/0011-client-side-pkcs11-module.md).
- Why not let the application draw the PIN prompt:
  [0002](docs/decisions/0002-service-owned-pin-prompt.md).
- Why the frontend is not in this repository:
  [0010](docs/decisions/0010-backend-only-frontend-lives-upstream.md).

## Interface at a glance

**Public**, `org.freedesktop.portal.experimental.Certificate` on
`org.freedesktop.portal.Desktop`. Defined by the frontend branch, not here; summarised in
[docs/PUBLIC-INTERFACE.md](docs/PUBLIC-INTERFACE.md).

| | |
|---|---|
| `CreateSession` | opens a session; the session handle comes back in the Response |
| `AcquireCredential` | consent and selection; returns the grant. A session acquires once |
| `Sign` | prehashed signature under an existing grant |
| `GetCapabilities` | mechanisms and operations this backend can offer |
| `Session.Close` | ends the grant |
| `GrantInvalidated` | to the session's owner only: `expired`, `token_removed`, `policy`, `backend_gone`, `error` |

`AcquireCredential` options: `handle_token`, `activation_token`, `purpose` (`client_auth`,
`signing`, `email`, `ssh`; required), `certificate_filter`, `operation_policy` (`sign` is the only
key), `requested_lifetime` (clamped), `interaction_mode`, `reason`.

**Private**, frontend to backend, `org.freedesktop.impl.portal.experimental.Certificate` on
`org.freedesktop.impl.portal.desktop.certificate`. Described in
[docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md), declared in
[`data/org.freedesktop.impl.portal.experimental.Certificate.xml`](data/org.freedesktop.impl.portal.experimental.Certificate.xml),
which is a copy of the branch's file with a provenance comment added, and must track it. **Applications do not call this.**

| | |
|---|---|
| `CreateSession` | `(o handle, o session_handle, s app_id, a{sv}) → (u, a{sv})` |
| `AcquireCredential` | `(o handle, o session_handle, s app_id, s parent_window, a{sv}) → (u, a{sv})` |
| `Sign` | `(o handle, o session_handle, s app_id, s parent_window, a{sv}) → (u, a{sv})` |
| `GetCapabilities` | `(s app_id, a{sv}) → a{sv}` |
| `SessionInvalidated` | the backend's half of `GrantInvalidated` |

Every impl call carries `app_id`, `GetCapabilities` included. The backend never derives it.

## Try it

```console
$ meson setup build
$ ninja -C build
$ meson test -C build
$ ./build/src/xdg-desktop-portal-certificate --list-tokens
```

Dependencies: GLib/GIO, GTK 4, libadwaita, p11-kit and GnuTLS. Not libdex: that is the frontend
branch's dependency. gcr-4 is optional (`-Dgcr=auto`) and is what adds `--pin-prompt=system`;
`-Dp11_module_path=` and `-Dp11_module_configs=` say where the PKCS#11 module and its p11-kit
module file are installed.

`--list-tokens` prints one block per security token and one entry per usable certificate, without
logging in and without asking for a PIN. Only hardware tokens are offered by default (a slot that
does not set `CKF_HW_SLOT` is skipped, and printed with a `SKIPPED` line saying why);
`--allow-software-tokens` turns that off, and `--module PATH` names a module directly, in which
case nothing else is loaded.

The end-to-end stack needs the frontend branch:

```console
$ XDP_BUILD=/path/to/xdg-desktop-portal/build tools/dev-stack.sh --softhsm
```

starts `xdg-permission-store`, this backend and a development frontend inside `dbus-run-session`
with `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate`, then runs
[`tools/certificate-e2e.py`](tools/certificate-e2e.py) against the public interface and verifies
the signature it gets back. With no token at all, `-- --expect-no-certificate` asserts the clean
refusal instead. `--live` does the same on the real session bus, which is what a run
with a real card needs; `--keep` leaves the stack up; `--softhsm` points the backend at a fixture
token from [`tools/softhsm-fixture.sh`](tools/softhsm-fixture.sh).

Other scripts: [`tools/ui-smoke.sh`](tools/ui-smoke.sh) drives the chooser and the PIN prompt with
xdotool under Xvfb; [`tools/module-smoke.sh`](tools/module-smoke.sh) drives the PKCS#11 module with
`p11tool`, `pkcs11-tool --sign` and a real mutual-TLS handshake;
[`tools/nss-smoke.sh`](tools/nss-smoke.sh) does the NSS equivalent with `modutil`, `certutil` and
`tstclnt`; [`tools/trigger-certificate.sh`](tools/trigger-certificate.sh) pokes one method at a
time with `gdbus`. [docs/TESTING.md](docs/TESTING.md) has the exact commands.

To select this backend explicitly, put in `portals.conf`:

```ini
[preferred]
org.freedesktop.impl.portal.experimental.Certificate=certificate
```

## Related repositories

- <https://github.com/sjtrotter/xdg-desktop-portal-webauth>. The sibling backend for the
  WebAuthentication portal, and the first consumer of this one. `src/module/portal-token.h` is
  shared with it verbatim, because a PKCS#11 URI is all that crosses between the two.
- <https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/certificate-webauthentication>
  The frontend fork branch that defines both public interfaces. 10 commits on upstream `86bd3e2`,
  tip `1aaffaf`; the Certificate portal is commit `a4c1f62`. Its `tests/test_certificate.py` is 26
  test functions, 49 parametrised cases, 98 runs across the host and Flatpak fixtures, all green
  against a python-dbusmock backend. Pushed to that fork and proposed to nobody.
- <https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/certificate-webauthentication+delegation>
  The archived earlier version with process-tree delegation, tip `209f9ff`.

## Known problems and open questions

- **One WebKitGTK handshake raises two choosers.** The UI process builds the `GTlsCertificate` and
  the network process uses the key, so each acquires its own grant. With Firefox the user sees the
  portal chooser, Firefox's own certificate picker and the PIN prompt: three dialogs. One chooser was only ever achieved on the archived `+delegation` branch,
  and process-tree delegation cannot work for a Flatpak caller, whose app-info pidfd is the sandbox
  instance's rather than the calling process's. Not fixable inside the module.
- **A search that names no object does not raise a chooser**, so a class-only enumeration, which
  is what NSS's certificate lookup and therefore Firefox's client-authentication path is, needs
  `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1`. Issuer, subject, serial and trust-category searches
  answer nothing while there is no grant, because GnuTLS sends them at every handshake and
  answering them with a window put a chooser in front of a user who had only opened a page.
- **Decryption is written and unreachable.** `RSA_OAEP` code exists in the broker and in the
  module; neither interface has a `Decrypt` method and `GetCapabilities` does not advertise one.
  It should be removed, or added to a future interface proposal; it should not stay as it is.
- **`chain_status` is always `leaf_only`.** No chain is built.
- **The module offers no slot when there is no portal or the experimental gate is off**, and
  `C_Initialize` still succeeds. It must not be enabled inside xdg-desktop-portal or inside this
  backend; it refuses to run there three ways, and neither is on the shipped allowlist.
- **`--pin-prompt=system` moves where the PIN is typed, not whether this process holds one.**
  `C_Login` takes a PIN, so it still arrives here, into the same locked, wiped, non-dumpable page.
- **No independent security review has been done**, and there is no second card stack, no second
  maintainer, and no packaging.

## Documents

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, the frontend/backend responsibility split, sequences, process model |
| [docs/PUBLIC-INTERFACE.md](docs/PUBLIC-INTERFACE.md) | the interface applications call, and a pointer to the branch's XML |
| [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md) | the interface this backend implements, and why the XML here is a tracking copy |
| [docs/UPSTREAMING.md](docs/UPSTREAMING.md) | where the frontend branch is and what remains before a pull request |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, PIN handling, grant scoping, caller identity, what runs in the application's process |
| [docs/TESTING.md](docs/TESTING.md) | the exact commands, including the runs with a card in a reader |
| [docs/SPIKES.md](docs/SPIKES.md) | the questions that decide whether this is buildable, and their answers |
| [docs/ROADMAP.md](docs/ROADMAP.md) | phases, effort estimate, and its assumptions |
| [docs/SOURCES.md](docs/SOURCES.md) | the primary source behind every claim made here about another system |
| [docs/decisions/](docs/decisions/) | the ADRs |
| [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) | how to work on it, and how to report a vulnerability |

## License

LGPL-2.1-or-later, matching `xdg-desktop-portal`, `xdg-desktop-portal-gtk` and
`xdg-desktop-portal-gnome`, so code can move into any of them without a relicensing step; the
reasoning is in [0004](docs/decisions/0004-license.md). The one piece of derived code is
`src/ui/external-window.c`, adapted from libgxdp (also LGPL-2.1-or-later) with its attribution
kept. No code was copied from Remmina's RDP plugin. Consumers that only speak D-Bus are unconstrained by the licence;
those that load the PKCS#11 module load an LGPL library.

## AI assistance

The code and documents here were written with AI assistance, Anthropic Claude and OpenAI Codex,
under the author's direction. The author is responsible for every claim in them. Prior-art
citations were checked against primary sources, listed in [docs/SOURCES.md](docs/SOURCES.md); where
a source confirmed less than a claim did, the claim was narrowed and the entry says so.

# xdg-desktop-portal-certificate

**This repository is an xdg-desktop-portal BACKEND.** It is not a portal, it owns no
public interface, and no application talks to it. It draws a certificate chooser and a PIN
prompt, discovers PKCS#11 tokens, and performs private-key operations when
xdg-desktop-portal asks it to.

**Status: EXPERIMENTAL, implemented, run against one real card.** It builds, it runs, it
finds PKCS#11 tokens, it draws a chooser and a PIN prompt, and it signs. Driven by the
frontend branch it has completed `CreateSession` → `AcquireCredential` → `Sign` end to end,
with the signature verified against the certificate it returned: RSA PKCS#1 v1.5, RSA-PSS
and ECDSA signatures and RSA-OAEP decryption against a SoftHSM fixture token, and RSA
PKCS#1 v1.5 signatures against a PIV card.

**The real-hardware claim is narrow.** [docs/TESTING.md](docs/TESTING.md) tier 3 is the run
against a real card; tiers 3.1–3.4 passed once, on 2026-09-04, with one PIV card in one reader,
on a GNOME Wayland session, through both PIN paths (this backend's window and gnome-shell's
system prompter). On 2026-09-05 the same card signed a real Microsoft Entra sign-in for an Azure
Virtual Desktop tenant through the web-auth portal consumer: one chooser at the certificate
challenge, one PIN, the authorization code returned to the caller. That is one card, one reader
and one identity provider, not a claim about PIV hardware in general, and the rest of tier 3 is
still the author's to run.

**There is now a PKCS#11 path for applications that cannot call D-Bus** — a module loaded into
the application's own process, not an endpoint served from here. A GnuTLS mutual-TLS handshake
has completed through it, driven by `g_tls_certificate_new_from_pkcs11_uris()`, and **so has a
real WebKitGTK one**: `xdg-desktop-portal-webauth` signs in through this backend's chooser and PIN
prompt, headless, with the card's common name in the server's log
([docs/TESTING.md](docs/TESTING.md) §2.55). See "For applications that speak PKCS#11" below,
[0011](docs/decisions/0011-client-side-pkcs11-module.md), and
[docs/SPIKES.md](docs/SPIKES.md) for what that does and does not answer. The socket-served
facade `OpenPkcs11Endpoint` would have reached is not being built.

> The GitHub repository was renamed `xdg-desktop-portal-certificate` to match the binary on
> 2026-09-04 — see [0009](docs/decisions/0009-name-it-certificate.md), which is why the
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

The frontend is a local-only branch, `experimental/certificate-webauthentication`, 18
commits on top of upstream `c95490a` — currently `bcedf85..209f9ff`, and rebased, so the
ids move and the count is the stable part. It has been built and tested (106 pytest cases
for this portal, all green, against a python-dbusmock backend) and **has not been proposed
to anyone**. Its
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
not spend. Almost nobody does this. It is why smart-card sign-in works in the applications
that load a PKCS#11 module themselves — Firefox, Thunderbird, Chromium — and in
approximately nothing else on the desktop. LibreOffice and Evolution look like exceptions
and are not: they sign through NSS and load no module of their own, so they see a card only
where the *distribution* has made NSS load `p11-kit-proxy.so`, which is a Fedora patch
rather than upstream behaviour [[S54](docs/SOURCES.md)].

**Get blanket access.** A Flatpak asks for [`--socket=pcsc`](https://docs.flatpak.org/en/latest/sandbox-permissions.html)
[[S43](docs/SOURCES.md)] and is then talking to `pcscd` directly: every card, every reader, every
slot, every APDU, for the lifetime of the application, with no user-visible moment of consent.
That is how Firefox's Flatpak does it today, because there is nothing else
[[S53](docs/SOURCES.md)]. Chromium's Flathub manifest does not take that socket — it takes
`--device=all` and `--filesystem=home`, which is broader rather than narrower.

Both failures compound into a third: **there is no window the user can learn to trust.** The PIN
prompt is the moment a person authorises a hardware token to authenticate as them. Today that
prompt looks different in every application, is drawn by the application asking for it, and is
therefore trivially imitable.

## What other systems do

| | Mechanism | Who owns the PIN prompt |
|---|---|---|
| **Windows** | Card minidriver under the [Base CSP / smart card KSP](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture); applications use CNG and certificates appear in the store by propagation | The OS — the Base CSP/KSP layer owns PIN entry and caching [[S51](docs/SOURCES.md)] |
| **macOS** | [CryptoTokenKit](https://developer.apple.com/documentation/cryptotokenkit) driver publishes token keys into the Keychain; applications use ordinary Keychain/`SecKey` APIs | The system — a token extension "has no UI component" [[S52](docs/SOURCES.md)] |
| **Linux** | PKCS#11 module loaded directly into every application that cares | Whichever application drew a dialog first |

The Linux row is the whole reason for this project. The interesting part of the other two rows is
not the cryptography — PKCS#11 and OpenSC already do that well. It is that **the credential is
used through an OS-brokered API, the consent decision and the PIN prompt belong to the system, and
the application never holds the key.** Note what those systems do *not* do: neither hands the
application a raw, general-purpose token interface and calls it mediation.

## The design, in one paragraph

xdg-desktop-portal brokers cryptographic credentials the way
[`org.freedesktop.portal.Camera`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Camera.html)
brokers cameras: it does not hand over the device, it hands back a PipeWire file descriptor
[[S38](docs/SOURCES.md)]. An application calls `AcquireCredential` naming a purpose. The
**frontend** works out who is asking and whether it may ask; **this backend** — not
the application — shows a chooser naming the application *the frontend identified*, how well it is
identified, the purpose in the backend's own words, and the candidate certificates on each token;
the frontend returns a **grant**: the chosen certificate as DER, its chain and chain status, the
key's type and mechanisms, the permitted operations, and an expiry. The application then asks the
frontend to **`Sign`**; the frontend checks the grant and forwards; this backend prompts for the PIN in its own window, logs into its own PKCS#11 session,
performs the operation and returns the result.
The PIN never crosses D-Bus, the private key never leaves the card, and the application never holds
a PKCS#11 handle. `Sign` is the whole of it: the interface has no `Decrypt`, and this backend does
not advertise one. [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md) has the detail.

## Current capabilities

**This table is the one place that says what works.** Every other document in this repository
defers to it; where one of them disagrees, this is right and it is a bug. Last checked 2026-09-05.

| | Status | |
|---|---|---|
| Token discovery, X.509 parsing, purpose rules, `certificate_filter` | **Implemented** | unit-tested against fixture certificates; `--list-tokens` prints what it found |
| The chooser and the PIN prompt | **Implemented** | GTK window or the desktop shell's prompter (`--pin-prompt`), protected authentication path, retry, final-try confirmation, login timeout |
| Brokered `Sign` — `RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA`, lazy login | **Implemented** | verified against SoftHSM and, once, against a PIV card |
| Brokered decryption — `RSA_OAEP` and nothing else | **Not on the interface** | the broker implements it, with one indistinguishable error per failure and 32 attempts per grant, and nothing can ask for it: the first proposal has no `Decrypt` method and `GetCapabilities` does not advertise `decrypt` |
| Token insertion and removal watching, `SessionInvalidated` | **Implemented** | polled and debounced. Never exercised with a card physically leaving a reader |
| The client-side PKCS#11 module | **Implemented** | one token, one credential per process. `tools/module-smoke.sh` drives `p11tool`, `pkcs11-tool --sign` and a real mutual-TLS handshake through it |
| The private-bus stack, the headless UI runs, the joint run with the web-auth portal | **Implemented** | `tools/dev-stack.sh`, `tools/ui-smoke.sh`, and the sibling repository's `tools/portal-stack.sh` |
| Hardware | **Partial** | **one PIV card, one reader, one middleware, once** — [TESTING.md](docs/TESTING.md) tiers 3.1–3.4, 2026-09-04. The rest of tier 3 is unrun: one PIN per grant, wrong PIN and `FINAL_TRY`, removal during an operation, a PIN-pad reader, a second card |
| Consumers of the module | **Partial** | GnuTLS through p11-kit, and WebKitGTK's network process, both proven headless. **NSS is untested** (Firefox, Thunderbird, LibreOffice) and so is the OpenSSL 3 provider |
| One grant across an application's processes | **Not implemented** | a grant belongs to the D-Bus peer that acquired it, so one WebKitGTK handshake loads the module in two processes and raises **two choosers**. The process-tree delegation that fixed it came out of the proposal and is archived on `experimental/certificate-webauthentication+delegation`. [0011](docs/decisions/0011-client-side-pkcs11-module.md) |
| Chain building | **Partial** | `chain_status` is always `leaf_only`, and says so |
| Flatpak | **Partial** | the portal bus name is already allowed, which is the transport half. Installing the module inside a runtime, its ABI and a browser's inner sandbox are **not** proven |
| Two concurrent grants in one process | **Not implemented** | [0006](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) failure mode 8, deferred because no consumer has asked |
| Rate limiting | **Not implemented** | on either side of the bus. The three-attempt cap on one PIN window is not one |
| Attesting what a signature is *for* | **Not implemented** | failure mode 10. `purpose` constrains selection and consent language, and proves nothing about use |
| Fork safety in the module | **Not implemented** | a consumer that forks after `C_Initialize` gets a worker thread the child does not have |
| The synthetic PKCS#11 facade | **Not implemented** | and not being built: `OpenPkcs11Endpoint` is on neither interface, and [0011](docs/decisions/0011-client-side-pkcs11-module.md) replaced it |
| Translation, packaging, a KDE backend | **Not implemented** | — |
| Independent security review, a second maintainer, a second card stack | **Not implemented** | the gap every reviewer named first |

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
                 operation_policy { sign }
                 requested_lifetime (clamped to 3600), interaction_mode,
                 reason (untrusted)
  Sign               (o session, s parent_window, a{sv}) → o handle      [Request]
  GetCapabilities    (a{sv})                             → a{sv}
  signals: GrantInvalidated (to the session's owner only)

  A grant ends with org.freedesktop.portal.Session.Close(). A session acquires
  once: a second credential is a second session and a second consent.
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
  Sign              (o handle, o session_handle, s app_id, s parent_window,
                     a{sv} options) → (u response, a{sv} results)
  GetCapabilities   (s app_id, a{sv} options) → a{sv}
  signals: SessionInvalidated
```

Every impl call carries `app_id` — including `GetCapabilities`, which is one of the things
the move upstream changed. That is the whole point of the boundary.

## For applications that speak PKCS#11

WebKitGTK's network process, Firefox, Thunderbird and LibreOffice reach TLS and S/MIME through
PKCS#11, not through D-Bus. They cannot call the interface above and they are not going to be
rewritten to. They can, however, all load a p11-kit module.

So there is one: **`libpkcs11-portal-certificate.so`**, in
[`src/module/`](src/module/), installed into p11-kit's module directory with
`xdg-desktop-portal-certificate.module`. p11-kit loads it **into the application's own
process**, and it turns
`C_Sign` into the portal's `Sign` over the public D-Bus interface. It is not part of this backend
and links none of it.

```
  application ── PKCS#11 ─▶ libpkcs11-portal-certificate.so ── D-Bus ─▶ xdg-desktop-portal
                                (in the application)                          │  impl
                                                                              ▼
                                                                        this backend ─▶ the card
```

What the application sees is one token, `Portal Certificate`, holding the one certificate the user
picked in the portal's chooser, its public key and its private key. The chooser appears the first
time the application searches **for this token's credential** — by the object label, by a
`CKA_ID`, or for the private key. There is no PIN prompt in the application: the token advertises
`CKF_PROTECTED_AUTHENTICATION_PATH` [[S12](docs/SOURCES.md)], `C_Login` succeeds without doing
anything, and the backend asks for the PIN in its own window at the first signature.

```console
$ PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1 \
    p11tool --provider ./build/src/module/libpkcs11-portal-certificate.so --list-all
# ... the chooser appears, and then:
Object 0:
	URL: pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate;id=...;object=Portal%20Certificate;type=cert
	Type: X.509 Certificate (RSA-2048)
```

The environment variable is there because **a search that names no object does not raise a
chooser**, and `--list-all` is exactly that search. GnuTLS verifying any *server's* certificate
chain sends issuer and subject lookups into p11-kit at every handshake, and on the system this was
measured on they reached this module [[S19](docs/SOURCES.md)]; answering those with a window put a
chooser in front of a user who had only opened a sign-in page. Issuer, subject, serial,
trust-category and class-only searches now answer
nothing while there is no grant, and never prompt. A URI naming `object=Portal%20Certificate` — the
one an application actually imports by — does, which is why nothing above this line needs the
variable.

The URIs an application writes down are constants, and they are in
[`src/module/portal-token.h`](src/module/portal-token.h) — **a file shared verbatim with the
web-auth backend, because a URI is all that crosses between the two projects**:

```
pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate;type=cert
pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate;type=private
```

**For `g_tls_certificate_new_from_pkcs11_uris()`, append `;object=Portal%20Certificate`.** That is
not decoration and it is not optional: GnuTLS's *single-object* import refuses a URI that names no
object and wants `object=` (`CKA_LABEL`) or `id=` [[S17](docs/SOURCES.md)], while *enumeration* —
`p11tool --list-all`, `gnutls_pkcs11_obj_list_import_url4` — is happy with the token URI above
[[S18](docs/SOURCES.md)]. The constructor itself takes no module argument, so the module has to be
configured in p11-kit before the URI can resolve [[S20](docs/SOURCES.md)]. `CKA_LABEL` is therefore
a constant rather than the certificate's common name, which an application could not know in
advance; the certificate's real identity is in its DER.

Three things worth knowing before enabling it:

- **With no portal, or with the experimental gate off, the module offers no slot** and
  `C_Initialize` still succeeds. An application that loads every configured module must not break
  because one of them has nothing to say.
- **It must not be enabled inside xdg-desktop-portal or inside this backend.** The backend
  enumerates p11-kit modules; this one answers by calling the portal that calls the backend. It
  refuses to run there three separate ways, and neither is on the shipped allowlist.
- **The module is opt-in by name.** The shipped `xdg-desktop-portal-certificate.module` carries
  `enable-in: xdg-desktop-portal-webauth, WebKitNetworkProcess` — the two processes one mutual-TLS
  handshake through WebKitGTK needs — and no other consumer loads it. p11-kit matches the base name
  of `argv[0]` [[S5](docs/SOURCES.md)]. Add `firefox, thunderbird` (the file has the line
  commented, with the NSS caveat) or write your own file into `~/.config/pkcs11/modules`, whose
  fields take precedence over the system file of the same name [[S7](docs/SOURCES.md)]. Do not
  add `disable-in` beside `enable-in`: `pkcs11.conf(5)` says not to set both, and p11-kit consults
  only the allowlist when both are there [[S5](docs/SOURCES.md), [S6](docs/SOURCES.md)]. Neither
  list is a security feature; both decide where a window may appear.

Environment, for a consumer that knows more than PKCS#11 lets it say:
`PKCS11_PORTAL_CERTIFICATE_PURPOSE` (`client_auth` by default),
`PKCS11_PORTAL_CERTIFICATE_REASON`, `PKCS11_PORTAL_CERTIFICATE_KEY_ALGORITHMS`,
`PKCS11_PORTAL_CERTIFICATE_DISABLE=1`, and
`PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` to let a class-only enumeration acquire a credential (for
NSS experiments; documented as an experiment in
[ADR 0011](docs/decisions/0011-client-side-pkcs11-module.md)).

[`tools/module-smoke.sh`](tools/module-smoke.sh) runs the whole thing — `p11tool`, `pkcs11-tool
--sign` verified with `openssl`, and a real mutual-TLS handshake — under Xvfb with xdotool
answering the chooser. A **real** consumer has since been driven through it end to end as well:
`xdg-desktop-portal-webauth`'s `tools/portal-stack.sh` runs both portals on one private bus, and a
WebKitGTK sign-in completes with the private key on the token
([docs/TESTING.md](docs/TESTING.md) §2.55).

**One handshake resolves the URI in two processes** — the application's own process builds the
`GTlsCertificate`, WebKit's network process uses the key — and that draws **two choosers** three
seconds apart. It is not fixable inside the module, because a grant belongs to the D-Bus peer that
acquired it. The process-tree delegation that did fix it is out of the proposal — it cannot work
for a Flatpak caller, whose app-info pidfd is the sandbox instance's rather than the calling
process's, and ancestry alone crosses app boundaries — and is archived on
`experimental/certificate-webauthentication+delegation`. **The module is not a trust boundary; the
portal is.** [0011](docs/decisions/0011-client-side-pkcs11-module.md) says what the candidates are.

## Building, and running it

```console
$ meson setup build
$ ninja -C build
$ meson test -C build
$ ./build/src/xdg-desktop-portal-certificate --help
```

Dependencies: GLib/GIO, GTK 4, libadwaita, p11-kit and GnuTLS. **Not libdex** — that is the
frontend branch's dependency, not a backend's.

**gcr-4 is optional** (`-Dgcr=auto`). With it, the PIN can be asked for by the desktop
shell's own system prompter instead of by a window this backend draws:
`--pin-prompt=auto|gtk|system`, where `auto` — the default — means the system prompter when
`org.gnome.keyring.SystemPrompter` has an owner on the session bus or is activatable there
[[S55](docs/SOURCES.md)]. Without gcr-4 the option does not
exist and the in-process window is the only prompt. **What that moves is where the PIN is
typed, not whether this process holds one**: `C_Login` takes a PIN, so it still arrives
here, into the same locked, wiped, non-dumpable page.
[docs/SECURITY.md](docs/SECURITY.md#where-the-field-is-drawn-and-what-that-moves) is the
table of what changes and what does not.

### Is there a card, and what is on it

```console
$ ./build/src/xdg-desktop-portal-certificate --list-tokens
```

prints one block per security token — label, manufacturer, model, a truncated serial,
reader, module, whether the slot says it is hardware, whether login is required and whether
the reader has a PIN pad — and then one entry per **usable** certificate: subject, issuer,
expiry (marked when expired), key type and size, the mechanisms the token advertises for it,
the purposes it fits, the PIV slot where that could be determined, and its stable id.
Nothing is logged in for this and no PIN is asked for.

**Only hardware tokens are offered by default.** p11-kit on an ordinary desktop presents
software key stores as tokens — the GNOME keyring's module is the usual one — and a window
headed "security token" that offers keys out of the user's home directory says something
untrue about where the key is. A token whose slot does not set `CKF_HW_SLOT`
[[S11](docs/SOURCES.md)] is skipped, and `--list-tokens` prints it anyway with a `SKIPPED`
line saying why. `--allow-software-tokens`
turns the default off. It is a default and **not a security boundary**: the flag is a claim
by a module that is already loaded into this process.

If p11-kit is not configured for your card's module, name it:

```console
$ ./build/src/xdg-desktop-portal-certificate \
      --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-tokens
```

`--module` is repeatable, when it is given **nothing else is loaded**, and naming a module
also lifts the hardware-only default for it — naming it is already the deliberate act.

### The whole stack, on a private bus

```console
$ tools/dev-stack.sh -- --expect-no-certificate
```

starts, inside `dbus-run-session`: `xdg-permission-store` (the portal refuses to start
without it), this backend, and a development xdg-desktop-portal from the branch with
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate` and an `XDG_DESKTOP_PORTAL_DIR`
pointing at a throwaway copy of the machine's portal configuration — a symlink to every
`.portal` installed here, this repository's, and the machine's effective `portals.conf` with
one line added — because setting that variable makes the frontend ignore every other portal
directory *and* every other `portals.conf`, so a directory holding only ours leaves the
stack with no settings portal and no file chooser. Then it runs the end-to-end client. Point it at your frontend
build with `XDP_BUILD=/path/to/xdg-desktop-portal/build`, and put the `LD_LIBRARY_PATH` its
libdex needs in `.xdp-env`.

`--live` does the same on your real session bus, with the frontend replacing the system one
— which is what a run against a real card needs, because the windows have to appear on your
display. `--keep` leaves the stack up. `--softhsm` points the backend at a fixture token
from `tools/softhsm-fixture.sh`.

### The client

```console
$ tools/certificate-e2e.py --purpose client_auth --reason "Sign in to the VPN"
$ tools/certificate-e2e.py --capabilities
$ tools/certificate-e2e.py --close          # acquire a grant and release it, no signature
```

talks to the **public** interface on `org.freedesktop.portal.Desktop`, exactly as an
application would, and then verifies the signature it got against the certificate that came
back. With the experimental gate off it says so and exits 40; that is the gate working.
`tools/trigger-certificate.sh` is the same idea with `gdbus`, for poking one method at a
time.

### What the windows look like

**The chooser** — *Use a Certificate* — leads with the application: the name resolved from
its desktop file if there is one, the raw app id, and, in words, how well the frontend knows
it ("Sandboxed application, identity verified by the system", or a warning that it is
unsandboxed, or that it could not be identified at all). Then the purpose in this backend's
own words. Then, only if the application sent one, its `reason` — sanitised to a single line,
quoted, inside a frame labelled *The application says*, and never in the position where the
application's identity goes. Then the certificates, each with subject, issuer, validity
(with **EXPIRED** as a word, not a colour), key type and size, token label and reader. Then
what the grant allows and for how long, and whether more operations can happen without
another prompt. Then Cancel and Use Certificate. Escape cancels, and so does `Close()` from
the frontend.

**The PIN prompt** — *Unlock Security Token* — appears at the **first signature**, not when
the grant is made, and names the application, the purpose, the token and the reader. A
reader with a PIN pad gets an instruction with no editable field. A wrong PIN clears the
field and says so; nothing retries on its own, one prompt offers at most three attempts, and
once the token says this is the last one it takes a second, explicit confirmation to spend
it. The PIN is copied into a locked buffer, wiped on every exit path, and never crosses the
portal interfaces in either direction — there is no field on either one it could travel in.

On a GNOME session that prompt is **drawn by the shell**, not by this backend: the field
belongs to gnome-shell's system prompter and the typed characters reach this process through
gcr's secret exchange. `--pin-prompt=gtk` asks for the in-process window instead, and the
journal records which was used. The chooser is always this backend's own window; only the
PIN request moves.

Installed files: `$libexecdir/xdg-desktop-portal-certificate`,
`$datadir/xdg-desktop-portal/portals/certificate.portal` (the real directory — that is where
the frontend looks, and it is what every out-of-tree backend does),
`$datadir/dbus-1/services/org.freedesktop.impl.portal.desktop.certificate.service`, and the
interface XML in `$datadir/dbus-1/interfaces`. To select it explicitly, put this in
`portals.conf`:

```ini
[preferred]
org.freedesktop.impl.portal.experimental.Certificate=certificate
```

Layout:

```
src/          main.c, the impl interface, the impl Request and Session,
              tokens/    module loading, discovery, X.509 parsing, the filter
              broker/    the mechanism mapping, the device calls, the operation
              ui/        the chooser; the PIN prompt (pin.c decides, pin-gtk.c and
                         pin-system.c draw), window parenting
              export/    the facade's requirements; nothing can reach it yet
              redact.h   what may be logged, enforced by there being no other way
data/         the impl interface XML (verbatim copies of the branch's), certificate.portal,
              the D-Bus service file
tests/        the unit tests, their fixture certificates, and the SoftHSM device test
tools/        dev-stack.sh, certificate-e2e.py, softhsm-fixture.sh, ui-smoke.sh,
              module-smoke.sh, trigger-certificate.sh
docs/         architecture, both interfaces, security, testing, spikes, roadmap,
              upstreaming, sources, decisions
```

## Documents

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, the frontend/backend responsibility table, sequences, process model |
| [docs/PUBLIC-INTERFACE.md](docs/PUBLIC-INTERFACE.md) | a pointer to the branch's XML, and a summary |
| [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md) | the interface this backend implements, why the XML here is a tracking copy, and why applications cannot reach it |
| [docs/UPSTREAMING.md](docs/UPSTREAMING.md) | where the frontend branch is, what its XML forced this repository to change, and what remains before a PR |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, PIN handling, grant scoping, caller identity, what runs in the application's process |
| [docs/decisions/0011-client-side-pkcs11-module.md](docs/decisions/0011-client-side-pkcs11-module.md) | why the PKCS#11 surface is a module in the application rather than an endpoint served from here |
| [docs/TESTING.md](docs/TESTING.md) | **the exact commands**, including the run with a real card in a reader |
| [docs/SPIKES.md](docs/SPIKES.md) | the questions that decide whether this is buildable |
| [docs/ROADMAP.md](docs/ROADMAP.md) | phases, effort estimate, and its assumptions |
| [docs/SOURCES.md](docs/SOURCES.md) | the primary source behind every claim this repository makes about another system |
| [docs/decisions/](docs/decisions/) | why the shape is the shape |

## License

LGPL-2.1-or-later. This matches `xdg-desktop-portal`, `xdg-desktop-portal-gtk` and
`xdg-desktop-portal-gnome`, so code can move into any of them without a relicensing step; the
reasoning, and the earlier GPL-2.0-or-later decision this supersedes, are in
[docs/decisions/0004-license.md](docs/decisions/0004-license.md). No code was ever copied from
Remmina's RDP plugin; the hardware edge cases its smart-card path uncovered informed the discovery
code, but the implementation here is independent. The one piece of derived code is
`src/ui/external-window.c`, adapted from libgxdp (also LGPL-2.1-or-later, Red Hat) with its
attribution kept. Consumers only speak D-Bus, so the licence places no constraint on them.

## AI assistance

These documents and the code were written with AI assistance — Anthropic Claude and OpenAI
Codex — under the author's direction, and the author is responsible for every claim in them. The
prior-art citations were checked against primary sources, which are listed in
[docs/SOURCES.md](docs/SOURCES.md); where a source confirms less than the claim did, the claim was
narrowed and the entry says so.

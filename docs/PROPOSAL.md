# Certificate portal proposal

Status: draft for discussion, October 2026. Author and maintainer: Stephen J. Trotter.
Tracking: [flatpak/xdg-desktop-portal#662](https://github.com/flatpak/xdg-desktop-portal/issues/662).

This proposes an experimental portal that lets sandboxed applications use a private key on a
smart card for TLS client authentication without access to the card itself. A working
prototype exists. Its interface needs changes before an upstream frontend pull request, and
this document asks for review of those changes first.

## Problem

A Flatpak application that needs a smart-card certificate today gets `--socket=pcsc`. That
gives it the whole card: every key, raw APDUs, PIN verification with the retry counter, and
administrative commands such as `C_InitToken`. In the 2023 discussion on #662, Daiki Ueno
named bricking and PIN exhaustion as the threat, and Jonas Ådahl ruled out lists of trusted
applications because portals must assume a compromised application. Mozilla tracks the
same gap for Firefox packages in bugs
[1734371](https://bugzilla.mozilla.org/show_bug.cgi?id=1734371) and
[1896499](https://bugzilla.mozilla.org/show_bug.cgi?id=1896499); both are open.

The users are PIV and CAC holders (US federal and military), corporate certificate
authentication, and some national eID systems. They are a small group with a hard
requirement. Most can use a native browser today. The portal matters to those on
image-based desktops where Flatpak is the usual way to install a browser, and to
organizations that want sandboxed applications to have less than full card access.

## Threat model

The application is untrusted. The portal frontend, the backend, the card middleware and the
compositor are trusted. The user is present.

| Asset | Exposure without the portal | With the prototype (`Certificate1`) |
|---|---|---|
| Card administration | Any PKCS#11 or APDU call | None; the backend exposes signing only |
| PIN | Typed into the application | Typed into a backend dialog; never sent to the application |
| Retry counter | Application can submit PINs until the card locks | Application cannot submit PINs; the backend caps attempts per prompt and shows the token's retry flags when it reports them |
| Other keys on the card | All usable | Only the key the user chose |
| Certificate inventory | Readable without consent | Chosen certificate only, after consent; enumeration timing still differs |
| Signatures | Unlimited, unattributed | Bound to a grant with an expiry; consent logged with the app id |

The portal does not protect against a compromised application signing arbitrary data with a
key it holds a grant for. A signature grant over a digest cannot attest what the digest is;
the grant's lifetime is the limit (under the proposed changes below, the application
instance's lifetime). After successful enumeration, token presence and certificate-filter
matches remain behind consent
([#29](https://github.com/sjtrotter/xdg-desktop-portal-certificate/issues/29)); the new interface
must preserve that boundary. Enumeration timing and middleware failures remain observable.
[SECURITY.md](SECURITY.md) has the full model,
including PIN memory handling and the attacks a same-UID host process can still make.

## Prototype

| Part | Location | Revision |
|---|---|---|
| Frontend (`org.freedesktop.portal.experimental.Certificate1`) | [sjtrotter/xdg-desktop-portal `experimental/certificate`](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/certificate) | `7a0ff38` |
| Card library (`libxdp-certificate-core`), standalone GTK/libadwaita backend and PKCS#11 module | [sjtrotter/xdg-desktop-portal-certificate](https://github.com/sjtrotter/xdg-desktop-portal-certificate) | tag `proposal-2026-10` |
| GNOME backend, `-Dcertificate=enabled` | [sjtrotter/xdg-desktop-portal-gnome `experimental/certificate`](https://github.com/sjtrotter/xdg-desktop-portal-gnome/tree/experimental/certificate) on 50.0 | `28c933a` |
| KDE backend, `-DBUILD_CERTIFICATE_PORTAL=ON` | [sjtrotter/xdg-desktop-portal-kde `experimental/certificate`](https://github.com/sjtrotter/xdg-desktop-portal-kde/tree/experimental/certificate) on v6.7.5 | `1912e8b0` |

The frontend follows the experimental convention merged in #2129 and is enabled with
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=Certificate1`. The current interface:

- `CreateSession`, then `AcquireCredential(session, parent_window, {purpose, ...})`. The
  backend shows a chooser naming the application, the user picks one certificate, and the
  session receives a grant for that key with an expiry (default 300 s, at most 3600 s).
- `Sign(session, parent_window, {mechanism, parameters, data})`. The backend prompts for
  the PIN when the card needs it and returns the signature. RSA PKCS#1 v1.5, RSA-PSS and
  ECDSA are supported. Keys with `CKA_ALWAYS_AUTHENTICATE` get a PIN prompt per signature.
- `GrantInvalidated` on expiry, card removal or backend loss.

Existing TLS stacks do not call D-Bus, so the backend repository also ships a PKCS#11 module.
NSS or GnuTLS load it like any token; it presents the granted certificate and turns
`C_Sign` into a portal call. Firefox and Chrome need no code changes, but each needs the module
loaded: from Firefox's Security Devices settings, or registered in Chrome's NSS database. A
browser without the module never calls the portal. Nothing installs or loads the module
automatically today; how it should reach sandboxed applications is question 3 below.

### Evidence

The browser results below are from one PIV card in one reader with OpenSC on GNOME 50. Other hardware is
untested. Procedures and full results are in [TESTING.md](TESTING.md).

| Client | Setup | Result |
|---|---|---|
| Flathub Firefox, `--nosocket=pcsc --nodevice=all` | Module registered in a test profile | Portal chooser, Firefox's picker, portal PIN prompt; sign-in succeeded |
| Same | `security.default_personal_cert` set to "Select Automatically" | Portal chooser and PIN prompt only; sign-in succeeded |
| Flathub Chrome, no pcsc socket or devices | Module registered in Chrome's NSS database | Portal chooser, then Chrome's picker |
| Same | `AutoSelectCertificateForUrls` for the authenticating host | Portal chooser and PIN prompt only; sign-in succeeded |
| Either browser | Server whose CA list the card does not match | Portal chooser, then rejection; no PIN prompt |

The GNOME and KDE backends were run against the same frontend, PKCS#11 module, NSS and
GnuTLS clients with a SoftHSM token, in a Fedora 44 container under Xvfb: certificate choice,
PIN entry, RSA and ECDSA signatures, regrant, cancellation at each dialog, mutual TLS through
GnuTLS, and NSS across grant expiry. The GNOME backend has also run in a live GNOME 50
session with the PIV card: signing from the test client, sign-in from Flathub Firefox, the
chooser filling in when the card is inserted, and wrong PINs up to the final-attempt warning.
The KDE backend has not run in a live session or with a card.

Both browser settings are deployment policy. Firefox's applies to every site and every
certificate. Chrome's must name the host that requests the certificate, which for the tested
site was a Microsoft sign-in host the user never sees. A wildcard pattern with an issuer
filter is untested. Neither setting is a reasonable default for consumers.

## Problems with the current interface

The browser case exposes the design's main fault: two choosers. The portal asks which
certificate before the browser has a choice to make, then the browser asks again. The PKCS#11
module also cannot tell the portal which site is asking, whether the request comes from a
private window, or whether the browser is listing certificates for its certificate manager
rather than authenticating. Opening Firefox's certificate manager opens the portal chooser.

Grants are per D-Bus connection. A browser that loads the module in more than one process
gets one chooser per process.

## Proposed changes

The change is breaking, so the interface would become `Certificate2`.

1. Access before selection. `RequestAccess(session, parent_window, {purpose, reason, filter})`
   asks the user whether the application may use the certificates on their security token.
   Before consent, every outcome looks the same to the caller, including no token and no
   match. On approval the response lists the matching certificates, each with an opaque
   `credential_id`, the certificate, the token label and key properties. The application's
   own picker chooses.
2. Every listed key is authorized, because a compromised application controls its own picker
   and could choose any of them. The access prompt therefore lists the certificates it
   covers. Key-level consent would instead need a portal confirmation at the first `Sign`
   with each key.
3. A `credential_id` is a reference valid only in its session, bound to the token serial and
   key id. Card removal, revocation or session close invalidates it. Revocation also clears
   the remembered consent, so the next request prompts again.
4. `Sign` names a `credential_id` from that list. The PIN prompt and signing stay in the
   backend, as now.
5. The portal chooser stays for applications without a picker: `RequestAccess` with
   `select: true` returns a single credential chosen in the portal UI.
6. Consent lasts for the running application instance, as identified by the sandbox (the
   Flatpak instance), so all processes of one browser share it. It covers the approved
   token, the listed keys and signing only; another card or a newly matching key needs a new
   prompt. It ends when the instance exits. Process ancestry is not used as identity. Unsandboxed host callers get no
   remembered consent.
7. Scope is TLS client authentication: signing only, with no decryption, document signing or
   SSH. This states intended use; the portal signs digests and cannot enforce purpose.

Remembered consent changes the meaning of the grant lifetime. Today every grant after expiry
needs a new chooser; under this proposal a new grant within the same instance would be issued
without a prompt, and only the PIN prompt (when the card has logged out) would show. That is
the trade for one prompt per browser session, and maintainers may prefer a cap.

With these changes a browser that loads the module shows the access prompt once per
instance and card, then only its own picker and the portal's PIN prompt, with no policy setup.

A later addition, outside this proposal, would let a browser call the portal directly
during the TLS handshake and pass the host name and the server's acceptable CAs. The portal
could then name the site in its prompt. That needs browser maintainers and is not required
for the steps above.

## Architecture

Most of the backend is card handling: token discovery through p11-kit, certificate
filtering, PIN memory hardening, login and retry state, and the signing broker. The
desktop-specific part is two dialogs, the chooser and the PIN prompt. The prototype splits
along that line:

```text
application ── PKCS#11 module ── xdg-desktop-portal (frontend)
                                        │
                     desktop backend (GNOME, KDE, or the standalone GTK one)
                     D-Bus adapter, chooser and PIN dialogs
                                        │
                     libxdp-certificate-core (linked in)
              discovery, filtering, grants, PIN handling, signing
                                        │
                              p11-kit ── OpenSC ── pcscd
```

The library has a C API with no GLib, GTK or PKCS#11 types in its core and UI headers
([SDK.md](SDK.md)). A backend supplies a table of UI callbacks and a dispatcher that queues
calls onto its UI thread; the library calls back to show the chooser or the PIN prompt and
takes the user's answers. The dialog submits the PIN in a library-owned buffer that is
locked and excluded from core dumps where the kernel allows. In a GNOME session the GNOME
backend collects the PIN through GNOME Shell's system prompt (Gcr), the prompt gnome-keyring
uses, and receives it over Gcr's secret exchange; its own libadwaita dialog is the fallback.
The GNOME backend adds about 3,200 lines (adapter, chooser and PIN dialogs, system-prompt
support, build glue); the KDE backend adds a Qt adapter,
Kirigami dialogs and a PIN field that stores typed bytes only in that buffer. A fix in card handling lands once, in the library.

Linking the library into a desktop backend has a cost. The standalone backend makes its
process non-dumpable and disables core dumps before it collects a PIN. The GNOME and KDE
backends host the other portals too, so the same settings would remove crash reports for all
of them, and children they launch would inherit the core limit. In the KDE backend it would
also break document-path translation for file chooser results, which relies on the frontend
identifying the backend process. The forks therefore leave process settings alone. A crash
report of the desktop backend can contain copies of PIN input from the input stack, and a
same-user debugger can read the PIN while it is typed. The forks describe this in
[`src/certificate.md`](https://github.com/sjtrotter/xdg-desktop-portal-gnome/blob/experimental/certificate/src/certificate.md)
and [`autotests/README.certificate.md`](https://github.com/sjtrotter/xdg-desktop-portal-kde/blob/experimental/certificate/autotests/README.certificate.md).

A separate broker service avoids that cost. It would own grants, expiry, revocation and PIN
collection in a hardened process of its own, accept calls only from the portal backend, and
leave the desktop backends with the dialogs that show what is being asked. It could be its
own user unit, part of p11-kit, or part of gnome-keyring. It is not built yet
([#40](https://github.com/sjtrotter/xdg-desktop-portal-certificate/issues/40)).

## PKCS#11 forwarding

Daiki Ueno's 2023 design (attached to #662) forwards p11-kit RPC to the sandbox after consent,
with the token as the unit of access and a flag for destructive operations. It identified the
threat this proposal works from: an application bricking the card or exhausting its PIN
retries. The prototype started from scoped p11-kit forwarding too and moved away from it
([decision 0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)):

- The PIN stays with the application. With forwarding, the application calls `C_Login`, so a
  compromised application sees the PIN and can try PINs until the card locks. Here the PIN is
  typed into a backend dialog and never reaches the application.
- Forwarding exposes the whole token. The design's writable and destructive flags gate writes
  and calls such as `C_InitToken`, but signing, decryption and object reads stay available
  with every key on the card, including decryption with a PIV card's key-management key.
  Here the only operation is signing, with keys the user consented to.
- Access is to the token as a whole and lasts as long as the forwarding connection; there is
  no per-key grant for the host to enforce or expire. Here a grant names the key, has an
  expiry, is bound to one D-Bus connection, and ends on card removal or revocation. Under the
  proposed changes, consent is remembered for the application instance, so grants can renew
  without a prompt while it runs (question 5).

Ueno's design asks for consent through portal D-Bus requests; the operations then run over
p11-kit RPC, which carries no caller identity or parent window per call. Filtering those
operations down to signing, with the PIN taken out of the application, would add the same
trusted PIN prompt, grant enforcement and revocation as this proposal, split across two
protocols. The prototype keeps the compatibility that forwarding offers: a PKCS#11 module in the
sandbox turns calls from unmodified TLS stacks into portal calls.

## Other options

[credentialsd](https://github.com/linux-credentials/credentialsd) proposes a Credentials
portal whose current API runs WebAuthn ceremonies: origin-bearing create and get requests from
browsers and applications. TLS client authentication needs repeated signing through PKCS#11
by a module that has no origin to give, so this proposal stays a separate interface.

A PIN-only broker keeps the PIN out of the application but leaves card access with it, so a
compromised application can still use every key and operation the token offers.

## Known limits

- No independent security review.
- Only the leaf certificate is returned; `chain_status` is always `leaf_only`.
- Through PKCS#11 the portal cannot show the site, detect private windows or distinguish
  listing from authenticating. That needs browser cooperation, such as the direct call above.
- A same-UID host process can attack the backend; see [SECURITY.md](SECURITY.md).

## Questions for maintainers

1. Token-level consent (every listed key, one prompt) or key-level consent (a portal
   confirmation at the first use of each key)?
2. Signing goes through a portal method rather than forwarded PKCS#11, for the reasons above.
   Do you see a problem with that, such as per-signature D-Bus round trips?
3. How should the PKCS#11 module reach sandboxed applications: in the runtime, as a Flatpak
   extension, or bundled by each application?
4. The card broker is a library linked into each desktop backend, which leaves PIN input in
   a process kept dumpable for the sake of the other portals (see Architecture). Is that acceptable for
   an experimental portal, or should PIN collection and the broker move into a separate
   service first?
5. Is remembered consent per application instance acceptable, given that it lets grants
   renew without a prompt?
6. Is there someone on the GNOME side and someone on the KDE side who could review the API?

## Maintenance

I will develop the frontend, the card library and the GNOME and KDE backends, and maintain them
while the portal is experimental, as offered in
[flatpak/flatpak#5756](https://github.com/flatpak/flatpak/issues/5756).

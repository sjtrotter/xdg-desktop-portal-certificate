# smartcard-portal

**Status: EXPERIMENTAL design sketch. Nothing works yet, and the first thing to do is a spike that
may kill it.** This repository contains design documents, a repository skeleton, and two stub
binaries that build and print usage. No card has ever been read by this code, no PIN has ever been
prompted for, and no cryptographic operation has ever been brokered.

## Two processes, plumbed like xdg-desktop-portal

This is the first thing to know about the repository, because it is the shape of everything in it.

```
  ┌─────────────┐   io.github.sjtrotter.portal.Desktop      ┌──────────────────────────┐
  │ application │ ─────────────────────────────────────────►│ FRONTEND                 │
  └─────────────┘   io.github.sjtrotter.portal.Smartcard1    │ smartcard-portal-frontend│
        ▲                                                    │                          │
        │                    who is asking (app id, and how  │ identity · policy ·      │
        │                    well we know it) · purpose and  │ permissions · request &  │
        │                    option validation · policy ·    │ session lifecycle ·      │
        └── grant, signature │ permission store · grants,    │ backend selection        │
                             │ expiry, rate limits           └────────────┬─────────────┘
                                                                          │
                              io.github.sjtrotter.impl.portal.Smartcard1  │  app_id is an
                              — PRIVATE. Applications never call it. ─────┤  ARGUMENT here
                                                                          ▼
                                                             ┌──────────────────────────┐
                                                             │ BACKEND                  │
                                                             │ smartcard-portal-gtk     │
                                                             │                          │
                                                             │ chooser · PIN prompt ·   │
                                                             │ PKCS#11 session · Sign · │
                                                             │ synthetic facade         │
                                                             └────────────┬─────────────┘
                                                                          ▼
                                                              p11-kit → OpenSC → pcscd → card
```

**A client talks to the frontend and to nothing else.** It calls
`io.github.sjtrotter.portal.Smartcard1` on `io.github.sjtrotter.portal.Desktop`, gets a `Request`
object whose path it can compute in advance, and a `Session` object that *is* the grant. It never
learns which backend is installed, never holds a PKCS#11 handle, and never sees a PIN.

The division is copied from xdg-desktop-portal, not invented: **frontend = caller identity, policy,
permissions, request lifecycle, backend selection; backend = UI and device access**. The one thing
that matters most is that `app_id` is *derived by the frontend* and *passed to the backend as an
argument* — so the process drawing the window that names an application never had to guess which
application it was.

Building it this way now, rather than after a first release, is a deliberate override of the
review's "premature for v0" advice:
[docs/decisions/0008](docs/decisions/0008-build-to-the-upstream-shape.md). What would change if this
were ever accepted upstream — names, and where the frontend lives — is
[docs/UPSTREAMING.md](docs/UPSTREAMING.md).

Read this paragraph before anything else:

> **The bad version of this idea is a certificate chooser wrapped around `p11-kit server`.** It
> gives the application far more access to the token than the consent dialog implies, and it does
> not solve PIN ownership at all. **The viable version is a cryptographic credential broker** —
> the service selects the credential, keeps the key, and performs the operations — **with a
> carefully restricted PKCS#11 compatibility facade** for consumers that can only speak PKCS#11.
> That is materially larger and riskier than it first looks: the facade is a security-sensitive
> PKCS#11 implementation, not plumbing. See
> [docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
> and [0007](docs/decisions/0007-brokered-operations-are-the-core.md).

> **Names.** `smartcard-portal` is a *directory name*, not a claim. The interfaces ship as
> **`io.github.sjtrotter.portal.Smartcard1`** (public) and
> **`io.github.sjtrotter.impl.portal.Smartcard1`** (private, frontend-to-backend) — project-controlled
> reverse-DNS names with a major version, as
> [the D-Bus specification recommends](https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names)
> — and deliberately not `org.freedesktop.portal.*`. **We mirror the shape; we do not take the
> namespace.** The name is also probably wrong in a second
> way: the real conceptual boundary is a **client certificate** or **cryptographic credential**,
> because the backing key might be a TPM, a software token, a phone or a remote HSM rather than a
> card. `Smartcard1` is an incubation name and is expected to change. See
> [0003](docs/decisions/0003-own-namespace-before-freedesktop.md).

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

A per-user, D-Bus-activated **portal** brokers cryptographic credentials the way
[`org.freedesktop.portal.Camera`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Camera.html)
brokers cameras: it does not hand over the device. An application calls `AcquireCredential` naming
a purpose. The **frontend** works out who is asking and whether it may ask; the **backend** — not
the application — shows a chooser naming the application *the frontend identified*, how well it is
identified, the purpose in the backend's own words, and the candidate certificates on each token;
the frontend returns a **grant**: the chosen certificate as DER, its chain and chain status, the
key's type and mechanisms, the permitted operations, and an expiry. The application then asks the
frontend to **`Sign`** (and, if the grant allows it, `Decrypt`); the frontend checks the grant and
forwards; the backend prompts for the PIN in its own window, logs into its own PKCS#11 session,
performs the operation and returns the result.
The PIN never crosses D-Bus, the private key never leaves the card, and the application never holds
a PKCS#11 handle. For consumers that can only consume a PKCS#11 module — which is most existing TLS
code — a **separately requested, experimental** `OpenPkcs11Endpoint` returns a socket fd backed by
a broker-controlled **synthetic** PKCS#11 facade exposing one slot, one token, the granted objects
and nothing else.

## Layers

```
                    ┌──────────────────────────────────────────────┐
                    │  FRONTEND  smartcard-portal-frontend         │
                    │  io.github.sjtrotter.portal.Smartcard1       │
                    │  app id · policy · permissions · grants      │
                    └───────────────────┬──────────────────────────┘
                                        │ io.github.sjtrotter.impl.portal.Smartcard1
                                        │ (private; app_id travels as an argument)
                    ┌───────────────────▼──────────────────────────┐
                    │  BACKEND  smartcard-portal-gtk               │
                    │  chooser UI · PIN UI · token session         │
                    │  brokered Sign / Decrypt        ← the core   │
                    │  synthetic PKCS#11 facade  ← experimental,   │
                    │                              opt-in, milestone 2
                    └───────┬──────────────────────────┬───────────┘
                            │                          │
             grant + brokered Sign                     │ grant + PKCS#11 endpoint fd
             (relayed by the frontend)                 │ (created by the backend,
                            │                          │  relayed by the frontend)
            ┌───────────────▼────────────────┐   ┌─────▼───────────────────────────┐
            │ webauth-portal-gtk (backend)   │   │ TLS applications that can only  │
            │ io.github.sjtrotter.portal.    │   │ consume a module. NOT MVP       │
            │ WebAuthentication1             │   │ consumers: Firefox, Chromium,   │
            │ (WebKit client-cert challenge) │   │ Evolution, openconnect, SSH,    │
            └───────────────┬────────────────┘   │ PDF signing each need explicit  │
                            │                    │ integration work of their own.  │
                completion URI                   └─────────────────────────────────┘

            ┌───────────────▼────────────────┐
            │ entra token client → FreeRDP   │
            │ Remmina / KRDC / sdl-freerdp   │
            └────────────────────────────────┘
```

Consumers see only the top box. The arrows from the backend are drawn from where the work happens,
not from where the D-Bus reply comes: every one of them passes through the frontend.

The left branch is the first consumer and the reason this exists
([0005](docs/decisions/0005-first-consumer-is-the-web-auth-service.md)). The right branch is the
long-term case for a separate service — but it is a *hope*, not a plan: every one of those
applications needs integration work in its own tree, and none of them has been asked.

Underneath, unchanged and unowned by this project: `pcsc-lite`, [OpenSC](https://github.com/OpenSC/OpenSC)
for PIV (the only supported card stack in v1), and p11-kit's module configuration.

## Interface at a glance

**Public**, on `io.github.sjtrotter.portal.Desktop`, object `/io/github/sjtrotter/portal/desktop` —
described in [docs/PUBLIC-INTERFACE.md](docs/PUBLIC-INTERFACE.md), declared in
[`frontend/data/io.github.sjtrotter.portal.Smartcard1.xml`](frontend/data/io.github.sjtrotter.portal.Smartcard1.xml).

```
io.github.sjtrotter.portal.Smartcard1

  CreateSession(a{sv} options) → o session_handle        ← the session IS the grant

  AcquireCredential(o session_handle, s parent_window, a{sv} options) → o request_handle
        options: handle_token, activation_token,
                 purpose: client_auth | signing | email | ssh   (no "any")
                 certificate_filter { issuers, key_usage, eku, token_label,
                                      piv_slot, key_algorithms }
                 operation_policy { sign, decrypt }
                 requested_lifetime, interaction_mode: required|allowed|forbidden,
                 allow_selection_memory, reason (untrusted), context (untrusted)

  Sign(o session_handle, s parent_window, a{sv} options) → o request_handle
        options: handle_token, operation_id, mechanism, parameters, data
        results: signature ay        ← a Request, because it MAY prompt
  Decrypt(o session_handle, s parent_window, a{sv} options) → o request_handle
  RenewGrant(o session_handle, a{sv} options) → t expires_at
  ReleaseGrant(o session_handle)                    ← alias of Session.Close()
  GetCapabilities(a{sv} options) → a{sv}

  OpenPkcs11Endpoint(o session_handle, a{sv} options)               ← EXPERIMENTAL
        → h endpoint_fd, s certificate_uri, s private_key_uri, u endpoint_version

  signals: TokenAdded, TokenRemoved, GrantInvalidated

io.github.sjtrotter.portal.Request        Close() · Response(u response, a{sv} results)
io.github.sjtrotter.portal.Session        Close() · Closed(a{sv} details)
```

**Private**, frontend-to-backend, on `io.github.sjtrotter.impl.portal.desktop.gtk` — described in
[docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md), declared in
[`backends/gtk/data/io.github.sjtrotter.impl.portal.Smartcard1.xml`](backends/gtk/data/io.github.sjtrotter.impl.portal.Smartcard1.xml).
**Applications do not call this.**

```
io.github.sjtrotter.impl.portal.Smartcard1

  CreateSession     (o handle, o session_handle, s app_id, a{sv} options) → (u, a{sv})
  AcquireCredential (o handle, o session_handle, s app_id, s parent_window,
                     a{sv} options) → (u response, a{sv} results)
  Sign / Decrypt    (o handle, o session_handle, s app_id, s parent_window,
                     a{sv} options) → (u response, a{sv} results)
  OpenPkcs11Endpoint(o session_handle, s app_id, a{sv} options)
                     → h endpoint_fd, s certificate_uri, s private_key_uri, u endpoint_version
  GetCapabilities   (a{sv} options) → a{sv}
  signals: TokenAdded, TokenRemoved, SessionInvalidated
```

Every impl call carries `app_id` and the grant handle. That is the whole point of the boundary.

The transaction pattern is copied closely from
[`org.freedesktop.portal.Request`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html)
and [`org.freedesktop.portal.Session`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Session.html),
and the frontend/backend division from
[writing a new backend](https://flatpak.github.io/xdg-desktop-portal/docs/writing-a-new-backend.html)
and [portals.conf](https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html), because
those patterns are right and callers already know them. Copying a pattern is not claiming a
namespace.

## Why not something simpler

**Why not just a PIN dialog?** A shared PIN prompt with no scoping is a UI library, not a security
boundary: the application still holds the module, still enumerates every object on the card, and
still holds a logged-in session it can use for anything. The consent moment would be honest and the
authorisation it granted would be unbounded.

**Why not just forward the token with `p11-kit server`?** Because that is the bad version. Stock
`p11-kit server` takes **token** URIs — its unit of exposure is a token, not an object — and
forwards the general PKCS#11 interface, including object creation and key generation. Login state
does not transfer across the forwarding boundary: the consumer's TLS stack opens its own sessions
and makes its own `C_Login` call. And `p11-kit-client.so` is located through process-level
configuration plus a single `P11_KIT_SERVER_ADDRESS`, which does not accommodate several concurrent
per-request grants in one process. Ten specific failure modes are enumerated in
[0006](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md). **Token-scoped forwarding
is insufficient isolation and this project will not ship it while calling it scoped.**

**Why is `Sign` the core rather than the module?** Because a grant expressed as brokered operations
can be counted, expired, revoked, rate-limited, audited and consented to per operation, and a
PKCS#11 session cannot. A module endpoint is a *compatibility* concession — a large one, worth
making — but it must be requested explicitly by a caller that can use it, and it must be backed by
a synthetic facade rather than by the real token. See
[0007](docs/decisions/0007-brokered-operations-are-the-core.md).

**Why not a signing API and nothing else?** Because GnuTLS, NSS and OpenSSL want a
`CK_FUNCTION_LIST`, and rewriting the PKCS#11 half of each TLS stack per consumer is not realistic.
The honest statement of the trade is: brokered operations give the better security model, the
facade gives the reach, and the facade is the part that might not work. Note also that neither
approach proves *semantics*: a `Sign` call cannot demonstrate that its input came from a TLS
handshake rather than from a PDF. Purpose constrains certificate *selection* and consent language;
it does not attest to what a later signature was for.

**Why not implement GNOME's system prompter interface?** `org.gnome.keyring.SystemPrompter` and
[gcr](https://gitlab.gnome.org/GNOME/gcr)'s `GcrSystemPrompt` are a real precedent for a
system-owned, system-modal PIN prompt — and they are GNOME's, tied to gnome-keyring's needs, with
no KDE equivalent. Impersonating that interface means inheriting its semantics without its
maintainers. The backend draws its own prompt and cites gcr as prior art. See
[0002](docs/decisions/0002-service-owned-pin-prompt.md).

**Why not blanket pcsc access?** Because that is the status quo, and it is what this exists to
replace.

## What this is not a boundary against

This design can give a **strong boundary for sandboxed applications**, whose identity a
containment framework can vouch for, and a **useful application-identity and consent boundary** for
ordinary host applications. It is **not** absolute same-UID isolation. A hostile unsandboxed
process running as the user may be able to inspect other processes, manipulate their environment,
read runtime files or inject input, depending on how the system is hardened. Any claim stronger
than that is false. The frontend/backend split does not change that answer either: both processes
run as the user, and what it buys is that identity derivation and window drawing are structurally
separate, not that either process is safe from a process that can `ptrace` it. See
[docs/SECURITY.md](docs/SECURITY.md) and
[docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md).

## Relation to xdg-desktop-portal

**Built in its shape, under our own names, and not ready to be proposed.** The frontend is the part
that would move *into* xdg-desktop-portal; the backend is the part that would live in or beside
xdg-desktop-portal-gtk. Every name and file has a mapping in
[docs/UPSTREAMING.md](docs/UPSTREAMING.md), and the claim that document exists to test is that
acceptance would be a rename rather than a redesign — with three open items where it would not be,
listed there rather than hidden.

Still incubating under its own namespace, and still not ready to be proposed. The
[review that shaped this repository](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
lists why it is not yet a credible portal API: applications cannot transparently consume
per-request PKCS#11 endpoints, object and operation scoping is unproven, application identity
versus delegated subprocess identity is unresolved, and the API currently mixes credential
selection, PIN agent behaviour, cryptographic operations and module transport.

The likely destination is *not* a portal named after a device. The
[linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) project is
already proposing `org.freedesktop.portal.Credentials` for FIDO2 and passkeys, and certificate-backed
signing plausibly belongs there as a **credential type** sharing the request, identity and consent
machinery, rather than as a rival portal. Those maintainers should be approached **before** names or
D-Bus signatures are frozen. [docs/ROADMAP.md](docs/ROADMAP.md) phase 3.

## Building the sketch

```
meson setup build && ninja -C build
./build/frontend/smartcard-portal-frontend --help
./build/backends/gtk/smartcard-portal-gtk --help
```

That is all they do. Both print usage and exit 0; every verb returns exit 70, "not implemented
(design sketch)". The exit codes are the same on both: `0` clean, `40` unavailable, `64` usage,
`70` internal / not implemented.

Layout:

```
frontend/     the portal frontend — the part that would move INTO xdg-desktop-portal
  data/       public interface XML, the .service file for io.github.sjtrotter.portal.Desktop,
              an example portals.conf
  src/        request, session, app-info, permission-store, portal-impl, smartcard, grant registry
backends/gtk/ the reference backend — the part that would live in or beside xdg-desktop-portal-gtk
  data/       impl interface XML, gtk.portal, the .service file for the impl bus name
  src/        request, session, smartcard, ui/, tokens/, broker/, export/
shared/       redaction rules, compiled into both
docs/         architecture, both interfaces, security, spikes, roadmap, upstreaming, decisions
```

## Documents

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, the frontend/backend responsibility table, sequences, process model |
| [docs/PUBLIC-INTERFACE.md](docs/PUBLIC-INTERFACE.md) | the interface applications call, in xdg-desktop-portal documentation style |
| [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md) | the private frontend-to-backend interface, and why applications cannot reach it |
| [docs/UPSTREAMING.md](docs/UPSTREAMING.md) | name-by-name and file-by-file mapping to freedesktop, and what changes at acceptance |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, PIN handling, grant scoping, caller identity |
| [docs/SPIKES.md](docs/SPIKES.md) | the five questions that decide whether this is buildable |
| [docs/ROADMAP.md](docs/ROADMAP.md) | phases, effort estimate, and its assumptions |
| [docs/decisions/](docs/decisions/) | why the shape is the shape |

## License

GPL-2.0-or-later. The chooser and PIN handling this project intends to build on is derived from
Remmina's RDP plugin, which is GPL-2.0-or-later; the reasoning, and the Apache-2.0 alternative that
would require a clean-room rewrite, are in [docs/decisions/0004-license.md](docs/decisions/0004-license.md).
Consumers only speak D-Bus and PKCS#11, so the licence places no constraint on them.

## AI assistance

These documents and the skeleton were drafted with AI assistance — Anthropic Claude and OpenAI
Codex — under the author's direction, and the author is responsible for every claim in them. The
prior-art citations were checked against primary sources; the ones that could not be verified are
called out where they appear.

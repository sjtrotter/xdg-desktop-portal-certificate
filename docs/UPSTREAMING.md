# Upstreaming

The experimental Certificate portal has no dedicated new-portal issue or upstream pull request
in the local project record. Issue states below describe dated evidence.

## Frontend location and convention

The frontend fork is
[github.com/sjtrotter/xdg-desktop-portal](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/integration),
branch `experimental/integration`. Git remotes are
<https://github.com/sjtrotter/xdg-desktop-portal.git> for the fork and
<https://github.com/flatpak/xdg-desktop-portal.git> for upstream `main`.
[ADR 0010](decisions/0010-backend-only-frontend-lives-upstream.md) assigns frontend ownership.

The merged experimental convention is defined by
[PR #2129](https://github.com/flatpak/xdg-desktop-portal/pull/2129), with the opt-in check fixed by
[PR #2173](https://github.com/flatpak/xdg-desktop-portal/pull/2173).
Certificate remains a fork interface. WebAuthentication will not be proposed: its development
stopped on 2026-10-16.

[ADR 0012](decisions/0012-merged-experimental-portal-convention.md) records the naming and
export convention. [PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md#contract) applies it to Certificate
and documents `version` and the `Certificate1` opt-in.

## Frontend dependencies

The Certificate series includes shared request/session support: `xdp_session_dex_close()`,
a fix to `xdp_session_dex_store_new_wrapped()` to read the session field instead of its address,
a request-closed accessor to prevent committing state after cancellation, and impl-request
closure. The frontend stores grant state on sessions.
Consult `experimental/integration` for the current patch series.

Frontend validation uses its Meson integration/unit tests, `tests/test_certificate.py`,
`tests/test_webauthentication.py`, gitlint and Black. This tree cannot establish their current
results; backend commands are in [TESTING.md](TESTING.md).

## Backend layout

| Path | Responsibility |
|---|---|
| `src/main.c` | D-Bus-activated executable |
| `src/certificate-impl.h`, `request-impl.h`, `session-impl.h` | Impl skeletons |
| `src/ui/`, `src/tokens/`, `src/broker/` | Chooser, PIN, discovery and device operations |
| `src/module/` | Client-side PKCS#11 compatibility |
| `src/export/` | Deferred served-facade requirements |
| `src/redact.h` | Structured logging |
| `data/certificate.portal.in` | `DBusName`, `Interfaces`, `UseIn`; installs under `$datadir/xdg-desktop-portal/portals` |
| `data/org.freedesktop.impl.portal.desktop.certificate.service.in` | D-Bus activation |
| `data/org.freedesktop.impl.portal.experimental.Certificate1.xml` | Tracking copy; use the installed frontend interfaces directory when a release provides it |
| `tools/` | Development stack, smoke tests and manual trigger |

This follows the out-of-tree layout used by `xdg-desktop-portal-termfilechooser` and
`xdg-desktop-portal-gtk`. Public frontend code and XML belong to xdg-desktop-portal.

## Contract and open design work

[PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md) defines request/session lifecycle, signing limits
and lifetime. [IMPL-INTERFACE.md](IMPL-INTERFACE.md) defines backend identity arguments,
invalidation and absent options.

A non-interactive `Sign` fast path would need measured round-trip cost. Backend-owned
device access follows ScreenCast/RemoteDesktop; maintainers may request another arrangement.
[Selection memory](SECURITY.md#selection-memory) requires a frontend design.

No interface exposes `OpenPkcs11Endpoint`; the client module serves PKCS#11 consumers. A
served endpoint would need fd-transfer review, the [security rules](SECURITY.md), and tests
capable of returning a usable fd beyond python-dbusmock. Process-tree delegation work is
archived on `experimental/certificate-webauthentication+delegation`; it is outside the contract.
Rate limits, decryption, renewal, selection memory and cross-process grant sharing each need a
consumer and a design. There are no public token-presence signals or `grant_id` result.

## Before proposing the portal

The proposal for review is [PROPOSAL.md](PROPOSAL.md).

Open an upstream new-portal discussion identifying the protected resource: use of a
hardware-backed private key and trusted consent/PIN interaction, replacing blanket
`--socket=pcsc` access with scoped, revocable grants. The author announced the work on
2026-09-05 in
[flatpak#5756](https://github.com/flatpak/flatpak/issues/5756#issuecomment-5553235336) and
[#662](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-5553242646)
[[S28](SOURCES.md)]. Those comments are separate from a new-portal proposal.

Discuss certificate-backed signing with
[linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) before
freezing names. That project proposes a Credentials portal for FIDO2/passkeys; signing might fit
as a credential type. [ADR 0003](decisions/0003-own-namespace-before-freedesktop.md) records
the conversation order. The experimental namespace confers no acceptance or stability promise.

Follow frontend contribution checks and the coding-agent attribution format
`Assisted-by: AGENT_NAME:MODEL_VERSION` required by its gitlint hook. Complete remaining
[ROADMAP.md](ROADMAP.md) gates, including hardware breadth and independent review.

Recorded backend/frontend evidence in [TESTING.md](TESTING.md): one PIV card in one reader
on 2026-09-04, tiers 3.2–3.4 (tier 3.1 requires no frontend); WebKitGTK on 2026-09-04/05,
including a live Entra ID sign-in; Firefox on 2026-09-06.

## Prior art and related discussion

The discussion below was read in full on 2026-09-04. Dates, quotations and issue states describe
that source record; [SOURCES.md](SOURCES.md) provides primary links and check dates.

[xdg-desktop-portal#662, "PKCS#11 portal"](https://github.com/flatpak/xdg-desktop-portal/issues/662).
Opened by `yoe`, who works on the Belgian eID software (`Fedict/eid-mw`), on 2021-11-17; the recorded discussion has no agreed interface. The source record checked on 2026-09-05
includes discussion through 2023-07-11 and the author's comment [[S28](SOURCES.md)].

| Who | When | Position |
|---|---|---|
| yoe | 2021-11-17 | The portal should use p11-kit on the unconfined side and export every module p11-kit knows. Named consumers: browsers, Thunderbird/Evolution, LibreOffice. Motivation: European ID cards ship a PKCS#11 module as their main deliverable |
| frankmorgner (OpenSC, vsmartcard) | 2022-02-28 | Points at `valentindavid/pkcs11-demo` as a working demonstration |
| 3v1n0 | 2023-03-22 | Proposes generic smart-card exposure through vsmartcard's `vpcd` |
| frankmorgner | 2023-03-22 | The layering comment. `vpcd`/`vicc` expose the token over PC/SC; `pkcs11-proxy` exposes the middleware over PKCS#11. Reproduced in [ARCHITECTURE.md](ARCHITECTURE.md#pcsc-middleware-and-certificate-access) |
| jmaris | 2023-04-04 | eIDAS is being extended to digital identity documents; this will matter to EU users |
| ueno (p11-kit, GnuTLS) | 2023-06-23 | Attaches a design (below). The threat model in one sentence: "a malicious application could brick smartcards by calling destructive functions like `C_InitToken` or by repeatedly providing incorrect PIN" |
| frankmorgner | 2023-06-23 | Agrees consent is needed; worries about permission fatigue, citing the Apple and Windows Vista backlashes. Floats whitelisting signed "friendly" applications |
| mcatanzaro (WebKitGTK) | 2023-06-23 | Describes the security model: "The security model is to protect against compromised applications" |
| Erick555 | 2023-06-26 | Every Flathub app is signed; signed is not benign; an app can turn malicious a minute after being blessed |
| jadahl (maintainer) | 2023-06-27 | Rejects blessed-application lists because portals must protect against compromised applications regardless of trust |
| Mikenux | 2023-06-28 | Review at scale is impossible; the only legitimate escape from prompting is the user choosing to always grant, with re-evaluation on app update |
| jmpolom | 2023-07-11 | Notarization is user-hostile and must be ruled out; yoe's original proposal is still the most reasonable; granular prompts will produce MFA-style fatigue; the brick argument is not watertight because a host app can do the same; rate limits belong lower in the stack, "not in this portal though, that is for certain"; wants one coarse per-app "allow PKCS#11" |

Every quotation in that table is cited comment by comment in [[S29](SOURCES.md)], and the
layering diagram in [ARCHITECTURE.md](ARCHITECTURE.md) is [[S30](SOURCES.md)].

Brokered operations are unevaluated in the recorded thread, which discusses coarse forwarding
and mediated access with consent. The [threat model](SECURITY.md#boundary-and-threat-model)
requires consent without a blessed-application list.

Ueno's "Flatpak portal design for smartcard access" (2023), attached to that issue
[[S31](SOURCES.md)], uses D-Bus for permission requests and p11-kit RPC for operations. States are no access, enumerating and accessing. Methods are
`StartForwarding(fd) -> handle` and `AccessToken(token_uri, {writable, destructive}) -> handle`,
where `AccessToken` may be called again to escalate. Its scoping rule is: "The minimal unit of access control is PKCS#11 token, not object nor certain
operation." A flag permits destructive functions. PIN entry stays with
the application ("it would be desirable to not interfere with the existing application level
pop-up, such as the password prompt implemented by Firefox"), and PIN-retry exhaustion is named as
motivation but not solved by the mechanism. Decision [0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
failure mode 9 is the disagreement: a PIV card holds four keys, so a token-scoped grant makes a
certificate-scoped consent sentence untrue.

[p11-kit#294](https://github.com/p11-glue/p11-kit/issues/294) (open since 2020-05-01)
[[S9](SOURCES.md)]. Morgner
asks for PKCS#11 modules to be sandboxed; Ueno answers that it is partly possible already with the
`remote:` configuration option plus bubblewrap (comment `622359664`), and that doing it
transparently might want a new `sandbox-profile:` option (comment `968077421`). The proposed option is absent; Ueno places it outside the portal proposal in #662.

[valentindavid/pkcs11-demo](https://github.com/valentindavid/pkcs11-demo)
[[S32](SOURCES.md)]. Two snaps joined by
snapd's content interface: an `opensc` snap running a confined `pcscd` plus
`p11-kit server -f --name … pkcs11:`; the bare URI, i.e. every module, unfiltered; and a
strictly-confined consumer shipping only `p11-kit-client.so`. It implements coarse forwarding: authorization is a one-time admin
`snap connect`, after which the app holds the whole token set for good. [ADR 0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) records the scoping limits.

vsmartcard's `vpcd`/`vicc` virtualize at the PC/SC layer, carrying APDUs over a socket. Its README makes no comparison to pkcs11-proxy; the layering distinction
is Morgner's own. pkcs11-proxy's original README says "the connection is not encrypted and can
easily be sniffed", which, since it tunnels `C_Login`, means unencrypted PIN arguments by default; the
SUNET fork adds TLS-PSK and seccomp but still no per-client authorization or call filtering.
Neither is OpenSC-maintained.

[xdg-desktop-portal PR #1889](https://github.com/flatpak/xdg-desktop-portal/pull/1889),
"Introduce Credentials portal (experimental)" [[S27](SOURCES.md)]. The local source record describes the Credentials proposal as open.
The experimental-portal convention is merged separately in PR #2129. Maintainers need to decide
whether certificate-backed signing belongs as a credential type in that proposal.

# Upstreaming: the frontend is already upstream-shaped, and what is left

Status: EXPERIMENTAL. **Nothing has been proposed to anyone.** No issue has been opened, no
pull request exists, no maintainer has been contacted, and the branch this document is
about is local-only — nothing was forked and nothing was pushed.

What changed since the previous version of this document is that "the frontend, if
accepted, would move into xdg-desktop-portal" stopped being a hypothesis with a mapping
table attached. The frontend **is** in xdg-desktop-portal now, on a branch, in the
`experimental` namespace upstream set aside for portals in exactly this state. See
[decisions/0010-backend-only-frontend-lives-upstream.md](decisions/0010-backend-only-frontend-lives-upstream.md).

## Where the frontend is

```
repository   a local checkout of xdg-desktop-portal
remote       upstream → https://github.com/flatpak/xdg-desktop-portal.git
             origin   → https://github.com/sjtrotter/xdg-desktop-portal.git
branch       experimental/certificate-webauthentication
base         upstream/main = 86bd3e2  po: Update Russian translation
commits      22818e6  xdp: Add a gate for experimental portals              series 1
             faf82d4  request-dex: Let a portal close an impl request     ┐
             a6b06d4  web-authentication: Add an experimental             │
                      WebAuthentication portal                            │ series 2
             ad72af8  doc: List the experimental portals in the           │
                      interface reference                                 │
             d21a4dc  tests: Add WebAuthentication portal tests           ┘
             0bff521  session-dex: Add xdp_session_dex_close()            ┐
             1385b47  session-dex: Fix the wrapped session store          │
             2ab8cca  request-dex: Let a portal see that a request was    │ series 3
                      closed                                              │
             a4c1f62  certificate: Add an experimental Certificate portal │ ← this one
             1aaffaf  tests: Add Certificate portal tests                 ┘
```

**Three series, proposed in that order**, because they are three separate questions: a
gate for experimental portals at all, then the smaller interface, then the one this
repository implements. The gate is 40 lines and needs the maintainers' answer
independently of whether they like either interface.

`a4c1f62` is the commit this repository tracks. Series 3 carries three small changes to
shared frontend code, each landing with its first user: `0bff521` adds an
`xdp_session_dex_close()` that upstream was missing and that a session-shaped portal cannot
do without; `1385b47` fixes `xdp_session_dex_store_new_wrapped()`, which has never worked —
it read the address of the session field rather than the field, so the store aborted in a
cast — and which the Certificate portal is the first thing to use, keeping a grant on the
session object rather than in a table keyed by its object path; `2ab8cca` adds the accessor
that lets a portal decline to commit state for a request the application has closed.

**What came out of the branch before it was shown to anyone**, after two independent
reviews: process-tree delegation and every change under `shared/` it needed, `Decrypt`,
`RenewGrant`, `ReleaseGrant`, `TokenAdded`/`TokenRemoved`, selection memory and `grant_id`.
The delegation commits are archived on
`experimental/certificate-webauthentication+delegation`, at the old tip `209f9ff`. This
backend follows the interface, not the archive.

Test results: `meson test --suite integration --suite unit` green except the pre-existing
`usb` failure (`umockdev-run` is not installed here), `tests/test_certificate.py` 98
passed, `tests/test_webauthentication.py` 69 passed, `gitlint --commits
upstream/main..HEAD` passes, `black --check` passes.

## Why `experimental` is not a claim of acceptance

[PR #1889](https://github.com/flatpak/xdg-desktop-portal/pull/1889) ("Introduce
Credentials portal (experimental)") is where the mechanism was settled. Sebastian Wick,
2026-01-28, verbatim:

> As for the interface name, let's call it something like
> `org.freedesktop.portal.experimental.Credentials`. It should also not be exposed by
> default and have a environment variable to turn it on (e.g.
> `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=credentials`).

and Isaiah Inuwa, minutes later:

> I noticed the other portals have singular names: should we do that here too?
> `org.freedesktop.portal.experimental.Credential`

So: singular name, `experimental` infix, not exported by default, turned on by an
environment variable holding portal names. That is what an unfinished portal looks like
upstream, and it is what the branch implements. It carries no more standing than the old
`io.github.sjtrotter.*` names did — it just carries it in the place where the people whose
opinion matters can see it.

The impl-side name follows: `org.freedesktop.impl.portal.experimental.Certificate`, which
is what `swick/wip/credentials-portal` does for its own portal, and which keeps the
frontend and backend generated symbols in step so the whole experimental surface can be
deleted with the namespace if it is dropped.

## What this repository is now

An out-of-tree backend, in the shape `xdg-desktop-portal-termfilechooser` and
`xdg-desktop-portal-gtk` use:

| Here | What it is |
|---|---|
| `src/main.c` | the D-Bus activated executable |
| `src/certificate-impl.h`, `request-impl.h`, `session-impl.h` | the impl skeleton, one file per portal interface |
| `src/ui/`, `src/tokens/`, `src/broker/`, `src/export/` | the chooser, the PIN prompt, discovery, the broker, the deferred facade |
| `src/redact.h` | logging rules — was `shared/`, when there were two sides here to share between |
| `data/certificate.portal.in` | `DBusName`, `Interfaces`, `UseIn`; installed into `$datadir/xdg-desktop-portal/portals` |
| `data/org.freedesktop.impl.portal.desktop.certificate.service.in` | D-Bus activation |
| `data/org.freedesktop.impl.portal.experimental.Certificate.xml` | a **verbatim tracking copy** of the branch's file; deleted the day the branch lands and the file ships in xdg-desktop-portal's interfaces directory |
| `tools/` | `trigger-certificate.sh`, `dev-stack.sh` |

What is *gone*, and was deleted rather than moved: `frontend/src/request.h`, `session.h`,
`app-info.h`, `permission-store.h`, `portal-impl.h`, `certificate.h`, `grant-registry.h`,
`main.c`, its interface XML, its `.service.in`, its `portals.conf.example`, and the
umbrella build that held two binaries. The previous version of this document listed most of
those as "*deleted* — xdg-desktop-portal already does this". It was right, and the deletion
has now happened.

## What the branch's XML forced this repository to change

The interface is the frontend's, and where the branch disagreed with what this repository
had written down, the branch won. Recorded because a claim that "acceptance is a rename"
is only worth anything with its exceptions attached — and these are the exceptions.

| This repository said | The branch says | Why |
|---|---|---|
| `CreateSession(a{sv}) → o session_handle` | `CreateSession(a{sv}) → o handle`, a **Request**; the `session_handle` comes back in the `Response` results | Every session-creating portal upstream does it this way: GlobalShortcuts, InputCapture, ScreenCast, RemoteDesktop |
| impl `GetCapabilities(a{sv} options) → a{sv}` | impl `GetCapabilities(s app_id, a{sv} options) → a{sv}` | Every impl call upstream carries `app_id` |
| `OpenPkcs11Endpoint(...) → h fd, s, s, u` on both interfaces | **not implemented, on either** | An fd-returning method needs its own review, and a python-dbusmock backend cannot hand back a usable fd, so a v0 with it would have had no test. A follow-up, with the facade rules from [SECURITY.md](SECURITY.md) |
| a `context` option carrying the requested destination host | **no such option** | The only caller-supplied text on the interface is `reason` |
| an `app_display_name` impl option | **no such option** | The backend gets `app_id` and `app_identity_level`; a human-readable name is its own to derive |
| the permission-store table name and resource-id format were "ours, and the kind of thing maintainers have opinions about" | **no permission store at all**: selection memory is not in the first proposal | The shape the branch had — one certificate per app id, across every purpose and filter — is not the shape it should return in |
| grant lifetime ceiling unspecified | 3600 s ceiling, 300 s default, forwarded to the backend as `lifetime` | Settled |
| mechanisms described prose-wise as "RSA PKCS#1 v1.5, RSA-PSS and ECDSA" | the exact allow-list strings `RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA`, intersected in the frontend's own order | Settled |
| `GrantInvalidated` reasons partly open | fixed: `token_removed`, `policy`, `backend_gone`, `error`, and the signal goes to the session's owner alone rather than to the bus | Settled |

The three "open items" the previous version of this document listed have all moved:

- **Who opens the device** is decided in the branch's favour of ScreenCast/RemoteDesktop —
  the backend owns the device — and is now a thing to argue about with a patch in hand
  rather than a thing to raise.
- **`Sign` returning a `Request`** is what the branch does. Nobody has measured the
  round-trip cost, and the answer if it is too slow is still probably a non-interactive
  fast path.
- **`ReleaseGrant` duplicating `Session.Close()`** is settled: `ReleaseGrant` is gone and
  a grant ends with `Session.Close()`. `GrantInvalidated` stays, because
  `Session.Closed` cannot say *why*.

## What remains before this could be a pull request

1. **Open the "new portals" discussion upstream first.** xdg-desktop-portal directs
   requests for new portals to an issue in `flatpak/xdg-desktop-portal`, with the question
   "what protected host resource is being mediated?" answered first. The honest answer
   here: **use of a hardware-backed private key, and the trusted consent and PIN UI around
   it**, replacing a blanket `--socket=pcsc` grant with a scoped, revocable, attributable
   one. No such issue has been opened. What exists is two comments the author posted on
   2026-09-05, announcing the work in
   [flatpak#5756](https://github.com/flatpak/flatpak/issues/5756#issuecomment-5553235336) and
   crossposting it into
   [#662](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-5553242646)
   [[S28](SOURCES.md)]. Neither is the discussion this item asks for.
2. **Talk to the credentials people before freezing any name.**
   [0003](decisions/0003-own-namespace-before-freedesktop.md)'s ordering constraint is
   unchanged by any of this:
   [linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) is
   proposing `org.freedesktop.portal.Credentials` for FIDO2 and passkeys, and
   certificate-backed signing may belong there as a credential *type* rather than beside it
   as a rival portal. `Certificate` is still an incubation name.
3. ~~**Fix the commit trailer.**~~ **Done.** The branch's commits carried
   `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, which
   `.gitlint.conf/co-authored-by-coding-agent.py` exists precisely to reject in favour of
   `Assisted-by: AGENT_NAME:MODEL_VERSION`. All eighteen now carry
   `Assisted-by: Claude:claude-fable-5-1`.
4. **`OpenPkcs11Endpoint` as a follow-up**, with the facade rules from
   [SECURITY.md](SECURITY.md), a review of the fd hand-off, and something better than
   python-dbusmock to test it against.
5. **The branch's own open items**, none of which are this repository's: rate limiting is
   not implemented at all, and the pieces that came out of the first proposal — decryption,
   renewal, selection memory, and any sharing of one grant across an application's
   processes — each need a consumer and a design before they return.
6. **Everything in [ROADMAP.md](ROADMAP.md) phase 0 and 1**, which is about hardware and has
   barely moved. The branch has now driven one PIV card in one reader, on 2026-09-04, through
   this repository's backend ([TESTING.md](TESTING.md) tiers 3.2–3.4; 3.1 needs no
   frontend) — one card, one reader,
   and not a hardware claim. It has never been run against a **web engine**, and apart from that
   one run the python-dbusmock templates are the only implementations that have ever answered
   these interfaces.

## Prior art and related discussion

None of this was cited anywhere in this repository until now, which was the wrong order: the
argument below is with a five-year-old thread, and posting into it without having recorded that it
was read would be rude as well as unconvincing. Read in full on 2026-09-04.

**[xdg-desktop-portal#662, "PKCS#11 portal"](https://github.com/flatpak/xdg-desktop-portal/issues/662).**
Opened by `yoe`, who works on the Belgian eID software (`Fedict/eid-mw`), on 2021-11-17; still
open, unassigned, and it produced no interface. Substantive discussion ran to 2023-07-11 over 21
comments; the 22nd is the author's own, from 2026-09-05 [[S28](SOURCES.md)]. The first row of the
table below is the issue body rather than a comment. The positions worth knowing, because each is
an objection this design has to survive:

| Who | When | Position |
|---|---|---|
| **yoe** | 2021-11-17 | The portal should use p11-kit on the unconfined side and **export every module p11-kit knows**. Named consumers: browsers, Thunderbird/Evolution, LibreOffice. Motivation: European ID cards ship a PKCS#11 module as their main deliverable |
| **frankmorgner** (OpenSC, vsmartcard) | 2022-02-28 | Points at `valentindavid/pkcs11-demo` as a working demonstration |
| **3v1n0** | 2023-03-22 | The opposite: do **not** expose modules to confined apps; expose a generic smart card, perhaps via vsmartcard's `vpcd` |
| **frankmorgner** | 2023-03-22 | The layering comment. `vpcd`/`vicc` expose the **token** over PC/SC; `pkcs11-proxy` exposes the **middleware** over PKCS#11. Reproduced in [ARCHITECTURE.md](ARCHITECTURE.md#two-layers-and-the-one-this-adds) |
| **jmaris** | 2023-04-04 | eIDAS is being extended to digital identity documents; this will matter to EU users |
| **ueno** (p11-kit, GnuTLS) | 2023-06-23 | Attaches a design (below). The threat model in one sentence: "a malicious application could brick smartcards by calling destructive functions like `C_InitToken` or by repeatedly providing incorrect PIN" |
| **frankmorgner** | 2023-06-23 | Agrees consent is needed; worries about permission fatigue, citing the Apple and Windows Vista backlashes. Floats **whitelisting signed "friendly" applications** |
| **mcatanzaro** (WebKitGTK) | 2023-06-23 | The framing the maintainers accept: "The security model is to protect against **compromised** applications" |
| **Erick555** | 2023-06-26 | Every Flathub app is signed; signed is not benign; an app can turn malicious a minute after being blessed |
| **jadahl** (maintainer) | 2023-06-27 | **The ruling.** "Listing 'blessed' applications is not how portals are designed… it also side steps one of the most important aspects of sandboxing — compromised apps, trusted or not" |
| **Mikenux** | 2023-06-28 | Review at scale is impossible; the only legitimate escape from prompting is the *user* choosing to always grant, with re-evaluation on app update |
| **jmpolom** | 2023-07-11 | The last word, and the strongest dissent. Notarization is user-hostile and must be ruled out; yoe's original proposal is still the most reasonable; granular prompts will produce MFA-style fatigue; the brick argument is not watertight because a host app can do the same; **rate limits belong lower in the stack**, "not in this portal though, that is for certain"; wants one coarse per-app "allow PKCS#11" |

Every quotation in that table is cited comment by comment in [[S29](SOURCES.md)], and the
layering diagram in [ARCHITECTURE.md](ARCHITECTURE.md) is [[S30](SOURCES.md)].

Two camps, then: *coarse forwarding* (yoe, jmpolom, frankmorgner's UX wing) and *mediated access
with consent* (ueno, 3v1n0, Erick555, Mikenux, and — on the security model — jadahl and
mcatanzaro). **Nobody argued for brokered operations, and nobody argued against them: the option
was never raised.** Where this project agrees with the thread it should say so plainly — the
consent model here is Mikenux's answer and jadahl's ruling, and there is no blessed-app list
anywhere in it.

**Ueno's "Flatpak portal design for smartcard access" (2023), attached to that issue**
[[S31](SOURCES.md)]**.** D-Bus to
*gain* access so permissions land in the normal permission UI, p11-kit RPC for the calls
themselves. Three states — no access, enumerating, accessing — and two methods,
`StartForwarding(fd) → handle` and `AccessToken(token_uri, {writable, destructive}) → handle`,
where `AccessToken` may be called again to escalate. The sentence this design differs from is
explicit: "The minimal unit of access control is PKCS#11 **token**, not object nor certain
operation." Destructive functions are gated behind a flag rather than removed, PIN entry stays with
the application ("it would be desirable to not interfere with the existing application level
pop-up, such as the password prompt implemented by Firefox"), and PIN-retry exhaustion is named as
motivation but not solved by the mechanism. Decision [0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
failure mode 9 is the disagreement: a PIV card holds four keys, so a token-scoped grant makes a
certificate-scoped consent sentence untrue.

**[p11-kit#294](https://github.com/p11-glue/p11-kit/issues/294)** (open since 2020-05-01)
[[S9](SOURCES.md)]. Morgner
asks for PKCS#11 modules to be sandboxed; Ueno answers that it is partly possible already with the
`remote:` configuration option plus bubblewrap (comment `622359664`), and that doing it
transparently might want a new `sandbox-profile:` option (comment `968077421`). **That option does
not exist**; it is a plan, and Ueno says in #662 that it is out of scope for the portal proposal.

**[valentindavid/pkcs11-demo](https://github.com/valentindavid/pkcs11-demo)**
[[S32](SOURCES.md)]**.** Two snaps joined by
snapd's content interface: an `opensc` snap running a confined `pcscd` plus
`p11-kit server -f --name … pkcs11:` — the bare URI, i.e. **every module, unfiltered** — and a
strictly-confined consumer shipping only `p11-kit-client.so`. It is yoe's and jmpolom's proposal,
already built, and it has **no consent model at all**: authorization is a one-time admin
`snap connect`, after which the app holds the whole token set for good. It is the thing decision
[0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) rejects, and it works, and it is
worth being fair about why someone would want it.

**pkcs11-proxy and vsmartcard.** vsmartcard's `vpcd`/`vicc` virtualize at the **PC/SC** layer —
APDUs over a socket — and its README makes no comparison to pkcs11-proxy; the layering distinction
is Morgner's own. pkcs11-proxy's original README says "the connection is not encrypted and can
easily be sniffed", which, since it tunnels `C_Login`, means PINs in the clear by default; the
SUNET fork adds TLS-PSK and seccomp but still no per-client authorization or call filtering.
Neither is OpenSC-maintained.

**[xdg-desktop-portal PR #1889](https://github.com/flatpak/xdg-desktop-portal/pull/1889)**,
"Introduce Credentials portal (experimental)" — **open, not merged**, so the experimental
namespace and the gate live on its branch rather than in `main` [[S27](SOURCES.md)]. Already
load-bearing here for the naming and gating convention (above), and relevant a second time:
certificate-backed signing may belong there as a
credential **type** rather than beside it as a rival portal. That is the maintainers' call.

## What does not change, and must not

- The application talks to xdg-desktop-portal and only to xdg-desktop-portal.
- The app id is established by the frontend and passed to the backend as an argument.
- The PIN exists only in this backend's process, and never on any bus.
- Selection memory is preselection, never authorisation, and lives in the permission
  store.
- Any future facade is experimental, opt-in, synthetic, and refuses every administrative and
  key-management entry point.
- `purpose` constrains selection and consent language and attests nothing.

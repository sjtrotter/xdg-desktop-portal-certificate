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
repository   /home/betty/Projects/xdg-desktop-portal
remote       upstream → https://github.com/flatpak/xdg-desktop-portal.git
branch       experimental/certificate-webauthentication
base         upstream/main = c95490a  settings: include xdp-dex.h for the
                                      dex_scheduler_spawnv fallback
commits      661e441  doc: List the experimental portals in the interface reference
             3a32e9b  web-authentication: Add an experimental WebAuthentication portal
             703fb22  certificate: Add an experimental Certificate portal      ← this one
             aa1d697  session-dex: Add xdp_session_dex_close()
             3f46e3c  xdp: Add a gate for experimental portals
```

`703fb22` is the commit this repository tracks. `3f46e3c` is the
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` gate; `aa1d697` adds an
`xdp_session_dex_close()` that upstream was missing and that a session-shaped portal
cannot do without. `3a32e9b` is the sibling project's portal, on the same branch for the
reason [0005](decisions/0005-first-consumer-is-the-web-auth-service.md) records: with both
in one frontend process the delegation gap closes in-process.

Test results, from the branch write-up: `meson test` green on the whole suite,
`tests/test_certificate.py` 40 passed, `tests/test_webauthentication.py` 38 passed,
`gitlint --commits upstream/main..HEAD` passes, `black --check` passes.

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
| the permission-store table name and resource-id format were "ours, and the kind of thing maintainers have opinions about" | table `certificate`, id = app id, value = the backend's `certificate_id` | Settled, in code, in the frontend |
| grant lifetime ceiling unspecified | 3600 s ceiling, 300 s default, forwarded to the backend as `lifetime` | Settled |
| mechanisms described prose-wise as "RSA PKCS#1 v1.5, RSA-PSS and ECDSA" | the exact allow-list strings `RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA`, intersected in the frontend's own order | Settled |
| `GrantInvalidated` reasons partly open | fixed: `released`, `expired`, `token_removed`, `owner_gone`, `policy`, `service_shutdown`, `backend_gone`, `error` | Settled |

The three "open items" the previous version of this document listed have all moved:

- **Who opens the device** is decided in the branch's favour of ScreenCast/RemoteDesktop —
  the backend owns the device — and is now a thing to argue about with a patch in hand
  rather than a thing to raise.
- **`Sign` and `Decrypt` returning a `Request`** is what the branch does. Nobody has
  measured the round-trip cost, and the answer if it is too slow is still probably a
  non-interactive fast path.
- **`ReleaseGrant` duplicating `Session.Close()`** and **`GrantInvalidated` duplicating
  `Session.Closed`** are both still in the interface, and a reviewer may still ask for one
  of each to go. The answer should still be yes.

## What remains before this could be a pull request

1. **Open the "new portals" discussion upstream first.** xdg-desktop-portal directs
   requests for new portals to an issue in `flatpak/xdg-desktop-portal`, with the question
   "what protected host resource is being mediated?" answered first. The honest answer
   here: **use of a hardware-backed private key, and the trusted consent and PIN UI around
   it**, replacing a blanket `--socket=pcsc` grant with a scoped, revocable, attributable
   one. Nothing has been opened.
2. **Talk to the credentials people before freezing any name.**
   [0003](decisions/0003-own-namespace-before-freedesktop.md)'s ordering constraint is
   unchanged by any of this:
   [linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) is
   proposing `org.freedesktop.portal.Credentials` for FIDO2 and passkeys, and
   certificate-backed signing may belong there as a credential *type* rather than beside it
   as a rival portal. `Certificate` is still an incubation name.
3. **Fix the commit trailer.** The branch's commits carry
   `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
   `gitlint` passes on that, but `.gitlint.conf/co-authored-by-coding-agent.py` exists
   precisely to reject AI co-author trailers and asks for
   `Assisted-by: AGENT_NAME:MODEL_VERSION` instead. A real PR should use
   `Assisted-by: Claude:Fable-5.1`. This is noted in the branch write-up and is a
   rewrite-the-commits job, not a code change.
4. **`OpenPkcs11Endpoint` as a follow-up**, with the facade rules from
   [SECURITY.md](SECURITY.md), a review of the fd hand-off, and something better than
   python-dbusmock to test it against.
5. **The branch's own open items**, none of which are this repository's:
   `TokenAdded`/`TokenRemoved`/`GrantInvalidated` are forwarded but untested; the
   `SessionInvalidated` → `GrantInvalidated` conversion is untested; selection memory is
   written but never read back in a test; rate limiting is not implemented at all.
6. **Everything in [ROADMAP.md](ROADMAP.md) phase 0 and 1**, which is about hardware and has
   barely moved. The branch has now driven one PIV card in one reader, on 2026-09-04, through
   this repository's backend ([TESTING.md](TESTING.md) tiers 3.2–3.4) — one card, one reader,
   and not a hardware claim. It has never been run against a **web engine**, and apart from that
   one run the python-dbusmock templates are the only implementations that have ever answered
   these interfaces.

## What does not change, and must not

- The application talks to xdg-desktop-portal and only to xdg-desktop-portal.
- The app id is established by the frontend and passed to the backend as an argument.
- The PIN exists only in this backend's process, and never on any bus.
- Selection memory is preselection, never authorisation, and lives in the permission
  store.
- Any future facade is experimental, opt-in, synthetic, and refuses every administrative and
  key-management entry point.
- `purpose` constrains selection and consent language and attests nothing.

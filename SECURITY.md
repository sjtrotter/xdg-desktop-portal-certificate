# Security

The security model, threat model, PIN handling rules, grant scoping requirements, caller identity
model and logging rules live in **[docs/SECURITY.md](docs/SECURITY.md)**.

Three things are worth saying here, where people look first.

**This is experimental, and it now has an attack surface.** The backend is implemented: it loads
PKCS#11 modules, draws a consent window and a PIN prompt, holds a logged-in card session, and
performs signatures. `docs/SECURITY.md` opens with a checklist of which of its rules are enforced by
code today and which are still intentions. Nothing in it has been reviewed by anyone but its
authors, and **exactly one real smart card has ever been read by this code**: one PIV card in one
reader, on 2026-09-04, through [docs/TESTING.md](docs/TESTING.md) tiers 3.1–3.4. That is a first
run rather than a hardware claim, and the rest of tier 3 is unrun.

**There are two processes, and only one of them is in this repository.** The frontend is
xdg-desktop-portal — specifically the branch `experimental/certificate-webauthentication` — and it
establishes who is calling and applies policy. This repository is the backend: it draws the chooser
and the PIN prompt and holds the token. Applications talk only to xdg-desktop-portal, and the app
id this backend displays is one it was *given* rather than one it guessed, which is the point of
the arrangement. See [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md) for how the private interface
between them is kept private, including what that does *not* protect against, and
[docs/decisions/0010](docs/decisions/0010-backend-only-frontend-lives-upstream.md) for why the
frontend is not here.

**The interface is experimental and gated.** The public side is not exported at all unless
xdg-desktop-portal is started with `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate`. Installing
this backend on a machine whose portal does not know the interface adds no attack surface: the
`.portal` file names an interface nothing matches, and this process is never activated.

**The boundary this intends to provide is narrower than it sounds.** For **sandboxed** applications
it can be a strong boundary. For ordinary **host** applications it is a useful identity-and-consent
boundary. It is **not** absolute same-UID isolation, and this project must never claim otherwise: a
hostile unsandboxed process running as the user may be able to inspect other processes, manipulate
their environment, reach runtime files or inject input, depending on how the system is hardened.
Splitting the design into two processes does not change that: both run as the user.

**Reporting.** Report security issues privately to the repository owner rather
than in a public issue. Until then, the most valuable report is a hole in the design — especially in
[docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md),
which exists because an independent review found that this project's founding claim was wrong. That
kind of correction is worth more than a bug.

# Contributing

**This is an experimental design sketch, and it is a backend.** There is no implementation, and
[docs/ROADMAP.md](docs/ROADMAP.md) phase 0 is a time-boxed feasibility spike that may end the
project rather than start it. The most useful contribution today is not code.

**The interface is not changed here.** It is defined by the xdg-desktop-portal branch
`experimental/certificate-webauthentication`, and `data/org.freedesktop.impl.portal.experimental.Certificate.xml`
is a verbatim copy of the branch's file. A change to the interface is a change to that branch,
followed by re-copying the file; a hand-edit here produces a backend that no longer implements what
it claims. See [docs/decisions/0010](docs/decisions/0010-backend-only-frontend-lives-upstream.md).

## What helps most

**Tell us the design is wrong.** This repository already exists in its second shape, because an
independent review established that its founding claim — a certificate-scoped, already-logged-in
PKCS#11 module produced by `p11-kit server` — was false in six separate ways. That correction is
recorded in [docs/decisions/0006](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
and it is worth more than any amount of code written on top of the wrong idea. If something else
here is wrong, saying so is the contribution.

Specifically valuable:

- **Anything about PKCS#11 semantics** we have got wrong — login state, session scope, handle
  lifetime, mechanism parameters, v3 interface tables.
- **Hardware results.** Which cards, which readers, which middleware, what breaks. One PIV card in
  one reader has been through [docs/TESTING.md](docs/TESTING.md) tiers 3.1–3.4, once; that is a
  first run, not a result. The spikes in [docs/SPIKES.md](docs/SPIKES.md) are all questions about
  real hardware and none has been run.
- **Consumer perspectives.** If you maintain something that would use this — a browser, a mail
  client, a VPN client, an SSH agent — the most useful thing you can say is whether brokered `Sign`
  is integrable in your codebase, or whether only a PKCS#11 module would work. That answer decides
  [decision 0007](docs/decisions/0007-brokered-operations-are-the-core.md)'s balance.
- **Desktop integration knowledge**, especially KDE. There is no KDE equivalent of GNOME's gcr
  prompter, and a KDE chooser and PIN prompt is a prerequisite for ever proposing this upstream.
- **Accessibility review** of the chooser and PIN designs. These controls carry the security
  decision; a dialog a screen-reader user cannot navigate cannot carry informed consent.

## Ground rules for changes to the documents

- **Do not weaken a claim into ambiguity.** If something is unproven, say it is unproven and say
  what would prove it. Every document here names its own open problems on purpose.
- **Do not add a feature without a consumer.** One consumer is already thin evidence; zero is none.
- **Do not describe token-scoped forwarding as object scoping**, in any wording, anywhere.
- **Do not blur the frontend/backend line to make a paragraph shorter.** "The service" is two
  services with different jobs, in two different projects, and a document that says "the service
  resolves the caller's identity and shows the chooser" has described a design this project
  deliberately does not have.
- **`purpose` is not enforceable** and every document that mentions it says so. Keep it that way.
- **Nothing may put caller-supplied text in the trusted identity position.**
- **No design may store, log, or transport a PIN.** There is no "remember PIN" and there will not
  be one.

## Code, when there is any

- C11, GLib, meson. Warnings are on; keep them clean.
- `SPDX-License-Identifier: GPL-2.0-or-later` in every file. See
  [docs/decisions/0004-license.md](docs/decisions/0004-license.md) for why, and for the Apache-2.0
  alternative that would require a clean-room rewrite of the chooser and PIN handling.
- Code derived from Remmina keeps its Remmina copyright attribution alongside the SPDX header.
- Logging goes through `src/redact.h`, which accepts only the fields it may emit. Do not add a
  `printf`-shaped logging call; a filter that must recognise a secret has already been handed one.
- The synthetic PKCS#11 facade (`src/export/facade.h`) is hostile-input code and is currently
  unreachable — the interface has no method that returns an endpoint. Every entry point is refused
  or constrained by default; there is no allow-by-default path, and a change to it needs a test that
  a hostile client cannot do the thing. Making it reachable means adding `OpenPkcs11Endpoint` to the
  frontend branch first.

## Which repository does a change belong in

This repository is a portal **backend**, laid out like every out-of-tree backend
(`xdg-desktop-portal-gtk`, `xdg-desktop-portal-termfilechooser`): `src/` holds one file per portal
interface implemented, `data/` holds the `.portal` file, the D-Bus service file and the interface
XML. The **frontend** is a branch of xdg-desktop-portal
([docs/decisions/0010](docs/decisions/0010-backend-only-frontend-lives-upstream.md)).

Before writing anything, decide which project it goes in, and check it against
[the responsibility table](docs/ARCHITECTURE.md#who-does-what):

- **Frontend** (xdg-desktop-portal, branch `experimental/certificate-webauthentication`,
  `desktop-portal/certificate.c`): who is calling, what they are allowed to ask for, what is
  remembered, how long a grant lives, which backend is used, the interface XML.
- **Backend** (here, `src/`): what the user sees, what the card does. It never derives an app id,
  never decides policy, never writes the permission store, and never widens what it was granted. It
  is the only side with a toolkit and a PKCS#11 dependency, and that is not a coincidence.

Three rules that are easy to break by accident:

- **Do not let the backend learn anything about the caller except what the frontend passed it.** If
  a change needs the backend to know something new about the application, the change is a new
  argument on the impl interface — that is, a change to the branch — not a lookup in the backend.
- **Do not add a way for an application to reach the impl interface.** Not a convenience method, not
  a debug flag, not a "direct mode". See [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md).
- **Do not edit `data/org.freedesktop.impl.portal.experimental.Certificate.xml`.** It is a tracking
  copy.

## AI assistance

These documents were drafted with AI assistance (Anthropic Claude and OpenAI Codex) under the
author's direction. If you use the same, say so in the commit message, and be responsible for every
claim you land — including the citations. Several claims in the first draft of this repository were
wrong, and checking them against primary sources is what found it.

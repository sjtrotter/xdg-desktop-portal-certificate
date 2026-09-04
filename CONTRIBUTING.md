# Contributing

**This is an experimental design sketch.** There is no implementation, and
[docs/ROADMAP.md](docs/ROADMAP.md) phase 0 is a time-boxed feasibility spike that may end the
project rather than start it. The most useful contribution today is not code.

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
- **Hardware results.** Which cards, which readers, which middleware, what breaks. The spikes in
  [docs/SPIKES.md](docs/SPIKES.md) are all questions about real hardware and none has been run.
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
- Logging goes through `src/log/redact.h`, which accepts only the fields it may emit. Do not add a
  `printf`-shaped logging call; a filter that must recognise a secret has already been handed one.
- The synthetic PKCS#11 facade (`src/export/facade.h`) is hostile-input code. Every entry point is
  refused or constrained by default; there is no allow-by-default path, and a change to it needs a
  test that a hostile client cannot do the thing.

## AI assistance

These documents were drafted with AI assistance (Anthropic Claude and OpenAI Codex) under the
author's direction. If you use the same, say so in the commit message, and be responsible for every
claim you land — including the citations. Several claims in the first draft of this repository were
wrong, and checking them against primary sources is what found it.

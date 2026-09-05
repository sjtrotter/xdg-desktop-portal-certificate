# 4. LGPL-2.1-or-later

Date: 2026-09-04
Status: accepted, supersedes the GPL-2.0-or-later decision below

## Decision

License this repository **LGPL-2.1-or-later**. Ship the LGPL-2.1 text as `LICENSE`, add a
REUSE-style `LICENSES/LGPL-2.1-or-later.txt`, and carry `SPDX-License-Identifier:
LGPL-2.1-or-later` plus `SPDX-FileCopyrightText: 2026 Stephen J. Trotter
<stephen.j.trotter@gmail.com>` in every source file.

## Why

**No Remmina code was ever copied.** The GPL-2.0-or-later decision below was made in
anticipation of lifting roughly 900 lines from Remmina's RDP plugin. That lift never happened —
the discovery, chooser and PIN-prompt code in this repository is an independent implementation,
informed by the edge cases Remmina's plugin documents but not derived from its source. The
reason the original decision gave for choosing GPL-2.0-or-later therefore no longer applies.

**It matches the code's actual destination.** `xdg-desktop-portal`, `xdg-desktop-portal-gtk` and
`xdg-desktop-portal-gnome` are all LGPL-2.1-or-later. This repository already carries one file
derived from `xdg-desktop-portal-gtk`/libgxdp under that licence
(`src/ui/external-window.c`), and [UPSTREAMING.md](../UPSTREAMING.md) describes this backend's
own eventual path into an out-of-tree or in-tree backend alongside those projects. Matching their licence removes the relicensing step the superseded decision below called out as
a cost, in its "Consequences" section.

**No constraint on D-Bus consumers.** This was already true under GPL-2.0-or-later — consumers
talk to this service over D-Bus, never by linking — and LGPL-2.1-or-later keeps it true while
also removing any ambiguity about whether the *implementation* could later be linked into another
project's process (an out-of-tree backend is a separate binary either way, but an LGPL backend
imposes no licensing question if that ever changes).

## Superseded

The decision below, dated 2026-09-03, is retained as the record of the original reasoning. It no
longer reflects this repository's licence.

---

# 4. GPL-2.0-or-later (superseded)

Date: 2026-09-03
Status: superseded by the decision above, 2026-09-04

## Context

The part of this project that is genuinely hard and genuinely proven — enumerating a card's
certificates, choosing one, and prompting for a PIN without spending the retry counter — already
exists, in Remmina's RDP plugin, under **GPL-2.0-or-later**.

It is roughly 900 lines, and its value is not the lines. It is the enumerated list of things that go
wrong with real hardware, found by running against real cards: p11-kit's trust tokens that hold no
client certificates and must be skipped without spawning anything; empty tokens that report failure
and must be treated as empty rather than fatal; token-listing failures that must stay fatal;
certificate loading that takes seconds and must leave the main loop alive; a PIN answered once per
challenge plus one engine-initiated retry and then expired; a toplevel window that may be destroyed
under a nested dialog; and a logging discipline that emits counts and reason codes and never a URI.

A clean-room reimplementation would have to rediscover all of that on hardware. That is not a coding
cost, it is a *re-discovery* cost, and it is the difference between a few months of work and a
research exercise.

## Decision

License this repository **GPL-2.0-or-later**. Ship the GPLv2 text as `LICENSE` and carry
`SPDX-License-Identifier: GPL-2.0-or-later` in every source file. Remmina-derived code, when lifted,
keeps its Remmina copyright attribution alongside the SPDX header.

## The alternative that was not chosen

**Apache-2.0 with a clean-room rewrite of the chooser and PIN handling.** It would let any project
vendor this code, and it would matter more here than in most projects: a component hoping to be
adopted by desktop projects, and possibly folded into a freedesktop portal implementation, has a
stronger case for a permissive licence than a CLI tool does.

It was not chosen for the sketch because the rewrite buys a licence property nobody has asked for,
at the cost of the only battle-tested component in the design. If a desktop project or a downstream
consumer ever genuinely needs a permissive implementation, the rewrite can be done then,
deliberately — and it will be a far cheaper clean room than the one available today, because
[SPIKES.md](../SPIKES.md) S4 and the discovery notes in
[ARCHITECTURE.md](../ARCHITECTURE.md) write the edge-case list down as a specification.

The "or later" keeps GPL-3.0 available if a future dependency needs it.

## Consequences

**No linking constraint reaches consumers.** This is the important consequence and it is worth being
explicit about, because "GPL service" makes people nervous:

- Consumers talk to this service over **D-Bus**, and — for the experimental facade — over the
  **PKCS#11 RPC protocol** through a socket. Neither is linking.
- No consumer includes a header from this repository, links a library from it, or ships any of its
  code. A proprietary, Apache-2.0, MPL or BSD application can use this service exactly as freely as
  a GPL one.
- The sibling `webauth-service` sketch is GPL-2.0-or-later for the same Remmina-derived reason,
  and it too is reached only over D-Bus.

**What it does cost:**

- This code cannot be *vendored* into a permissively licensed program, or linked as a library. The
  supported integration is the D-Bus interface, which is the integration anyone should want anyway.
- If this design is ever adopted into xdg-desktop-portal — which is LGPL-2.1-or-later — the *code*
  would need relicensing or rewriting even though the *interface* would not. That is a real
  consideration for phase 3 and an argument for keeping the interface description and the
  implementation cleanly separable. The introspection XML and the documents in `docs/` are the parts
  that would travel, and they are the parts with no Remmina derivation in them.
- The synthetic PKCS#11 facade ([0007](0007-brokered-operations-are-the-core.md)) will be written
  from scratch and has no Remmina lineage. If a relicensing question ever becomes urgent, that
  component is separable, and it is the component a desktop project would most likely want.

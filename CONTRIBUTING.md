# Contributing

The experimental backend and client-side PKCS#11 module implement the unmerged Certificate
interface. Status and hardware coverage are in [README.md](README.md#status).

The interface belongs to the xdg-desktop-portal branch
[experimental/certificate](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/certificate).
The [impl XML](data/org.freedesktop.impl.portal.experimental.Certificate1.xml) is a tracking
copy, apart from its provenance comment. Make interface changes in the frontend branch and
copy the XML here. See [ADR 0010](docs/decisions/0010-backend-only-frontend-lives-upstream.md).

## Useful contributions

- Check PKCS#11 semantics: login state, session scope, handle lifetime, mechanism parameters
  and v3 interface tables. Report design errors; [ADR 0006](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
  records the limits of token forwarding.
- Record cards, readers, middleware and failures using [docs/TESTING.md](docs/TESTING.md).
  [docs/SPIKES.md](docs/SPIKES.md) lists unanswered feasibility questions.
- Describe consumer integration requirements, including whether brokered `Sign` or a PKCS#11
  module fits the application. See [ADR 0007](docs/decisions/0007-brokered-operations-are-the-core.md).
- Test desktop integration in the [GNOME](https://github.com/sjtrotter/xdg-desktop-portal-gnome/tree/experimental/certificate)
  and [KDE](https://github.com/sjtrotter/xdg-desktop-portal-kde/tree/experimental/certificate)
  forks. Both have SoftHSM container coverage. GNOME also has a live GNOME 50/PIV-card run;
  KDE has no live-session or card run. KDE uses its own PIN dialog.
- Review keyboard and screen-reader access to the chooser and PIN prompts. These controls
  must support informed consent.

## Documentation rules

State unproven claims and the evidence needed to establish them. Add features with a consumer.
Keep frontend and backend responsibilities explicit; token-scoped forwarding cannot provide
object scoping. `purpose` constrains selection and consent language and cannot attest later use.
Keep caller-supplied text outside the trusted identity position.

PINs must never be stored, logged or carried over the Certificate interfaces. The system
prompter transports an encrypted PIN to the backend for login; see
[PIN handling](docs/SECURITY.md#pin-handling). No prompt offers PIN retention.

## Code and ownership

Use C11, GLib and Meson, and keep compiler warnings clean. Preserve
`SPDX-License-Identifier: LGPL-2.1-or-later` and `SPDX-FileCopyrightText` headers in source,
tests, tools and build files. [ADR 0004](docs/decisions/0004-license.md) explains licensing.
Logging uses `src/redact.h`, whose entry points accept only permitted fields.

Assign changes using the [responsibility table](docs/ARCHITECTURE.md#responsibilities) and
[backend layout](docs/UPSTREAMING.md#backend-layout). New caller information requires an impl
argument; see [docs/IMPL-INTERFACE.md](docs/IMPL-INTERFACE.md).

The served facade in `src/export/facade.h` is unimplemented. PKCS#11 consumers use
`src/module/`; see [ADR 0011](docs/decisions/0011-client-side-pkcs11-module.md).

## Running tests

Run `meson setup build` and `meson test -C build` before sending a change.
[docs/TESTING.md](docs/TESTING.md) covers sanitizer builds, frontend configuration,
software-token smoke tests and hardware checks. Development scripts preserve the caller's
experimental-portal list and append `Certificate1` when missing; both portals require
`Certificate1,WebAuthentication1`.

## Sign-off and licence

A `Signed-off-by` trailer (`git commit -s`) is welcome but optional. Contributions are
licensed under LGPL-2.1-or-later.

## AI assistance

Documentation credits: Anthropic Claude and OpenAI Codex, under the author's direction.
Disclose AI assistance in the commit body and take responsibility for each claim and citation.
Check claims against primary sources.

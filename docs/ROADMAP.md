# Roadmap

[README.md](../README.md#status) records experimental implementation status.
The frontend is the xdg-desktop-portal fork's `experimental/certificate` branch;
[ADR 0010](decisions/0010-backend-only-frontend-lives-upstream.md) assigns ownership and
[UPSTREAMING.md](UPSTREAMING.md) lists proposal work.

The client module supports GnuTLS and WebKitGTK, with NSS evidence dated 2026-09-06
([SPIKES.md](SPIKES.md) S2, [TESTING.md](TESTING.md) §2.56).
[ADR 0011](decisions/0011-client-side-pkcs11-module.md) defines that compatibility path.
Remaining work includes hardware breadth, sharing a grant across an application's processes,
packaging, independent review and another maintainer.

## Effort estimates and assumptions

The total-work estimates assume one experienced Linux security/C developer familiar with
PKCS#11 and the Remmina chooser/PIN work. Remaining effort and a distribution-ready release
are unestimated.

Assumptions are full-time work by one developer, OpenSC-compatible PIV only, hardware available
throughout (including a card that can be blocked, a PIN-pad reader and two readers), GNOME/Wayland
first and KDE later. Additional card stacks and application integration need separate estimates.
The feasibility gates below must pass before depending on the interface.

| Work | Estimate |
|---|---|
| Feasibility checks, phase 0 | 2–4 weeks |
| Frontend/backend plumbing | 2–3 weeks in the total-work estimate; implemented on the frontend branch |
| Chooser, enumeration, request lifecycle and brokered signing | 4–7 weeks |
| PIN interaction, protected path, removal, concurrency and lifecycle hardening | 3–5 weeks |
| Optional served synthetic PKCS#11 facade | 5–9 weeks |
| WebKitGTK/GnuTLS integration and distribution testing | 3–6 weeks |
| Packaging, fuzzing, documentation, accessibility and security review | 4–7 weeks |
| Brokered-signing prototype | 10–15 person-weeks total |
| Release including a served facade | 20–33 person-weeks total |

The optional served-facade estimate covers a separate design from the
[implemented client module](decisions/0011-client-side-pkcs11-module.md). Firefox, Chromium, NSS,
VPN, mail, SSH and PDF integrations each need their maintainers' agreement and work in their
own trees. Frontend mock tests cover
hardware-independent policy and lifecycle; they cannot replace card tests.

## Phase 0: feasibility gates

Allow 2–4 weeks for focused experiments. Disposable experiment code should answer a question
without becoming a product dependency. [SPIKES.md](SPIKES.md) records the detailed checks.
Interface stability requires evidence for:

1. A real GnuTLS mutual-TLS handshake through brokered `Sign`.
2. A real WebKitGTK client-certificate handshake. The module must be configured in each process
   that uses GLib's PKCS#11 URI constructor, which has no module parameter. Recorded once
   (2026-09-05) through the now-stopped web-auth backend.
3. Wrong PIN and final retry on hardware that can be unblocked. The GNOME fork's dialog
   passed through the final-try warning on 2026-10-19; Cancel on the final try remains unrun.
4. Protected authentication path on a PIN-pad reader without an emulated entry.
5. Card removal during signing.
6. Simultaneous credentials in one consumer process.
7. Hostile-client tests for any served facade, including v3 tables and administration refusals.
8. Caller disconnect during an operation.
9. Mechanism-parameter tests and fuzzing of any served RPC surface.
10. Frontend/backend cancellation, result clamping and hardware runs; fd relay tests if an
    endpoint method is proposed. Frontend mock tests cover cancellation and clamping.

GnuTLS and WebKitGTK have dated evidence in [TESTING.md](TESTING.md). Hardware breadth and
remaining gates are open. Facade-specific gates apply only if that design is pursued.

## Phase 1: brokered-signing backend

The total prototype estimate is 10–15 person-weeks. Scope is the GTK backend's chooser, PIN
interaction, discovery and broker; the frontend owns identity, policy, grants, lifecycle and
backend selection.

Requirements include OpenSC-compatible PIV cards, p11-kit API enumeration and filtering,
trusted accessible dialogs, verified Flatpak identities and labelled host callers, short-lived
independent grants, removal/invalidation, and separate `client_auth` and `signing` consent
policies. The mechanisms are RSA PKCS#1 v1.5, RSA-PSS and ECDSA as supported by tested cards.
The first consumers are browsers loading the client-side PKCS#11 module: Firefox (tested
2026-09-06 and 2026-10-16) and Chrome (tested 2026-10-16). The web-auth backend was the first
consumer until its development stopped on 2026-10-16.

Complete [chain construction](IMPL-INTERFACE.md#token-display-and-chain) with best-effort
intermediates and `complete`/`partial`/`leaf_only` reporting. Add idle exit with no sessions and
[per-operation signing consent](SECURITY.md#missing-controls-and-evidence).
[Selection memory](SECURITY.md#selection-memory) needs a frontend design; the interface has no
`certificate` permission-store table.

PIN storage, decryption, SSH-agent and S/MIME protocols, remembered authorization, raw PC/SC
forwarding and stock-token forwarding described as certificate scoping are outside this phase.
Browser experiments in the test record do not establish packaging or general browser support.

## Phase 2: packaging and compatibility

Package the backend and module, test GNOME and KDE on Wayland including parenting and activation,
and confirm browser consumers without manual setup. The [GNOME](https://github.com/sjtrotter/xdg-desktop-portal-gnome/tree/experimental/certificate)
and [KDE](https://github.com/sjtrotter/xdg-desktop-portal-kde/tree/experimental/certificate)
forks implement native backends with their own `.portal` files. Both have SoftHSM container
coverage. GNOME also ran in a live GNOME 50 session with one PIV card, including test-client
signing, Flathub Firefox sign-in, chooser hotplug, wrong PIN through the final-try warning and
Shell system prompting. KDE has no live-session or card run and uses its own PIN dialog.
PIN-pad and Cancel-on-final-try hardware checks remain open.

A served synthetic facade is optional future work. It needs an `OpenPkcs11Endpoint` proposal in
the frontend, endpoint versioning and capabilities, synthetic handle mapping, administrative
refusals, mechanism validation, process isolation, fd-transfer review and RPC fuzzing. Its
20–33 person-week cumulative estimate applies only to that larger scope. Firefox and Chromium
packaging, sandbox and lifecycle integration are separate projects, beyond this milestone.

## Phase 3: interface agreement

Discuss certificate-backed signing with the credentials-portal developers before freezing names
or signatures. It may fit as a credential type sharing identity and consent machinery while
remaining independently deployable. [ADR 0003](decisions/0003-own-namespace-before-freedesktop.md)
lists the conversation order. `Certificate` remains an incubation name.

1. Working implementation and published introspection XML.
2. Documented threat model, consent policy, identity, scoping and UI security.
3. Two independent consumers; Firefox and Chrome through the PKCS#11 module are the current ones.
4. GNOME and KDE/Wayland testing, including parenting and activation.
5. An upstream new-portal issue identifying the protected host resource: hardware-backed private
   key use and trusted consent/PIN interaction, replacing blanket `--socket=pcsc` access.
6. Agreement on the public API and frontend enforcement, including backend-owned device access
   and Request-shaped `Sign`; round-trip latency remains unmeasured.
7. Frontend routing and an impl interface. Both exist on the unmerged fork branch without
   implying maintainer agreement. `Session.Close()` releases grants; `GrantInvalidated` gives reasons.
8. A backend implementation and interest from a second desktop.
9. Conformance tests and documentation before retiring the incubation name.

## Deferred work

| Item | Requirement or constraint |
|---|---|
| Served PKCS#11 endpoint | Separate fd-returning API review and tests capable of returning a usable endpoint; client module already serves PKCS#11 consumers |
| Decryption | Consumer and per-operation consent design for confidential-data release |
| SSH-agent protocol | Independent purpose, policy and long-lived-agent expectations |
| S/MIME integration | Mail-client maintainer participation |
| Enrolment, key generation, PIN change/unblock, import | Separate administrative consent and UI; absent from this interface |
| PIN caching | No storage; token-level login caching is uncontrolled hardware behavior |
| Windows-style minidriver semantics | Certificate propagation, device-level caching and a CSP/KSP-like OS-wide API would require broader platform work |
| Non-PIV stacks | Hardware and middleware testing for each stack |
| Raw PC/SC forwarding | Grants direct device access outside certificate-scoped mediation |

## Email operation matching

[Email-purpose matching](IMPL-INTERFACE.md#email-purpose-matching) uses the existing
four-purpose vocabulary for the internal signing/decryption split.

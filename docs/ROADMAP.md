# Roadmap

Status: EXPERIMENTAL design sketch. The sketch itself is done; nothing after it has started, and
**phase 0 is a spike that may end the project rather than a build that begins it.**

## Effort figures and their assumptions

Person-weeks for **one experienced Linux security/C developer**, already familiar with PKCS#11 and
with the working Remmina chooser/PIN patches. They describe a *credible* result, not a
distribution-ready one. State the assumptions plainly, because effort numbers travel further than
their caveats:

- one developer, not a team, and not part-time;
- PIV cards through OpenSC only — every additional card stack is separate work;
- real hardware available throughout, including a card the author is willing to **block**, a PIN-pad
  reader, and two readers at once;
- GNOME/Wayland as the primary target, with KDE testing later;
- **no browser integration**, which is separate work in someone else's tree;
- the figures assume S1 and S3 **pass**. If they fail the project gets smaller, not later.

| | |
|---|---|
| Feasibility spike (phase 0) | **2–4 weeks** |
| Chooser, enumeration, D-Bus request lifecycle, basic brokered signing | 4–7 weeks |
| PIN agent, protected path, removal, concurrency, lifecycle hardening | 3–5 weeks |
| The restricted synthetic PKCS#11 facade | 5–9 weeks |
| WebKitGTK/GnuTLS integration and distro testing | 3–6 weeks |
| Packaging, fuzzing, documentation, accessibility, security review | 4–7 weeks |
| **A useful brokered-signing prototype** | **8–12 person-weeks** |
| **A credible release including the experimental facade** | **18–30 person-weeks** |

Firefox, Chromium, NSS, VPN clients, mail clients, SSH and PDF signing are **more** on top of that,
each in its own tree, each needing its own maintainers to agree.

---

## Phase 0 — Time-boxed feasibility spike — **2–4 weeks**

Not a build. A disposable experiment that answers [SPIKES.md](SPIKES.md) S1, S2 and S3 and either
justifies the rest of this document or ends it. The code is thrown away.

While it runs, `webauth-service` keeps its **in-process certificate handling behind an internal
adapter**, so that it can use either this service or its own implementation. Nothing depends on this
project until the spike passes.

**Gate: the D-Bus API is not stabilised, and this repository is not published as anyone's
dependency, until all of the following exist.**

1. One real **GnuTLS mutual-TLS client** handshake through brokered `Sign`.
2. One real **WebKitGTK client-certificate handshake** — joint with `webauth-service`, and the
   weakest link in the design. Module loading is the specific unknown:
   `g_tls_certificate_new_from_pkcs11_uris()` has no module parameter and a URI cannot name a
   socket. **The likely architecture is one permanently registered broker module exposing synthetic
   grant-bound slots**, not a new module per grant; the spike is what decides.
3. **Wrong-PIN and final-retry** behaviour, on a card the author is prepared to block.
4. **Protected authentication path** on a PIN-pad reader, with no emulated PIN field.
5. **Card removal during signing.**
6. **Simultaneous grants** in one consumer process.
7. **Hostile-client PKCS#11 call tests** against the facade — every administrative and
   key-management entry point refused, including through the PKCS#11 v3 interface tables.
8. **Caller disconnect and subprocess delegation** tests.
9. **Fuzzing** of the facade's RPC surface and **mechanism-parameter validation** tests, RSA-PSS
   included.

---

## Phase 1 — Brokered-signing service — **8–12 person-weeks**

Assuming the spike passed. A working service on the machines the author controls. Not packaged for
the world, not proposed to anyone, **facade not included**.

**Scope, deliberately narrow:**

- OpenSC-compatible **PIV cards only**;
- certificate enumeration and filtering, with the Remmina hardware edge-case list as acceptance
  criteria, using the p11-kit API rather than a `p11tool` subprocess;
- one selected certificate; leaf DER plus best-effort intermediates, labelled `complete`/`partial`/
  `leaf_only`;
- the trusted chooser and the PIN / protected-path UI, with accessibility as acceptance criteria;
- verified Flatpak application identity, and clearly marked unsandboxed callers;
- **`client_auth` and `signing` as separate purposes**, with separate consent policies;
- short-lived grants, multiple independent grants, removal and invalidation signals;
- brokered `Sign`, with RSA PKCS#1 v1.5, RSA-PSS and ECDSA **only as the tested cards require**;
- `webauth-service` as the first consumer, through brokered signing where its TLS stack permits.

**Explicitly not in phase 1:** no PIN storage; no decryption; no SSH-agent protocol; no S/MIME
integration; no browser integration claims; no remembered authorisation; no raw PC/SC forwarding;
**and no stock-token forwarding presented as object scoping**.

---

## Phase 2 — The experimental PKCS#11 facade — to **18–30 person-weeks** cumulative

The compatibility milestone, and the one with the security-sensitive engineering in it: the
synthetic module, its refusals, its handle mapping, its mechanism validation, its process isolation,
its fuzzing. `OpenPkcs11Endpoint` appears here, marked experimental, versioned by
`endpoint_version`, and reported by `GetCapabilities` so no caller has to probe by failing.

Also here: distro packaging; GNOME **and KDE** Wayland testing, including parenting and activation
(a KDE implementation of the chooser and PIN UI is a prerequisite for phase 3, and there is no KDE
equivalent of gcr's prompter to defer to); and the first non-`webauth-service` consumer, chosen for
being *willing* rather than for being popular.

**Firefox and Chromium are not this phase's consumers.** Their sandboxing, module lifecycle, browser
UI and client-certificate selection paths all differ, and each needs explicit integration work in its
own tree by people who are not the author of this project. They are the long-term case for the
project, not a phase-2 deliverable.

---

## Phase 3 — Talk to the credentials people, then to freedesktop

**In that order.** The [linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd)
project is already proposing `org.freedesktop.portal.Credentials` for FIDO2 and passkeys. The
question to ask them, before freezing any name or D-Bus signature, is: **does certificate-backed
signing belong as a credential type under that proposal**, sharing its request, identity and consent
machinery, while remaining independently deployable?

The expectation should be that maintainers prefer a coherent credential-use model over a portal
named after a physical device; that `ClientCertificate` or `CryptographicCredential` is a better
conceptual boundary than `Smartcard`, because the backing key might be a TPM, a software token, a
phone or a remote HSM; and that "return a PKCS#11 module" will not be accepted as the generic
credential abstraction. The name in this repository is expected to change.

Only then, the acceptance path:

1. A working implementation with published introspection XML — done in phases 1–2.
2. Documented threat model, consent policy, caller identity model, scoping guarantees, and UI
   security chrome — this repository's `docs/`, once they describe something real.
3. **Two consumers**, one of them unrelated to `webauth-service`. One consumer is a private tool
   with extra governance obligations.
4. Tested on GNOME **and** KDE/Wayland, including parenting and activation.
5. A design discussion opened in `flatpak/xdg-desktop-portal`, where the project directs requests for
   new portals — with the answer to "what protected host resource is being mediated?" written down
   first. The honest answer here: **use of a hardware-backed private key, and the trusted consent and
   PIN UI around it**, replacing a blanket `--socket=pcsc` grant with a scoped, revocable,
   attributable one.
6. Agreement on the public interface and on what the frontend enforces.
7. Frontend routing plus an `org.freedesktop.impl.portal.*` backend interface, derived **with** the
   maintainers rather than imitated in advance.
8. At least one backend implementation, and interest from a second desktop.
9. Conformance tests and documentation before the incubating name is declared obsolete.

This is long on purpose. The failure mode is a name claimed early and an interface frozen before it
was understood.

---

## Deferred, with reasons

| | Why not now |
|---|---|
| **Decryption** | A different and larger consent question — it exposes confidential data rather than producing an authentication artefact — and it needs per-operation policy that `Sign` does not. |
| **SSH agent protocol** | Its own purpose, its own policy, its own long-lived-agent expectations. Not "signing with extra steps". |
| **S/MIME integration** | Needs a mail client's maintainers, not this project's. |
| **Enrolment, key generation, PIN change and unblock, certificate import** | Each is a different consent question with a different UI, and a service that mediates *use* should not be able to perform *administration*. The facade refuses these functions outright. |
| **PIN caching policy** | There is no PIN caching, so there is no policy. Token-level login caching is hardware behaviour this project does not control and must not present as a feature. |
| **Windows-style minidriver semantics** | Certificate propagation into a system store, a device-level PIN cache, a CSP/KSP layer every application uses implicitly. It is the right long-term shape and it presumes an OS-wide credential API that Linux does not have. Building one on top of a D-Bus service nobody has adopted is a way to have neither. |
| **Non-PIV card stacks** | Each is separate testing on hardware the author does not have. |
| **Raw PC/SC forwarding** | That is `--socket=pcsc` with extra steps, and it is what this exists to replace. |

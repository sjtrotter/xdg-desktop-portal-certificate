# Roadmap

Status: EXPERIMENTAL. **The backend is built.** The chooser, the PIN prompt, token discovery,
certificate filtering and brokered `Sign`/`Decrypt` exist, build clean, and have been driven end to
end through the real frontend against a software token. What has *not* happened is the thing the
whole list below was gated on: **nothing has touched a smart card.** The facade is still not
reachable, and the spikes that decide whether it can exist are still unrun.

Read the table under "Where the code actually is" before the effort figures: the figures were
written when none of this existed and have not been re-derived.

**What has changed since this document was last honest about its own scope:** the frontend is no
longer this project's to build. It is an xdg-desktop-portal branch
([0010](decisions/0010-backend-only-frontend-lives-upstream.md),
[UPSTREAMING.md](UPSTREAMING.md)), written and passing its own test suite. Every "the
frontend/backend split itself" line below is therefore work that is *done, elsewhere, by the same
author*, and what is left in this repository is the backend. The effort figures have not been
re-derived from scratch; the split's line is struck through in the table instead, which is honest
about where the saving landed without pretending the rest of the numbers got any better.

## Where the code actually is

| | Status |
|---|---|
| The frontend, the impl interface, app-id derivation, the grant registry, the permission store, backend discovery | **Done**, upstream, on the branch. 40 pytest cases green against a mock backend |
| PKCS#11 module loading, slot and token enumeration, certificate and key discovery, X.509 parsing | **Done**. `--list-tokens` prints it |
| The purpose rules and `certificate_filter` | **Done**, unit-tested against seven real fixture certificates |
| The mechanism mapping and its parameter validation | **Done**, unit-tested, including the RSA-PSS salt that does not fit the key |
| The chooser | **Done**. Identity level in words, caller text quoted and labelled, expiry as a word |
| The PIN prompt | **Done**, including protected authentication path, retry, and locked-token handling |
| Brokered `Sign`, lazy login, one PKCS#11 session per grant | **Done**. Verified against SoftHSM for RSA PKCS#1 v1.5, RSA-PSS and ECDSA |
| Brokered `Decrypt` | **`RSA_OAEP` only**, now that the frontend's allow list has it. PKCS#1 v1.5 decryption stays refused: over D-Bus it is a padding oracle against the card's key. Every failure is one error and a grant buys 32 attempts; see [IMPL-INTERFACE.md](IMPL-INTERFACE.md) |
| Token insertion and removal watching, `SessionInvalidated` | **Done**, polled, debounced. Never tested with a card actually leaving a reader |
| The end-to-end client, the private-bus stack, the headless UI run | **Done** |
| Chain building | **Not done.** `chain_status` is always `leaf_only` |
| Rate limiting | **Not done**, on either side |
| The synthetic PKCS#11 facade | **Not started, and unreachable**: `OpenPkcs11Endpoint` is on neither interface |
| Anything on hardware | **Not done.** This is the gap that matters |
| Translation, packaging, a KDE backend | **Not started** |

The two-to-four-week feasibility spike below is therefore **half-answered**: the brokered path is
built and works, which was never the doubtful half. S1 and S3 — can a synthetic facade exist, and
can a browser use it — are untouched, and they are the ones that decide the shape of everything
after brokered `Sign`.

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
- the figures assume S1 and S3 **pass**. If they fail the project gets smaller, not later;
- the frontend/backend split was in these figures at two to three person-weeks. It is now **out**,
  because the frontend is upstream's code on an xdg-desktop-portal branch and the "half of it that
  is plumbing xdg-desktop-portal already has" is no longer written twice
  ([0010](decisions/0010-backend-only-frontend-lives-upstream.md)). What remains of that line is
  keeping this backend's impl XML in step with the branch, which is not measured in weeks;
- the frontend's own hardware-independent testing is done and green (40 pytest cases for this
  portal against a python-dbusmock backend), which removes some of phase 0 item 10 below but none
  of the hardware items.

| | |
|---|---|
| Feasibility spike (phase 0) | **2–4 weeks** |
| ~~The frontend/backend split itself: two services, the impl interface, app-id derivation, permission store, backend discovery~~ | ~~2–3 weeks~~ — done upstream, on a branch |
| Chooser, enumeration, D-Bus request lifecycle, basic brokered signing | 4–7 weeks |
| PIN agent, protected path, removal, concurrency, lifecycle hardening | 3–5 weeks |
| The restricted synthetic PKCS#11 facade | 5–9 weeks |
| WebKitGTK/GnuTLS integration and distro testing | 3–6 weeks |
| Packaging, fuzzing, documentation, accessibility, security review | 4–7 weeks |
| **A useful brokered-signing prototype** | **10–15 person-weeks** |
| **A credible release including the experimental facade** | **20–33 person-weeks** |

Firefox, Chromium, NSS, VPN clients, mail clients, SSH and PDF signing are **more** on top of that,
each in its own tree, each needing its own maintainers to agree.

---

## Phase 0 — Time-boxed feasibility spike — **2–4 weeks**

Not a build. A disposable experiment that answers [SPIKES.md](SPIKES.md) S1, S2 and S3 and either
justifies the rest of this document or ends it. The code is thrown away.

While it runs, `xdg-desktop-portal-webauth` keeps its **in-process certificate handling behind an
internal adapter**, so that it can use either this backend or its own implementation. Nothing
depends on this project until the spike passes.

**Gate: the D-Bus API is not stabilised, and this repository is not published as anyone's
dependency, until all of the following exist.**

1. One real **GnuTLS mutual-TLS client** handshake through brokered `Sign`.
2. One real **WebKitGTK client-certificate handshake** — joint with `xdg-desktop-portal-webauth`, and the
   weakest link in the design. Module loading is the specific unknown:
   `g_tls_certificate_new_from_pkcs11_uris()` has no module parameter and a URI cannot name a
   socket. **The likely architecture is one permanently registered broker module exposing synthetic
   grant-bound slots**, not a new module per grant; the spike is what decides.
3. **Wrong-PIN and final-retry** behaviour, on a card the author is prepared to block.
4. **Protected authentication path** on a PIN-pad reader, with no emulated PIN field.
5. **Card removal during signing.**
6. **Simultaneous grants** in one consumer process.
7. **Hostile-client PKCS#11 call tests** against the facade — every administrative and
   key-management entry point refused, including through the PKCS#11 v3 interface tables. (Blocked
   on there *being* a facade: `OpenPkcs11Endpoint` is on neither interface, having been deferred as
   a follow-up in the frontend branch.)
8. **Caller disconnect and subprocess delegation** tests.
9. **Fuzzing** of the facade's RPC surface and **mechanism-parameter validation** tests, RSA-PSS
   included.
10. **The frontend/backend boundary** ([SPIKES.md](SPIKES.md) S5). Three of its four questions are
    already answered by the branch's pytest suite against a mock backend — `Close()` reaching the
    impl Request, a backend that over-claims being clamped, and the experimental gate — so what is
    left is the fd relay (which needs a method that does not exist) and the same tests against a
    backend that talks to real hardware.

---

## Phase 1 — Brokered-signing frontend and backend — **10–15 person-weeks**

Assuming the spike passed. A working service on the machines the author controls. Not packaged for
the world, not proposed to anyone, **facade not included**.

**Scope, deliberately narrow:**

- **one process here**: the GTK backend (chooser, PIN, discovery, brokered signing), answering the
  impl interface. The frontend half — identity, policy, permissions, request and session lifecycle,
  backend discovery — exists already, upstream, on a branch;
- OpenSC-compatible **PIV cards only**;
- certificate enumeration and filtering, with the Remmina hardware edge-case list as acceptance
  criteria, using the p11-kit API rather than a `p11tool` subprocess;
- one selected certificate; leaf DER plus best-effort intermediates, labelled `complete`/`partial`/
  `leaf_only`;
- the trusted chooser and the PIN / protected-path UI, with accessibility as acceptance criteria;
- verified Flatpak application identity **derived in the frontend and rendered by this backend**,
  with clearly marked unsandboxed callers — the derivation is xdg-desktop-portal's and is done;
- remembered certificate selection in the real `org.freedesktop.impl.portal.PermissionStore`, table
  `certificate`, and nothing else in it — also the frontend's, also done;
- **`client_auth` and `signing` as separate purposes**, with separate consent policies;
- short-lived grants, multiple independent grants, removal and invalidation signals;
- brokered `Sign`, with RSA PKCS#1 v1.5, RSA-PSS and ECDSA **only as the tested cards require**;
- `xdg-desktop-portal-webauth` as the first consumer, through brokered signing where its TLS stack
  permits — which, with no `OpenPkcs11Endpoint` on the interface, is the only path there is.

**Explicitly not in phase 1:** no PIN storage; no decryption; no SSH-agent protocol; no S/MIME
integration; no browser integration claims; no remembered authorisation; no raw PC/SC forwarding;
**and no stock-token forwarding presented as object scoping**.

---

## Phase 2 — The experimental PKCS#11 facade — to **20–33 person-weeks** cumulative

The compatibility milestone, and the one with the security-sensitive engineering in it: the
synthetic module, its refusals, its handle mapping, its mechanism validation, its process isolation,
its fuzzing. `OpenPkcs11Endpoint` appears here — and note that it now has to be **added to the
frontend branch first**, as the follow-up that commit's message promises, before this repository has
anything to answer. Marked experimental, versioned by `endpoint_version`, and reported by
`GetCapabilities` so no caller has to probe by failing.

Also here: distro packaging **of this backend**, which is one package rather than two now; GNOME
**and KDE** Wayland testing, including
parenting and activation (a KDE chooser and PIN prompt is a prerequisite for phase 3 — and is now a
second *backend package* with its own `.portal` file rather than a second code path in one binary,
which is the main practical dividend of [0008](decisions/0008-build-to-the-upstream-shape.md); there
is still no KDE equivalent of gcr's prompter to defer to); and the first consumer that is not
`xdg-desktop-portal-webauth`, chosen for being *willing* rather than for being popular.

**Firefox and Chromium are not this phase's consumers.** Their sandboxing, module lifecycle, browser
UI and client-certificate selection paths all differ, and each needs explicit integration work in its
own tree by people who are not the author of this project. They are the long-term case for the
project, not a phase-2 deliverable.

---

## Phase 3 — Talk to the credentials people, then to freedesktop

**In that order, and note that step 7 has already been done in the wrong order.** The frontend
exists, as an unproposed branch. That is the sanctioned way to write an experimental portal
([UPSTREAMING.md](UPSTREAMING.md)) but it is not a substitute for opening the conversation, and it
must not be presented as one. The [linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd)
project is already proposing `org.freedesktop.portal.Credentials` for FIDO2 and passkeys. The
question to ask them, before freezing any name or D-Bus signature, is: **does certificate-backed
signing belong as a credential type under that proposal**, sharing its request, identity and consent
machinery, while remaining independently deployable?

The expectation should be that maintainers prefer a coherent credential-use model over a portal
named after a physical device; that `ClientCertificate` or `CryptographicCredential` is a better
conceptual boundary than `Certificate`, because the backing key might be a TPM, a software token, a
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
7. Frontend routing plus an `org.freedesktop.impl.portal.*` backend interface. **Both already
   exist**, in the `experimental` namespace, on an unproposed xdg-desktop-portal branch with a
   passing test suite — which is a patch to argue with rather than a design to start. It is
   emphatically not a claim that the shape is agreed: which side opens the device, `Sign` returning
   a `Request`, and the duplicated `ReleaseGrant`/`GrantInvalidated` are still questions for
   maintainers, and the answers may change the interface.
8. At least one backend implementation, and interest from a second desktop.
9. Conformance tests and documentation before the incubating name is declared obsolete.

This is long on purpose. The failure mode is a name claimed early and an interface frozen before it
was understood.

---

## Deferred, with reasons

| | Why not now |
|---|---|
| **The PKCS#11 endpoint** | Deferred by the frontend branch, not by this repository: an fd-returning method needs its own review, and the mock backend the frontend is tested against cannot produce a usable fd. Until it is added there, every consumer that can only speak PKCS#11 is unserved. |
| **Decryption** | A different and larger consent question — it exposes confidential data rather than producing an authentication artefact — and it needs per-operation policy that `Sign` does not. |
| **SSH agent protocol** | Its own purpose, its own policy, its own long-lived-agent expectations. Not "signing with extra steps". |
| **S/MIME integration** | Needs a mail client's maintainers, not this project's. |
| **Enrolment, key generation, PIN change and unblock, certificate import** | Each is a different consent question with a different UI, and a service that mediates *use* should not be able to perform *administration*. The facade refuses these functions outright. |
| **PIN caching policy** | There is no PIN caching, so there is no policy. Token-level login caching is hardware behaviour this project does not control and must not present as a feature. |
| **Windows-style minidriver semantics** | Certificate propagation into a system store, a device-level PIN cache, a CSP/KSP layer every application uses implicitly. It is the right long-term shape and it presumes an OS-wide credential API that Linux does not have. Building one on top of a D-Bus service nobody has adopted is a way to have neither. |
| **Non-PIV card stacks** | Each is separate testing on hardware the author does not have. |
| **Raw PC/SC forwarding** | That is `--socket=pcsc` with extra steps, and it is what this exists to replace. |

---

## Open questions

| | |
|---|---|
| **~~A decryption-only certificate matches no purpose~~** | **Settled.** `email` now matches a certificate whose extended key usage permits `emailProtection` (or carries none) and whose key usage permits `digitalSignature` **or** `keyEncipherment`, and the half it matched decides which operations it can serve. A decrypt-only certificate — a PIV "key management" certificate — is offered for `email` only when the request's `operation_policy` permits `decrypt`, and its grant then permits `decrypt` alone. The purpose vocabulary stayed at four; the sign/decrypt split lives in `operation_policy`, where the application already states it. Decided on the frontend branch first (`7635aa8`), then implemented here. See [IMPL-INTERFACE.md](IMPL-INTERFACE.md#email-is-the-one-purpose-that-does-not-end-in-a-signature). |

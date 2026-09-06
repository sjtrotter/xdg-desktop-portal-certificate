# Go / no-go spikes

Status: EXPERIMENTAL. **S1 and S3 have answers now, and they are not the answers these pages
expected.** Both were written about a facade served over a socket from a helper process beside this
backend, reached through an `OpenPkcs11Endpoint` that was never added to either interface. What was
built instead is a PKCS#11 module that runs in the APPLICATION's process and forwards to the public
portal interface over D-Bus — [0011](decisions/0011-client-side-pkcs11-module.md). S3's own list of
workarounds had already named the shape ("one permanently registered broker module ... exposing
synthetic grant-bound slots"); the only thing it got wrong was which process the module runs in.

**What has actually run**, on 2026-09-04, against the SoftHSM fixture on a private bus under Xvfb
(`tools/module-smoke.sh`):

- GnuTLS enumerating the token through the module (`p11tool --list-all`), with the chooser
  appearing at the search and the certificate, public key and private key all present;
- `pkcs11-tool --sign --mechanism SHA256-RSA-PKCS`, verified with `openssl dgst` against the
  certificate the module handed back;
- **a real mutual-TLS handshake**, TLS 1.3, from a GLib client built with
  `g_tls_certificate_new_from_pkcs11_uris()` — the constructor WebKitGTK reaches through
  glib-networking — against a server that required and verified the client certificate;
- the same, with the module built under AddressSanitizer, clean.

**NSS was added on 2026-09-06** — `tools/nss-smoke.sh`, the module loaded as Firefox loads it, a
private key found, a certificate listed as a user certificate, and a TLS 1.3 client-auth handshake
through `tstclnt`, clean under AddressSanitizer as well. It cost two module fixes, both in
[0011](decisions/0011-client-side-pkcs11-module.md): `CKA_TOKEN` had to stop counting as a
distinguishing attribute, and the token had to stop claiming `CKF_LOGIN_REQUIRED`.

**What is still unrun** is the rest of S1 (Firefox itself — see [TESTING.md](TESTING.md) §2.6 — the
OpenSSL 3 provider, fuzzing, concurrency) and
all of S3's browser-process questions: WebKitGTK itself has not been driven, only the API it uses.

The rest of this document is unchanged except where marked, because a spike's questions outlive the
answer to one of them.

What the implementation has answered, partially — against a software token, and since 2026-09-04
against one PIV card in one reader as well ([TESTING.md](TESTING.md) tiers 3.1–3.4):

- **S2, both halves.** The backend keeps its own PKCS#11 session per grant, logs in lazily at
  first private-key use, and the PIN prompt is its own window. The module half is answered too, and
  the answer is `CKF_PROTECTED_AUTHENTICATION_PATH`: with it set, GnuTLS calls
  `C_Login(CKU_USER, NULL, 0)` and never asks the user for a PIN, which is what makes "the PIN
  never reaches the consumer" a property rather than a wish. A TLS stack opening its own sessions
  turned out to matter for a different reason than expected: GnuTLS opens and closes one for every
  object import and every signature, so a grant released with the last PKCS#11 session put the
  chooser up again each time. The grant now outlives the sessions.
- **S4's software half.** Tokens are identified by manufacturer, model, serial and label together
  and re-resolved on every use, so a different card in the same slot is a different token by
  construction. The insertion and removal watcher polls every two seconds and debounces over two
  polls. **Both numbers are guesses**, and S4 exists to replace them with measurements from real
  readers; the one card that has been read was inserted before the run and left there. Nothing has
  been pulled out of a reader mid-signature.
- **S5's non-fd half.** Answered by the branch's own pytest suite, plus this repository's
  private-bus run: a real frontend and a real backend complete `CreateSession`,
  `AcquireCredential`, `Sign` and `Close` on a private bus, and a backend crash surfaces as
  "Backend call failed" rather than a hang — which is how the one use-after-free found so far was
  noticed.

S1 and S3 have moved; see the status paragraph above and
[0011](decisions/0011-client-side-pkcs11-module.md).

Two things changed since this list was written. The frontend is now an xdg-desktop-portal branch
([0010](decisions/0010-backend-only-frontend-lives-upstream.md)), so **S5 is largely answered
already** — against a mock backend, in the test harness that branch brings with it, which until
the branch is accepted is this author's to run and to keep passing — and what is left of it is
noted in place. And `OpenPkcs11Endpoint` is still not on either interface — but S1 and S2 are no
longer blocked on it, because the module they now describe needs no interface method at all.

Phase 0 of [ROADMAP.md](ROADMAP.md) is a **time-boxed feasibility spike of 2–4 weeks**, not a build.
The rule for all of them: a spike is throwaway code that answers one question. It does not become
the product, it does not get a test suite, and it does not get merged.

| | Question | Decides |
|---|---|---|
| **S1** | Can a broker-controlled synthetic PKCS#11 module actually be built and consumed? | Whether the compatibility path exists at all. **GnuTLS: yes. NSS: yes, since 2026-09-06. Firefox itself and the OpenSSL provider: unrun** |
| **S2** | Who prompts for the PIN, and when, once a module is involved? | The login model. **Answered: `CKF_PROTECTED_AUTHENTICATION_PATH`, and no stack tried to synthesise a PIN** |
| **S3** | Can WebKitGTK complete a client-certificate handshake through it? | Whether the first consumer can use this project. **The GLib constructor WebKit uses: yes. WebKit itself: unrun** |
| **S4** | What happens with removal, reinsertion, and several readers? | Whether the lifetime model is right, and how much of it is card-specific |
| **S5** | Does the frontend/backend split survive contact with fd passing, prompts and a dying backend? | Mostly answered by the branch's pytest suite; the fd half is blocked on there being an fd |

**S3 was the one that decided whether this project is worth publishing**, and its central question —
can a real TLS stack complete a client-certificate handshake against a synthetic token this project
serves — is answered yes. What remains of it is a browser rather than a design risk.
`xdg-desktop-portal-webauth` should still keep its in-process adapter until WebKitGTK itself has
been driven.

---

## S1 — Object and operation scoping: the facade

**The question.** The original claim — "`p11-kit server` exports a module scoped to one certificate
and key, already logged in" — is **false**. `p11-kit server` takes **token** URIs; its unit of
exposure is a token, not an object. It forwards the general PKCS#11 interface, including object
creation and key generation. Login state does not cross the boundary. So: can a **synthetic**
PKCS#11 module — one this project implements — be built, served, and driven by real TLS stacks?

**Why it matters.** If the answer is no, the compatibility endpoint does not exist, the project is
brokered `Sign` only, and every consumer needs explicit integration work in its own tree. That is a
much smaller project with a much longer adoption path — worth knowing in week two rather than month
six.

### Steps

1. Build a minimal `CK_FUNCTION_LIST` that wraps OpenSC's module and exposes **one synthetic slot,
   one synthetic token, one certificate and one private key**, with synthetic handles mapped to
   underlying ones.
2. Serve it over a socket with
   [`p11_kit_remote_serve_module()`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/remote.h)
   [[S10](SOURCES.md)]
   (behind `P11_KIT_FUTURE_UNSTABLE_API`). Confirm this entry point is usable and stable enough to
   depend on, and what happens when it is not present in the distro's p11-kit.
3. Drive it from `p11-kit-client.so` and complete **one real GnuTLS mutual-TLS client handshake**
   against a test server that requests a client certificate. This is publication gate #1.
4. Repeat with **NSS** (`modutil`-registered) and with the
   [OpenSSL 3 pkcs11 provider](https://github.com/latchset/pkcs11-provider). Record for each: does it
   load, does it find one certificate and one key, does it complete the handshake, what does it call
   that the facade must answer.
5. **Hostile-client tests.** Against the facade, attempt: `C_CreateObject`, `C_CopyObject`,
   `C_DestroyObject`, `C_SetAttributeValue`, `C_GenerateKeyPair`, `C_WrapKey`, `C_DeriveKey`,
   `C_InitPIN`, `C_SetPIN`, `C_InitToken`, SO login, `CKF_RW_SESSION`, a fabricated object handle, a
   handle from another grant, `C_FindObjects` with a template matching every object on the card,
   `C_GetAttributeValue` for sensitive attributes, a mechanism not in the allow-list, and RSA-PSS
   with mismatched hash/MGF/salt parameters. **Every one must be refused.** Also confirm the
   **PKCS#11 v3 `C_GetInterface`** path is filtered, not just `C_GetFunctionList`.
6. **Concurrency.** Two grants, two certificates, two endpoints, in one consumer process. Determine
   whether `p11-kit-client.so`'s single `P11_KIT_SERVER_ADDRESS` makes this impossible, and if so
   what does work: several dynamically loaded module instances, or one multiplexing broker module
   with grant-aware virtual slots.
7. **Fuzz** the RPC surface the facade exposes.
8. **Sandbox reach.** Determine whether the endpoint fd can be used inside a Flatpak — it is passed
   over D-Bus, which should be the point of doing it that way — and what p11-kit configuration the
   sandboxed consumer still needs.
9. **Two hops.** The fd is created by the backend, returned over the impl interface, and relayed by
   the frontend without being copied. Confirm that survives: that the descriptor the application
   receives is the backend's socket, that no reference is retained by the frontend, that closing it
   in the application is observed by the facade helper, and that a `GUnixFDList` round trip through
   two services does not silently duplicate or leak it. This is S5's first step and it belongs in
   both spikes.

**Pass** = a real GnuTLS mutual-TLS handshake through the facade, every hostile call refused, a
credible answer for concurrency, and the fd surviving the relay. **Fail** = brokered operations only; delete `OpenPkcs11Endpoint`
from the interface rather than shipping it weakened.

### What was actually run, 2026-09-04

The module was built in the **application's** process rather than served over a socket
([0011](decisions/0011-client-side-pkcs11-module.md)), so steps 2, 6, 8 and 9 do not apply: there
is no RPC transport, no `P11_KIT_SERVER_ADDRESS`, no fd and no relay. Of the rest:

- **step 1 — done**, and the module is synthetic rather than a wrapper: it wraps no module at all
  and reaches the card only through the portal;
- **step 3 — done.** A GnuTLS mutual-TLS client handshake completed against a server that required
  and verified the client certificate. `tools/module-smoke.sh` phase 3;
- **step 4 — NSS is done, 2026-09-06** (`tools/nss-smoke.sh`: `modutil`-registered, a private key,
  a user certificate, a `tstclnt` client-auth handshake); **the OpenSSL 3 provider is unrun**, and
  so is Firefox as a program rather than NSS as a library. That is now the largest open piece
  of S1;
- **step 5 — by construction rather than by test.** Every entry point in the hostile-client list
  answers `CKR_FUNCTION_NOT_SUPPORTED`, SO login answers `CKR_USER_TYPE_INVALID`, `CKF_RW_SESSION`
  answers `CKR_TOKEN_WRITE_PROTECTED`, a fabricated or stale handle answers
  `CKR_OBJECT_HANDLE_INVALID` because handles carry a grant generation, sensitive attributes answer
  `CKR_ATTRIBUTE_SENSITIVE`, and RSA-PSS parameters are validated before the call. The PKCS#11 v3
  table is implemented rather than absent, so `C_GetInterface` is not a different set of functions.
  `tests/test-module.c` covers the attribute and template halves; **the refusals themselves have
  unit coverage only through the function table, not a hostile driver**;
- **step 7 — no fuzzing has been done**, and the argument for why it is no longer the first thing
  that should be fuzzed is in [0011](decisions/0011-client-side-pkcs11-module.md): the module faces
  the process it lives in, not a wire.

---

## S2 — PIN and login ownership

**The question.** With a module involved, who prompts for the PIN and when? PKCS#11's login state
belongs to an application's sessions; the consumer's TLS stack opens **its own** sessions and makes
**its own** `C_Login` call. Pre-logging in on the service's session therefore buys nothing across
the boundary, and depending on the provider's device-wide caching behaviour is depending on
undocumented behaviour.

**Why it matters.** This is the difference between "the PIN never reaches the consumer" being a
design property and being a wish.

### Steps

1. Confirm the negative: log into the service's own session, then have a consumer connect through
   the facade and use the key. Does the consumer's stack call `C_Login`? What does it do if the
   facade returns `CKR_USER_ALREADY_LOGGED_IN`, `CKR_OK`, or `CKR_PIN_INCORRECT`?
2. Implement **lazy login**: the facade treats the consumer's `C_Login` as an
   **authorisation-state transition** carrying no real PIN, returns success, and the broker prompts
   and logs into its own underlying session on the **first `C_Sign` or `C_Decrypt`**. Determine
   which return codes GnuTLS, NSS and OpenSSL's provider actually require at each step, and whether
   any of them refuses to proceed without a `CKF_LOGIN_REQUIRED` flag or a specific token state.
3. Determine what a consumer does when the PIN prompt takes 30 seconds because the user is looking
   for their glasses. Timeouts, retries, and whether any stack gives up and retries the whole
   handshake — which would double-prompt.
4. **Protected authentication path.** With a PIN-pad reader, confirm
   `CKF_PROTECTED_AUTHENTICATION_PATH` is visible through the facade, that the underlying login uses
   a null PIN, and that an instructional dialog with **no editable PIN field** is the correct UI.
   Confirm no stack tries to synthesise a PIN.
5. **Wrong PIN and final retry.** Confirm the token reports remaining attempts, that the service can
   tell incorrect from blocked from device error, and that no automatic retry can spend an attempt.
   Publication gate. Use a card you are willing to block.
6. Confirm `C_Logout` at grant end, and **measure** whether the card or middleware still permits a
   signature afterwards — the honest answer for [SECURITY.md](SECURITY.md).

**Pass** = lazy login works across at least GnuTLS, with documented behaviour for NSS and OpenSSL.
**Fail** = the consumer must supply a PIN, which means the design's central claim is false and the
facade should not ship.

---

## S3 — WebKitGTK client-certificate handshake (joint with `xdg-desktop-portal-webauth`)

**The question.** Can WebKitGTK, driven by `xdg-desktop-portal-webauth`, complete a real client-certificate
handshake using a credential this service produced? **This is the weakest link in the design.**

**Why it matters.** It is the first consumer and the reason the project exists. It is also the case
where every hard problem lands at once: dynamic module registration, GLib's API surface, and
WebKit's multi-process architecture.

**What is already known, and what is not.** The two *ends* of the chain are documented and real:
[`g_tls_certificate_new_from_pkcs11_uris()`](https://docs.gtk.org/gio/ctor.TlsCertificate.new_from_pkcs11_uris.html)
takes a certificate URI and a private-key URI, deferring key access until use; and
`webkit_credential_new_for_certificate()` accepts the resulting `GTlsCertificate`. **The middle is
not proven.** A PKCS#11 URI cannot name a socket. GLib's constructor has **no module parameter**.
The p11-kit remote path expects `p11-kit-client.so` plus `P11_KIT_SERVER_ADDRESS` plus module
registration in p11-kit configuration — process-level state, poorly matched to per-request grants.
And WebKit's TLS may happen in the **network process**, which may have started before the endpoint
existed and may not see an environment variable or a module registered afterwards.

### Steps

1. Start WebKitGTK with a **clean, ephemeral p11-kit configuration**, so nothing is inherited.
2. Obtain a new endpoint **after** the WebKit web and network processes exist.
3. Construct the `GTlsCertificate` from the returned URIs.
4. Answer a **real client-certificate challenge** and complete a mutual-TLS handshake. Publication
   gate #2.
5. Repeat with a **second concurrent endpoint and certificate** in the same process.
6. Remove the card **mid-handshake**.
7. Close the **owner's D-Bus connection** mid-handshake and observe what the network subprocess does.
8. **Determine which process opens the Unix socket, and when.** This single observation decides the
   architecture.
9. Repeat on the **oldest and newest supported** GLib, WebKitGTK and GnuTLS versions in the target
   distro matrix.

**If dynamic introduction fails**, the workarounds, in order of plausibility:

1. **One permanently registered broker module**, installed into p11-kit configuration, exposing
   **synthetic grant-bound slots**, with `OpenPkcs11Endpoint` returning a URI that module resolves
   rather than a new module. **This is the most plausible outcome and would change the architecture**
   from "return a module" to "return a capability an already-loaded module can resolve" — with the
   security consequence noted in [SECURITY.md](SECURITY.md): grant binding then has to be enforced
   inside a module shared by every consumer in the process.
2. A dedicated WebKit network process or environment per authentication session.
3. Integrating the broker into glib-networking or GnuTLS directly.
4. `xdg-desktop-portal-webauth` keeps its in-process PKCS#11 implementation and this project serves
   other consumers first.

**Pass** = one real WebKitGTK client-certificate handshake, on at least one distro version.
**Fail** = do not publish this repository as a dependency of anything; keep it as an experiment.

### What was actually run, 2026-09-04

Steps 1, 3 and 4 are done, and step 8 is answered by not arising. `tests/gtls-client.c` builds a
`GTlsCertificate` with `g_tls_certificate_new_from_pkcs11_uris()` and completes a TLS 1.3
mutual-TLS handshake; the module is found through an ephemeral p11-kit configuration under
`XDG_CONFIG_HOME`, so nothing is installed system wide and nothing is inherited. No Unix socket is
opened by anyone, because there is no endpoint: the module is in the process that needs it, and any
process that loads p11-kit loads it, whenever it starts.

**Steps 2, 5, 6, 7 and 9 are unrun**, and WebKitGTK itself has not been started. What has been
proved is that the API WebKit reaches works; what has not is WebKit's process model around it.
Two findings that a browser will meet immediately:

- **the URI must name an object.** GnuTLS's single-object import refuses
  `pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate;type=cert`
  and wants `object=` or `id=`. Enumeration
  (`p11tool --list-all`, `gnutls_pkcs11_obj_list_import_url4`) accepts the token-only URI; the
  single-object path does not. `CKA_LABEL` is a constant so that an application can write the URI
  down in advance;
- **one grant per process, and it must outlive the PKCS#11 sessions**, or a stack that opens a
  session per operation prompts per operation.

---

## S4 — Removal, reinsertion, and multiple readers

**The question.** What actually happens to sessions, objects, in-flight operations and grants when
the card leaves — and how much of the answer is specific to a card, a reader or a middleware
version?

**Why it matters.** Removal mid-operation is not an edge case; it is Tuesday. It is also where the
"poison the endpoint, never rebind" rule either holds or turns out to be unimplementable.

### Steps

1. Remove the card **during** a `C_Sign`. Record what OpenSC returns, what p11-kit returns, what the
   facade must return, and how long it takes to notice. Publication gate.
2. Remove between `C_SignInit` and `C_Sign`. Remove between grant and first use. Remove during the
   PIN prompt.
3. Reinsert **the same card**. Confirm the poisoned endpoint does **not** rebind and that the old
   grant stays dead.
4. Reinsert a **different card with the same label** in the same slot. Confirm it is treated as a
   different token. This is the test that proves label-and-slot identity is insufficient.
5. **Two readers, two cards.** Confirm discovery attributes distinguish them, that `token_label`
   filtering picks the right one, and that a grant follows the token rather than the slot.
6. Unplug the **reader** rather than the card. Unplug it while `pcscd` has an open handle. Restart
   `pcscd` under a live grant.
7. Confirm `TokenAdded`/`TokenRemoved` fire correctly and are not chattier than a consumer can cope
   with — a reader that reports insert/remove repeatedly must not produce a signal storm.
8. Re-verify the discovery edge cases the Remmina work found on hardware: p11-kit trust tokens
   skipped without a subprocess; an empty token that reports failure treated as empty rather than
   fatal; a token-listing failure still fatal; loading a certificate taking seconds without blocking
   the UI. These are the acceptance criteria for replacing the `p11tool` subprocess with the p11-kit
   API.

**Pass** = a documented, card-independent lifetime model, with the card-specific parts identified as
such. **Fail** = the lifetime model in [PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md#lifetime) needs rewriting before
anything is built on it.

---

## S5 — The frontend/backend boundary

**Largely answered, by the branch's own tests — which are still this author's.** The frontend is
an xdg-desktop-portal branch with a python-dbusmock backend and 40 passing pytest cases, which
cover steps 2, 4 and part of 6
below against a mock. What is left is the fd relay (blocked: no `OpenPkcs11Endpoint`), and running
the same cases against a backend that talks to real hardware rather than a mock. The steps are kept
because "a mock passed" is not "a card passed".

**The question.** Does the split behave the way [0008](decisions/0008-build-to-the-upstream-shape.md)
assumes, after contact with a running system and a real card?

### Steps

1. **fd relay.** As S1 step 9: the facade socket created in the backend, returned over the impl
   interface, relayed by the frontend, used by the application. No copy retained, no leak, closure
   observed. **Blocked**: there is no method that returns one.
2. **Prompt cancellation across two hops.** `Request.Close()` on the frontend's object must close
   the backend's window *before* the application is told anything. Measure the gap. A user who
   cancels and sees the PIN dialog linger has been shown that the dialog is not in charge.
3. **A backend that dies mid-grant.** Kill it during a prompt, during a `Sign`, and while a facade
   endpoint is open. Confirm every grant is invalidated with `backend_gone`, that no application is
   left holding a session handle to nothing, and that the facade helper is reaped.
4. **A backend that lies.** A test backend that returns mechanisms outside the allow-list,
   `permitted_operations` the purpose forbids, and a `remember_selection` the caller never asked
   for. **Every one must be clamped by the frontend and logged**, not honoured. *(Done on the
   branch: `test_grant_is_bounded_by_the_request`. Note `expires_at` is not in the list any more — it is
   frontend-generated and a backend has no way to send one.)*
5. **A caller that tries to reach the impl interface directly**, sandboxed and unsandboxed. Confirm
   the sender check refuses it, and record honestly what an unsandboxed process on an unhardened
   desktop can still do.
6. **Backend selection.** Two `.portal` files, `portals.conf` preferring each in turn, one naming a
   backend that is not installed, and one naming `none`. Confirm the documented order and that a
   missing backend is handled cleanly. *(Note what the frontend actually does when no backend is
   configured: it logs nothing and simply does not export the public interface, so an application
   sees "no such interface" rather than an error.)* `tools/dev-stack.sh` is the harness for this.
7. **Round-trip cost.** Measure `Sign` end to end, with and without a prompt, against a
   single-process build of the same code. This is the number that decides whether the
   `Request`-shaped `Sign` needs a non-interactive fast path — see
   [UPSTREAMING.md](UPSTREAMING.md), open items.

**Pass** = the relay is clean, cancellation is prompt, a dying backend is survivable and loud, a
lying backend cannot widen a grant, and the round-trip cost is tolerable. **Fail** = either the
boundary needs a redesign before anything is built on it, or the round trip is too expensive and the
interface needs a fast path — both of which are much cheaper to learn now than after acceptance.

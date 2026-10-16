# Feasibility checks

S1, S2 and S3 have evidence for the experimental client-side PKCS#11 module defined by
[ADR 0011](decisions/0011-client-side-pkcs11-module.md). A served facade remains unimplemented;
neither interface exposes `OpenPkcs11Endpoint`. The frontend belongs to the xdg-desktop-portal
fork's `experimental/integration` branch
([ADR 0010](decisions/0010-backend-only-frontend-lives-upstream.md)).

[ROADMAP.md](ROADMAP.md) budgets 2–4 weeks for focused feasibility experiments.

| Check | Criterion | Evidence and remaining work |
|---|---|---|
| S1 | TLS stacks consume the synthetic PKCS#11 module | GnuTLS, NSS and Firefox have evidence; OpenSSL 3 provider and concurrent grants remain unrun |
| S2 | Backend-owned PIN prompting and login | Backend lazy login and module protected-authentication flag work; real retry counters and PIN-pad readers need checks |
| S3 | WebKitGTK completes a client-certificate handshake | GLib constructor and WebKitGTK have evidence; removal, concurrency and distribution matrix remain open |
| S4 | Grant behavior under removal, reinsertion and multiple readers | Identity and polling implemented; hardware removal tests unrun |
| S5 | Frontend/backend lifecycle preserves scope and cancellation | Mock frontend tests and private-bus runs cover part of it; hardware failures and latency need measurement; fd tests require an endpoint API |

## Recorded evidence

On 2026-09-04, `tools/module-smoke.sh` ran against SoftHSM on a private bus under Xvfb:
GnuTLS enumerated the certificate and both keys with `p11tool --list-all`;
`pkcs11-tool --sign --mechanism SHA256-RSA-PKCS` produced a signature verified by
`openssl dgst`; a GLib client using `g_tls_certificate_new_from_pkcs11_uris()` completed
TLS 1.3 client authentication against a server requiring and verifying the certificate.
The module also passed the handshake under AddressSanitizer.

On 2026-09-06, `tools/nss-smoke.sh` loaded the module with `modutil`, found a private key,
listed a user certificate and completed `tstclnt` TLS 1.3 client authentication, including
an AddressSanitizer run. NSS attaches `CKA_TOKEN` to searches and authenticates before listing
a token with `CKF_LOGIN_REQUIRED`; the module ignores the persistent-token intent modifier
and clears that flag. [ADR 0011](decisions/0011-client-side-pkcs11-module.md) records the details.
Firefox itself has evidence from 2026-09-06 ([TESTING.md](TESTING.md) §2.6).

WebKitGTK ran through the web-auth backend's `tools/portal-stack.sh` on 2026-09-04/05,
including a live Entra ID sign-in on 2026-09-05 ([TESTING.md](TESTING.md) §2.55).
Hardware tiers 3.1–3.4 have evidence from one PIV card/reader on 2026-09-04: discovery,
private-bus signing, cancellation and a live session-bus run. The card remained inserted
throughout; removal during signing has no hardware result.

The private-bus stack completes `CreateSession`, `AcquireCredential`, `Sign` and `Close`
with a real frontend/backend. A backend crash surfaces as "Backend call failed"; the test
record includes a chooser use-after-free discovered that way. Frontend pytest tests use a
python-dbusmock backend for policy and lifecycle. The DER corpus replay and optional libFuzzer
build exist; no sustained fuzzing result is recorded here.

## S1: object and operation scoping

[PKCS#11 forwarding constraints](ARCHITECTURE.md#pkcs11-forwarding-constraints) require the
client module to expose synthetic objects and reach hardware through portal grants.

Acceptance for the module requires a real GnuTLS handshake, NSS coverage, unsupported-operation
refusals and safe handle/attribute behavior. GnuTLS phase 3 and NSS/Firefox have dated results
above. Remaining work includes the
[OpenSSL 3 pkcs11 provider](https://github.com/latchset/pkcs11-provider), concurrent credentials
and a hostile external driver. Unit tests exercise attribute/template rules, sensitive attributes
and some invalid RSA-PSS lengths. The module implements refusals for unsupported calls, SO login,
read-write sessions and fabricated/stale handles; v3 tables expose the same set as the v2 list.
The registered suites in [test-module.c](../tests/test-module.c) and
[test-module-portal.c](../tests/test-module-portal.c) do not exercise SO login, read-write session
rejection or the listed unsupported function-table calls. Those refusal tests remain missing.

A served facade needs the [scoping rules](SECURITY.md#grant-scoping), including one synthetic
slot/token, granted certificate/key and broker-mapped handles, plus:

- A usable `p11_kit_remote_serve_module()`
  [entry point](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/remote.h)
  behind `P11_KIT_FUTURE_UNSTABLE_API`, with distribution availability checked [[S10](SOURCES.md)].
- A GnuTLS handshake through `p11-kit-client.so`, then NSS and OpenSSL-provider checks.
- A hostile client exercising every [facade restriction](SECURITY.md#grant-scoping), including
  broad templates and mismatched PSS parameters.
- Concurrent grants/endpoints in one consumer; evaluate static `P11_KIT_SERVER_ADDRESS`
  limitations versus multiple modules or grant-aware slots.
- RPC fuzzing and Flatpak fd reach/configuration tests.
- Backend-to-frontend-to-client fd relay without retained references or leaks, and observable closure.

These fd/RPC checks do not apply to the client module's transport. Failure to establish scoping
would limit a served design to brokered operations; it must not ship a weakened endpoint.

## S2: PIN and login ownership

GnuTLS can call `C_Login(CKU_USER, NULL, 0)` under the module's
[protected-path contract](SECURITY.md#client-side-pkcs11-module). Application-side sessions can
open and close per import or signature, so a grant must outlive them.

Record GnuTLS, NSS and OpenSSL-provider behavior for `CKR_USER_ALREADY_LOGGED_IN`, `CKR_OK`
and `CKR_PIN_INCORRECT`, token flags and delayed prompts. Check a 30-second user delay for
stack timeout, handshake retries and duplicate prompts. Real hardware must establish protected
path behavior without an editable field, wrong-PIN/blocked/device distinctions, final-attempt
confirmation and the absence of automatic retries. Use a test card you can unblock for those checks.
Measure whether a signature remains possible after grant-end `C_Logout`, since middleware and
cards can cache authentication. [SECURITY.md](SECURITY.md) records the limit of that guarantee.
A design requiring the consumer to collect the real PIN fails this gate.

## S3: WebKitGTK client-certificate handshake

[`g_tls_certificate_new_from_pkcs11_uris()`](https://docs.gtk.org/gio/ctor.TlsCertificate.new_from_pkcs11_uris.html)
accepts certificate/key URIs and defers private-key use. `webkit_credential_new_for_certificate()`
accepts the resulting `GTlsCertificate`. Module registration is process-level; the constructor
has no module argument and a URI cannot name a socket. WebKit's network process resolves the
private-key URI independently.

The 2026-09-04 run used `tests/gtls-client.c` with an ephemeral p11-kit directory under
`XDG_CONFIG_HOME`, no system installation, and a TLS 1.3 server verifying the client.
The module is available in whichever process loads that configuration; no endpoint socket is
needed. WebKitGTK itself met the handshake criterion on 2026-09-04/05.

GnuTLS single-object import requires `object=` or `id=`. A token-only URI works for enumeration
but cannot construct a certificate. The contract's constant `CKA_LABEL` lets applications name
an object before selection. One grant per process must outlive PKCS#11 sessions. WebKit's UI
and network processes therefore acquire independently; sharing ownership needs a frontend design.

Remaining checks are concurrent credentials, card removal mid-handshake, owner disconnect while
the network process is active, and oldest/newest supported GLib, WebKitGTK and GnuTLS versions.
A dynamic endpoint design would also need late introduction after browser subprocess startup,
URI resolution and socket-owner tracing. Possible alternatives are a permanently registered
broker with grant-aware slots, dedicated network-process environments, or direct glib-networking/
GnuTLS integration. Retaining a separate consumer implementation would require its own design;
the web-auth backend used this module exclusively until its development stopped.

## S4: removal, reinsertion and multiple readers

[Removal handling](SECURITY.md#card-removal-and-grants) uses identity re-resolution and polling.
The poll and debounce intervals have no hardware-based calibration.
See [lifetime](PUBLIC-INTERFACE.md#lifetime).

Hardware checks must record OpenSC/module results, UI behavior and detection latency for removal
inside `C_Sign`, between `C_SignInit` and `C_Sign`, between grant and first use, and during PIN
entry. After a detected removal, same-card reinsertion must require consent. A different card
with the same label in the same slot must fail identity binding. Polling can miss an intervening
removal, so record that case separately.

Test two readers/cards and `token_label` filtering, reader unplug during a pcscd handle, and
pcscd restart under a grant. Check debounced internal presence events and `SessionInvalidated`;
there are no public `TokenAdded`/`TokenRemoved` signals. A served endpoint would also need
poisoning rather than rebinding.

Recheck hardware-derived discovery requirements: skip p11-kit trust tokens, distinguish an empty
result from token-listing failure, and keep slow certificate loading off the UI thread. A result
must separate card-independent lifetime guarantees from middleware-specific behavior.

## S5: frontend/backend boundary

Frontend pytest tests cover cancellation, result clamping and backend selection against a mock;
this repository's `impl-dbus` suite tests the other direction. Hardware cases remain necessary
([ADR 0008](decisions/0008-build-to-the-upstream-shape.md)).

Check frontend `Request.Close()` closes the backend window promptly and measure the gap. Kill
the backend during prompting, signing and any future live endpoint; expect `backend_gone`,
closed grants and reaped helpers. Return mechanisms/operations beyond policy and ensure they
are intersected; the frontend test `test_grant_is_bounded_by_the_request` covers this. Unknown
selection-memory results must not create authorization; expiry is frontend-generated.

Try direct impl calls from sandboxed and host peers, including both `Close()` methods, and
record same-UID limitations. Test two `.portal` files with each preferred, a missing backend,
and `none`. Without a configured backend the frontend does not export the public interface;
clients see no such interface. `tools/dev-stack.sh` is the harness.

Measure end-to-end `Sign` with and without prompting and compare with a single-process baseline.
That result determines whether a non-interactive fast path is needed
([UPSTREAMING.md](UPSTREAMING.md)). A future endpoint also needs the two-hop fd checks in S1.

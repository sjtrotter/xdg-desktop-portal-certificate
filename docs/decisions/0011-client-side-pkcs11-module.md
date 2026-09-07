# 11. A client-side PKCS#11 module, in the application's process

Date: 2026-09-04
Status: accepted, implemented — this decision **supersedes the compatibility half** of
[0007](0007-brokered-operations-are-the-core.md) and answers
[SPIKES.md](../SPIKES.md) S1 and S3

## Context

[0006](0006-failure-modes-of-naive-p11kit-forwarding.md) killed token-scoped forwarding.
[0007](0007-brokered-operations-are-the-core.md) made brokered `Sign` the contract and left a
PKCS#11 **facade** as the compatibility path: a `CK_FUNCTION_LIST` served over a socket, an
`OpenPkcs11Endpoint` returning a file descriptor, a helper process, 5–9 person-weeks, and a
fuzzing target. None of it was reachable, because the frontend branch deliberately left
`OpenPkcs11Endpoint` off both interfaces.

Meanwhile the consumers that make the project worth doing cannot call the D-Bus API at all.
WebKitGTK's network process reaches TLS through glib-networking and
`g_tls_certificate_new_from_pkcs11_uris()` [[S20](../SOURCES.md), [S21](../SOURCES.md),
[S22](../SOURCES.md)]. Firefox and Thunderbird reach it through NSS.
LibreOffice reaches it through NSS. Every one of them wants a `CK_FUNCTION_LIST`, and every one of
them already loads whatever p11-kit has configured.

S3 had already written down the shape of the answer, as the *workaround* it expected to need:
"one permanently registered broker module, installed into p11-kit configuration, exposing
synthetic grant-bound slots". The only thing wrong with that sentence was where it put the module.

## Decision

**Ship a PKCS#11 module that runs in the APPLICATION's process, is registered with p11-kit at
install time, and forwards every operation to the PUBLIC portal interface over D-Bus.**

`src/module/` → `libpkcs11-portal-certificate.so`, plus `xdg-desktop-portal-certificate.module` in p11-kit's
module directory. It presents one slot, one token (`Portal Certificate`), and — once the user has
chosen one — one certificate, its public key and its private key. `C_Sign` becomes
`org.freedesktop.portal.experimental.Certificate.Sign`. `C_Decrypt` becomes `Decrypt`.

### Why this is not the facade under a different name

The facade was a server. This is a client.

| | Facade (0007, deferred) | This module |
|---|---|---|
| Where it runs | its own helper process, beside the backend | inside the application |
| What it speaks to the consumer | PKCS#11 over p11-kit's RPC socket | PKCS#11, in process |
| What it speaks outwards | the card, through the backend's session | the **public** portal D-Bus interface |
| New interface method | `OpenPkcs11Endpoint`, fd-returning, unreviewed | **none** |
| Reachable from a Flatpak | needs an fd relayed through two services | yes: the portal bus name is already allowed |
| Who the frontend thinks is calling | the backend's peer, relayed | **the application itself**, derived the ordinary way |
| Hostile peer | a wire protocol from an untrusted process | the application's own calls, in the application's own address space |
| Cost | 5–9 person-weeks, its own fuzzing target | one library, one D-Bus client, one fuzzing target |

The last two rows are the argument. **The facade had to defend a boundary; this module is on the
application's side of one.** A compromised application that abuses this module can call `Sign` as
itself — which it could already do by calling the D-Bus interface directly. It gains nothing.

### The module's threat model, which is smaller but not empty

An earlier draft of this decision said the code that used to need a threat model needs a test suite
instead. That was wrong, and three independent reviews said so in the same words: *"already
compromised application gains nothing" ignores "previously uncompromised application acquires this
code"*. A consumer that loads this module gains a DER parser, a D-Bus client, a worker thread and
an attribute protocol **inside its own address space**, next to its own secrets and its own
authority. The threat model is smaller than the facade's. It is not absent.

What it has to answer:

1. **The portal's reply is the hostile input, and it is only trusted-ish.** `certificate_der`,
   `chain_der`, `key_type`, `key_curve` and `supported_mechanisms` arrive over D-Bus from
   `org.freedesktop.portal.Desktop` and are parsed in the consumer's process by `objects.c` and
   `der.c`. The frontend is a trusted service and the bus authenticates it, but "trusted" is a
   statement about intent, not about the bytes: the certificate DER came off a card, through a
   backend, through a frontend, and none of them promise it is well formed. **This code must parse
   defensively regardless of who sent it**, because the alternative is that a malformed
   certificate on a card — or a compromised backend, or a portal implementation with a bug —
   becomes memory corruption in a browser.
2. **Certificate operations are reachable from the network.** A TLS server chooses when to ask for
   a client certificate, chooses the acceptable issuers and chooses the mechanism and parameters of
   the `CertificateVerify`. Those choices reach `mechanism.c` and `portal_digestinfo_parse()`
   through GnuTLS or NSS with no user in between. A remote peer therefore drives this parser
   several times per handshake and can retry.
3. **What an attacker with control of the portal reply could do.** Nothing to the card and nothing
   to the PIN: neither is on this side. What is in reach is the consumer's process — a
   heap overflow in the SPKI split, a length confusion in the attribute protocol, a read past the
   end of a `GBytes`. The value at risk is the browser's, not the portal's. That is the whole point
   of writing this down: the asset this module can damage does not belong to the project that
   ships it.
4. **Lifecycle in somebody else's process.** `C_Initialize` may be called after `fork()`;
   `C_Finalize` may be called while another thread is in a call; the library may be `dlclose()`d.
   The module claims no fork safety (`CKF_OS_LOCKING_OK` handling in `module.c`), and the claim is
   honest rather than a defence. A consumer that forks after initialising gets a worker thread that
   does not exist in the child, which is a hang and not a compromise — but it is a defect this
   module owns, not one the portal boundary absorbs.

What answers it, and what does not:

- **`tests/fuzz-der.c`** drives the TLV reader, the DigestInfo parser, `portal_objects_new()` on an
  arbitrary certificate DER, and the attribute protocol (`portal_object_matches`,
  `portal_objects_find`, `portal_object_get_attributes`, `portal_template_wants_credential`,
  `portal_template_fingerprint`) with hostile templates. It builds as a libFuzzer target when clang
  is available, and always builds as a corpus replay binary that `meson test` runs under ASan/UBSan.
- **Opt-in loading** (below) keeps the code out of processes that never asked for it, which is the
  cheapest reduction in exposure available and the one this decision should have started with.
- **What does not answer it:** the argument that the module is not a trust boundary. That argument
  is about the *portal's* assets and it is still correct. It says nothing about the consumer's.

**The identity story gets better, not worse.** The facade would have been called by an application
whose identity the frontend could not see; the frontend would have derived the *backend's* peer.
Here the frontend derives the identity of the process the module is loaded into, which is the
application, by the ordinary `xdp_invocation_get_app_info()` route. The chooser names the right
application because it is the one that called.

### What this does NOT solve

- **The application process holds a PKCS#11 handle to a synthetic token.** It holds no key, no PIN
  and no card. `CKA_VALUE` on the private key answers `CKR_ATTRIBUTE_SENSITIVE`; there is nothing
  behind it to leak. That attribute is this module's own, on its own synthetic object — PKCS#11
  defines no `CKA_VALUE` for an RSA private key [[S15](../SOURCES.md)].
- **The module is not a trust boundary. The portal is.** Everything the module refuses, the portal
  refuses again on the other side of D-Bus. The refusals here are for the sake of consumers that
  would otherwise misbehave, not for the sake of a boundary. Anyone hardening this file should
  harden `desktop-portal/certificate.c` and `src/broker/` instead.
- **`purpose` is still not attested.** [0006](0006-failure-modes-of-naive-p11kit-forwarding.md)
  failure mode 10 is exactly where it was: a `C_Sign` cannot prove it came from a handshake, and
  neither can the `Sign` it turns into.
- **Rate limiting is still in neither half.**
- **It is one credential per process.** Two concurrent grants in one application is
  [0006](0006-failure-modes-of-naive-p11kit-forwarding.md) failure mode 8 again and is not solved;
  it is deferred, because no consumer has asked.
- **One handshake still loads the module twice; it no longer asks the user twice.** Measured with
  WebKitGTK: one TLS handshake resolves the URI **twice**, in two processes — the application's
  own, to build a `GTlsCertificate`, because `webkit_credential_new_for_certificate()` takes an
  object and not a URI [[S24](../SOURCES.md)]; and WebKit's network process, which owns the
  handshake and re-resolves the URI itself [[S22](../SOURCES.md)]. Two p11-kit module instances
  and two `AcquireCredential` calls, which for a long
  time meant **two choosers about three seconds apart asking the same question**, and one PIN
  prompt, because only the network process signs.

  Both of those stand inside the challenge and always did; what used to stand *outside* it was a
  third chooser, from the server-chain enumeration described under "A search has to name the
  credential" below, and that one is gone.

  Nothing in the module could fix the remaining two. A grant belongs to the D-Bus peer that
  acquired it, and that is the property the whole design rests on: the frontend identifies the
  process the module is loaded into, which is what makes the chooser name the right application.
  Sharing a grant between two processes means deciding what "the same application" is, which is an
  interface question and not a module one.

  **What was built, and then removed from the proposal: delegation down the process tree.** The
  frontend's `AcquireCredential` grew a `delegate_to_children` (`b`) option; a grant whose holder
  passed it answered a later `AcquireCredential` from a **descendant of the holder's process** as a
  derived grant, and the backend was told `delegated: true` with the certificate to bind and no
  window to show. It worked, and two independent reviews of the branch agreed it should not be
  proposed:

  - **it cannot work for a Flatpak caller at all.** `XdpAppInfo`'s pidfd for a Flatpak app is the
    *bwrap instance's*, identical for every process in the instance, so two peers inside one
    sandbox are never in a descendant relationship and the check never fires. The branch's tests
    passed only because the synthetic Flatpak app-info used by tests had been changed to store the
    caller's own pidfd — a fixture altered to make a feature look tested.
  - **ancestry alone crosses application boundaries.** A host process holding a delegable grant
    that runs `flatpak run com.other.App` produces a descendant, so an unrelated application would
    receive a derived credential with no prompt.
  - the pidfd argument for the walk was wrong as well: a pidfd holds the `struct pid`, not the
    numeric pid's reservation.

  It is archived on `experimental/certificate-webauthentication+delegation` and is not part of the
  first proposal. The user-visible consequence is **two choosers** for one WebKitGTK handshake. The
  candidate that would replace it, and which upstream would recognise, is a grant that belongs to
  the *app-info identity* rather than to the D-Bus peer: inside a Flatpak every process shares that
  identity, so the helper process would get the grant with no new mechanism at all. Host processes
  have no instance identity, so that fixes the sandboxed case and not the host one.

  **The other candidate, not taken: a WebKit API that accepts a PKCS#11 URI**, so the application
  process would never import the certificate and only the network process would ever load the
  module — one instance, one grant, no delegation needed. It is the better shape and it is not
  available: `webkit_credential_new_for_certificate()` takes a `GTlsCertificate`, there is no
  `_for_certificate_uri()` [[S24](../SOURCES.md)], and adding one is a WebKitGTK release cycle
  away from anything this project can test. It would fix only WebKit, where a per-app-instance
  grant would answer the same question for any consumer whose work spans a process tree. If such an
  API appears, this backend should use it: one process that needs the card is better than two that
  agree about it.

### Consequences for the login model

The token sets `CKF_PROTECTED_AUTHENTICATION_PATH` [[S12](../SOURCES.md)] and **does not set
`CKF_LOGIN_REQUIRED`**. The first is not a convenience: it is what stops a TLS stack asking the
user for a PIN it must never receive — WebKitGTK has a whole authentication scheme for exactly
that request [[S23](../SOURCES.md)]. With
it, GnuTLS and OpenSC call `C_Login(CKU_USER, NULL, 0)`, the module answers `CKR_OK` without doing
anything, and the portal's backend collects the PIN in its own window at the first `Sign`. That is
[SPIKES.md](../SPIKES.md) S2's "lazy login", now answered against a module rather than in theory.
Any PIN bytes an application does pass are ignored and never forwarded; there is nothing on this
side of the boundary for them to unlock.

**`CKF_LOGIN_REQUIRED` was set until 2026-09-06 and removing it is the second half of the NSS
fix.** It was a claim the module could not back: `C_Login` sets a flag nothing reads, and every
object and every operation is available without one, because the authentication that matters is the
card's and happens in the backend. NSS is the consumer that takes the claim literally.
`PK11_Authenticate()` does nothing at all when the token does not set the flag, and Firefox's
`FindClientCertificatesWithPrivateKeys()` calls it on every slot that is not "friendly" **before**
`PK11_ListCertsInSlot()` — a module loaded through the "Security Devices → Load" dialog is never
friendly, because "friendly" comes from a `Flags=friendly` in the NSS spec string that the dialog
does not write [[S59](../SOURCES.md)]. So the login came first, and NSS ran the application's
password callback to get it; a protected authentication path changes what that callback is expected
to *return*, not whether it is called. Firefox's callback dispatches `PK11_CheckUserPassword()` to a
background task and then puts up a **modal alert with an OK button** — "Please authenticate to the
security device" — and waits for the background task only after the alert is dismissed. The
module's `C_Login` had already answered `CKR_OK`; the dialog was waiting for a person, and while it
was up Firefox's main thread had not begun the certificate search, so the portal frontend saw no
request at all. One dialog before the chooser, saying nothing, for a login that does nothing.

Dropping the flag costs nothing measurable: `tools/module-smoke.sh` passes unchanged — GnuTLS's
`pkcs11_login()` returns early with "no login required" and the TLS 1.3 handshake still completes,
and `pkcs11-tool --login` still logs in and still asks for no PIN, because that is
`CKF_PROTECTED_AUTHENTICATION_PATH` and not this flag. `C_Login` and `C_Logout` keep working for
consumers that call them regardless, and `C_GetSessionInfo` keeps reporting
`CKS_RO_USER_FUNCTIONS` once one has. What is gone is only NSS's reason to demand a login before it
will look at the token.

### The rule that must not be broken

**This module must never be loaded by the portal frontend or by the certificate backend.** The
backend enumerates p11-kit's configured modules; loading this one would make it enumerate a token
whose enumeration is a call back into itself. Three fences, because
`pkcs11.conf(5)` says `disable-in` "is not a security feature" [[S5](../SOURCES.md)]:

1. `certificate_module_is_portal_module()` in `src/tokens/discovery.c`, applied to the configured
   modules and to an explicit `--module` path;
2. the module refuses to run in any process whose executable is named `xdg-desktop-portal` or
   `xdg-desktop-portal-certificate`;
3. the installed module file's `enable-in:` list, which names two consumers and neither of those
   two processes. This is the weakest of the three and always was — `pkcs11.conf(5)` says so — but
   an allowlist that cannot name them by accident is a better third fence than a denylist that has
   to remember to.

Fence 2 is **two exact executable names**, `xdg-desktop-portal` and
`xdg-desktop-portal-certificate`, and it was a prefix match on `xdg-desktop-portal` until the first
consumer arrived. That consumer is `xdg-desktop-portal-webauth`, a portal BACKEND — it enumerates
no tokens, owns no card, and calls the portal exactly as an application does, but it needs this
module loaded in its own process to build a certificate before WebKit will carry one to its network
process. The prefix rule refused it, and the only symptom was GnuTLS reporting that the object was
not available. **A backend named after the portal is not the portal**; only the two that would
recurse are on the list.

### The module is opt-in by name, and the shipped file is the allowlist

**The first version of this file enabled the module for every p11-kit consumer** and disabled it in
three processes. That is wrong for a component whose object search can raise a window: `curl`,
`ssh`, a mail fetcher or a background service that enumerates PKCS#11 objects at start-up would
have provoked a chooser nobody asked for and nobody is there to answer. The ten-second refusal
cache in `module.c` makes that survivable; it does not make it defensible.

The shipped file now carries an **`enable-in:` allowlist**:

```
enable-in: xdg-desktop-portal-webauth, WebKitNetworkProcess
```

p11-kit matches the **base name of `argv[0]`** [[S5](../SOURCES.md), [S6](../SOURCES.md)]. Those
two are the pair one mutual-TLS handshake needs: the web-authentication backend, which must
build a `GTlsCertificate` before WebKit will
carry one anywhere, and WebKitGTK's network process, which owns the handshake and resolves the URI
itself. `firefox, thunderbird` is in the file as a commented line with the NSS caveat attached.

**`disable-in:` is gone from the file, and must not come back.** `pkcs11.conf(5)` says "Do not
specify both enable-in and disable-in for the same module", and p11-kit's
`is_module_enabled_unlocked()` takes the `enable-in` branch and never reaches `disable-in` — so
with both set the denylist is dead weight that reads as though it were doing something
[[S5](../SOURCES.md), [S6](../SOURCES.md)]. The two portal processes are excluded because they
are not on the allowlist, and by the
two fences in code above.

Neither list is a security control. Both are ways to decide where a window may appear.

### A search has to name the credential before a window opens

The allowlist decides which *processes* load the module. It says nothing about which *searches*
inside those processes may put a chooser up, and that turned out to be the larger half.

The chooser appears at `C_FindObjectsInit`, because that is the first moment the module learns the
consumer wants a credential. The first version of that gate asked only whether the template named a
`CKA_CLASS` this token has — `CKO_CERTIFICATE`, `CKO_PUBLIC_KEY` or `CKO_PRIVATE_KEY` — which reads
as conservative and is not, because **certificate searches are not only about the client's
certificate**. GnuTLS verifying a *server's* chain calls `gnutls_pkcs11_get_raw_issuer()` and
`_gnutls_pkcs11_crt_is_known()`, and those issue `C_FindObjectsInit` for `CKO_CERTIFICATE` with
`CKA_SUBJECT`, `CKA_ISSUER` or a trust category, through p11-kit, at every handshake
[[S19](../SOURCES.md)]. How far that sweep reaches is a property of the GnuTLS build and the
trust-store configuration rather than a guarantee; on the machine this ran on it reached this
module. The live Entra run on 2026-09-05 measured the consequence: a chooser two seconds after
the sign-in window opened, before any client-certificate
challenge, for a certificate nothing had asked for.

**A search now acquires a credential only when it can mean nothing else.** The table is in
`portal_template_intent()` in `src/module/objects.c`:

| Template | Meaning | Acquires? |
|---|---|---|
| `CKA_LABEL == "Portal Certificate"` | the object label of the shared contract; what a PKCS#11 URI naming an object imports by | yes |
| a non-empty `CKA_ID` | a consumer that has one got it from us | yes |
| `CKA_CLASS == CKO_PRIVATE_KEY`, alone or with `CKA_SIGN`/`CKA_DECRYPT` | nothing on a server's chain is a private key | yes |
| `CKA_CLASS` alone (`CKO_CERTIFICATE`, `CKO_PUBLIC_KEY`), or an empty template | "list what is on this token" | only with the opt-in below |
| `CKA_ISSUER`, `CKA_SUBJECT`, `CKA_SERIAL_NUMBER`, `CKA_TRUSTED`, `CKA_CERTIFICATE_CATEGORY`, `CKA_TOKEN == CK_FALSE`, a `CKA_LABEL` that is not ours, `CKO_DATA`, a malformed `CKA_CLASS` | somebody else's certificate, or nothing this token has | **never** |

`CKA_TOKEN == CK_TRUE` is not in the table at all: it is **passed over**, exactly as `CKA_SIGN` and
`CKA_DECRYPT` are, and the rows are decided on what is left. It says the object is persistent, which
all three of this token's objects are, and it names nothing. Counting it was the whole of the
2026-09-06 NSS defect: NSS attaches it to every search it makes — `[CKA_TOKEN, CKA_CLASS]` for
`PK11_ListCertsInSlot()`, `[CKA_CLASS, CKA_TOKEN]` for `PK11_ListPrivKeysInSlot()` — so **both** of
those landed on the last row. The private-key search never reached the third row, and the
certificate search was never classified as enumeration, which left the opt-in below with nothing to
switch: Firefox saw an empty token *with* `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` set.
`CKA_TOKEN == CK_FALSE` asks for session objects, which this token never has, and stays on the
refusing side.

A search on the last row answers zero objects while there is no grant, and never asks for one. Once
a grant exists, ordinary attribute matching applies and every one of these sees the three objects
like any other search: the gate decides when a **window** may open, not what a token holds.

`PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` moves the fourth row onto the acquiring side, and only the
fourth row. NSS's `PK11_ListCertsInSlot()` is "every certificate on this token" and has no way to
name an object, so an NSS consumer needs it; nothing else does, and a process that sets it is asking
for choosers it would not otherwise get. **NSS's other two lookups do not need it** — the
private-key search names a credential by class, and `token:nickname`, which is how NSS names an
object on a token, arrives as a `CKA_LABEL` search — but Firefox's client-authentication path starts
from the certificate list, so for Firefox the opt-in is required. `tools/nss-smoke.sh` phase 2
asserts both sides of the switch.

The cost is that a consumer which enumerates and then imports by URI sees an empty token on the
first pass. That is the right trade: the enumeration is not what the user was asked about, and the
import is.

A deployment adds names by editing the installed file, or by dropping its own
`xdg-desktop-portal-certificate.module` into `~/.config/pkcs11/modules`, whose fields take
precedence over the system file of the same name — p11-kit merges the two, user first, rather
than replacing one with the other [[S7](../SOURCES.md)]. `tools/module-smoke.sh`,
`tools/ui-smoke.sh` and the web-auth repository's
`tools/portal-stack.sh` all write their own file into a private `XDG_CONFIG_HOME` and are
unaffected by what is shipped; `portal-stack.sh --live` writes the real per-user file with the same
`enable-in` line as above.

## Consequences

- `OpenPkcs11Endpoint` is not needed for the consumers it was designed for, and nothing in this
  repository is waiting for it any more. `src/export/facade.h` is a pointer to this file.
- S1 and S3 are answered — see [SPIKES.md](../SPIKES.md) — by a real GnuTLS mutual-TLS handshake
  through `g_tls_certificate_new_from_pkcs11_uris()`, which is the constructor WebKitGTK reaches,
  and since 2026-09-04 by **WebKitGTK itself**: `xdg-desktop-portal-webauth`'s
  `tools/portal-stack.sh` runs both portals on one private bus and signs in through this backend's
  chooser and PIN prompt, headless, with the card's common name in the server's log. The mechanism
  the handshake actually used is `RSA_PSS`, because TLS 1.3 asks for it — `module-smoke.sh`'s
  `pkcs11-tool` phase only ever exercised v1.5, and TLS 1.3 requires PSS for an RSA key
  [[S25](../SOURCES.md)]. **NSS is answered as of 2026-09-06** by `tools/nss-smoke.sh`: the module
  loaded the way Firefox loads it (`modutil -add -libfile`), `certutil -K` finding the private key,
  `certutil -L` listing it as a user certificate, and `tstclnt` completing a TLS 1.3 client-auth
  handshake with the card's common name in the server's log — headless, and again under
  AddressSanitizer. It cost two module fixes, both above: `CKA_TOKEN` and `CKF_LOGIN_REQUIRED`.
  **Firefox itself was confirmed on 2026-09-06** — see [TESTING.md](../TESTING.md) §2.6 — and the
  OpenSSL 3 provider is still untouched, so that much of S1 is still open.
- **The token's names are a contract with another repository.**
  `src/module/portal-token.h` is the same file as `xdg-desktop-portal-webauth`'s
  `backend/src/tls/portal-token.h` — **byte for byte, licence line included**, since that project
  relicensed to LGPL-2.1-or-later on 2026-09-04: label `Portal Certificate`, manufacturer
  `freedesktop.org`, model `portal-cert`, module configuration file
  `xdg-desktop-portal-certificate.module`, and the URIs built from those three. Changing a
  constant is changing an interface, and `cmp` between the two copies is the check.
- **`CKA_LABEL` is a constant, not the certificate's subject CN**, and that is a consequence of
  the consumer rather than a preference. GnuTLS's single-object import — the one behind
  `g_tls_certificate_new_from_pkcs11_uris()` — refuses a URI that names no object
  [[S17](../SOURCES.md)], so a consumer must be able to write `object=` down before anything has
  been chosen, and it cannot know a common name in advance. A token holding exactly one
  credential can be allowed to name it after
  itself. The certificate's real identity is in its DER.

  **The contract's URIs carry `object=`, and they did not at first.** Measured, not assumed:
  `pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate;type=cert`
  is refused by `gnutls_x509_crt_import_url()` and by
  `g_tls_certificate_new_from_pkcs11_uris()` — GnuTLS's `find_single_obj_cb()` wants `object=`
  (CKA_LABEL) or `id=`, and the import fails before any chooser appears; the same URI with
  `;object=Portal%20Certificate` succeeds and completes the handshake. Enumeration accepts either
  [[S17](../SOURCES.md), [S18](../SOURCES.md)]. The first version of the contract named only
  the token,
  which left every single-object consumer to append the attribute itself and got the web-auth
  backend exactly nowhere; `XDG_PORTAL_CERTIFICATE_CERT_URI` and `_KEY_URI` now carry it,
  `XDG_PORTAL_CERTIFICATE_TOKEN_URI` is the token-only form an enumerating consumer wants, and
  `PKCS11_PORTAL_URI_OBJECT_ATTRIBUTE` in `src/module/constants.h` is the attribute alone.
- **A grant outlives the PKCS#11 sessions.** GnuTLS opens and closes a session for each object
  import and each signature; releasing the grant with the last session put the chooser up again
  every time. The grant now ends at `C_Finalize`, at its own expiry, or when the portal
  invalidates it.
- **TLS 1.0 and 1.1 cannot work through this module and will not be made to.** They sign an
  MD5 ‖ SHA-1 concatenation with `CKM_RSA_PKCS` [[S26](../SOURCES.md)], which has no hash name the
  portal's `Sign` will accept and no DigestInfo to parse. It is refused with
  `CKR_MECHANISM_INVALID`. Both protocols
  are long dead.

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
`g_tls_certificate_new_from_pkcs11_uris()`. Firefox and Thunderbird reach it through NSS.
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
| Cost | 5–9 person-weeks, its own fuzzing target | one library, one D-Bus client |

The last two rows are the argument. **The facade had to defend a boundary; this module is on the
application's side of one.** A compromised application that abuses this module can call `Sign` as
itself — which it could already do by calling the D-Bus interface directly. It gains nothing. That
is why the code that used to need a threat model needs a test suite instead.

**The identity story gets better, not worse.** The facade would have been called by an application
whose identity the frontend could not see; the frontend would have derived the *backend's* peer.
Here the frontend derives the identity of the process the module is loaded into, which is the
application, by the ordinary `xdp_invocation_get_app_info()` route. The chooser names the right
application because it is the one that called.

### What this does NOT solve

- **The application process holds a PKCS#11 handle to a synthetic token.** It holds no key, no PIN
  and no card. `CKA_VALUE` on the private key answers `CKR_ATTRIBUTE_SENSITIVE`; there is nothing
  behind it to leak.
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
- **A grant cannot be shared between an application's own processes, and the first real consumer
  needs exactly that.** Measured with WebKitGTK: one TLS handshake resolves the URI **twice**, in
  two processes — the application's own, to build a `GTlsCertificate`, because
  `webkit_credential_new_for_certificate()` takes an object and not a URI; and WebKit's network
  process, which owns the handshake and re-resolves the URI itself. Two p11-kit module instances,
  two `AcquireCredential` calls, **two choosers about three seconds apart asking the same
  question**, and one PIN prompt, because only the network process signs.

  Nothing in the module can fix it. A grant belongs to the D-Bus peer that acquired it, and that
  is the property the whole design rests on: the frontend identifies the process the module is
  loaded into, which is what makes the chooser name the right application. Sharing a grant between
  two processes means deciding what "the same application" is, which is an interface question and
  not a module one. The two candidate answers, neither taken: a portal method that lets a caller
  hand a live grant to a named peer, or a WebKit API that takes a PKCS#11 URI so the application
  process never has to import anything. Recorded here so that whoever meets the two choosers knows
  it was measured and not missed.

### Consequences for the login model

The token sets `CKF_LOGIN_REQUIRED` **and** `CKF_PROTECTED_AUTHENTICATION_PATH`. The second is not
a convenience: it is what stops a TLS stack asking the user for a PIN it must never receive. With
it, GnuTLS and NSS call `C_Login(CKU_USER, NULL, 0)`, the module answers `CKR_OK` without doing
anything, and the portal's backend collects the PIN in its own window at the first `Sign`. That is
[SPIKES.md](../SPIKES.md) S2's "lazy login", now answered against a module rather than in theory.
Any PIN bytes an application does pass are ignored and never forwarded; there is nothing on this
side of the boundary for them to unlock.

### The rule that must not be broken

**This module must never be loaded by the portal frontend or by the certificate backend.** The
backend enumerates p11-kit's configured modules; loading this one would make it enumerate a token
whose enumeration is a call back into itself. Three fences, because
`pkcs11.conf(5)` says `disable-in` "is not a security feature":

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

p11-kit matches the **base name of `argv[0]`**. Those two are the pair one mutual-TLS handshake
needs: the web-authentication backend, which must build a `GTlsCertificate` before WebKit will
carry one anywhere, and WebKitGTK's network process, which owns the handshake and resolves the URI
itself. `firefox, thunderbird` is in the file as a commented line with the NSS caveat attached.

**`disable-in:` is gone from the file, and must not come back.** `pkcs11.conf(5)` says "Do not
specify both enable-in and disable-in for the same module", and p11-kit's
`is_module_enabled_unlocked()` returns out of the `enable-in` branch before it looks at
`disable-in` — so with both set the denylist is dead weight that reads as though it were doing
something. The two portal processes are excluded because they are not on the allowlist, and by the
two fences in code above.

Neither list is a security control. Both are ways to decide where a window may appear.

A deployment adds names by editing the installed file, or by dropping its own
`xdg-desktop-portal-certificate.module` into `~/.config/pkcs11/modules`, which overrides the
system one entirely. `tools/module-smoke.sh`, `tools/ui-smoke.sh` and the web-auth repository's
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
  `pkcs11-tool` phase only ever exercised v1.5. NSS and the OpenSSL 3 provider are not answered and
  remain S1's open half.
- **The token's names are a contract with another repository.**
  `src/module/portal-token.h` is the same file as `xdg-desktop-portal-webauth`'s
  `backend/src/tls/portal-token.h` — **byte for byte, licence line included**, since that project
  relicensed to LGPL-2.1-or-later on 2026-09-04: label `Portal Certificate`, manufacturer
  `freedesktop.org`, model `portal-cert`, module configuration file
  `xdg-desktop-portal-certificate.module`, and the URIs built from those three. Changing a
  constant is changing an interface, and `cmp` between the two copies is the check.
- **`CKA_LABEL` is a constant, not the certificate's subject CN**, and that is a consequence of
  the consumer rather than a preference. GnuTLS's single-object import — the one behind
  `g_tls_certificate_new_from_pkcs11_uris()` — refuses a URI that names no object, so a consumer
  must be able to write `object=` down before anything has been chosen, and it cannot know a
  common name in advance. A token holding exactly one credential can be allowed to name it after
  itself. The certificate's real identity is in its DER.

  **The contract's URIs carry `object=`, and they did not at first.** Measured, not assumed:
  `pkcs11:model=portal-cert;manufacturer=freedesktop.org;token=Portal%20Certificate;type=cert`
  is refused by `gnutls_x509_crt_import_url()` and by
  `g_tls_certificate_new_from_pkcs11_uris()` — GnuTLS's `find_single_obj_cb()` wants `object=`
  (CKA_LABEL) or `id=` and fails with `GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILABLE` before any
  chooser appears; the same URI with `;object=Portal%20Certificate` succeeds and completes the
  handshake. Enumeration accepts either. The first version of the contract named only the token,
  which left every single-object consumer to append the attribute itself and got the web-auth
  backend exactly nowhere; `XDG_PORTAL_CERTIFICATE_CERT_URI` and `_KEY_URI` now carry it,
  `XDG_PORTAL_CERTIFICATE_TOKEN_URI` is the token-only form an enumerating consumer wants, and
  `PKCS11_PORTAL_URI_OBJECT_ATTRIBUTE` in `src/module/constants.h` is the attribute alone.
- **A grant outlives the PKCS#11 sessions.** GnuTLS opens and closes a session for each object
  import and each signature; releasing the grant with the last session put the chooser up again
  every time. The grant now ends at `C_Finalize`, at its own expiry, or when the portal
  invalidates it.
- **TLS 1.0 and 1.1 cannot work through this module and will not be made to.** They sign an
  MD5 ‖ SHA-1 concatenation with `CKM_RSA_PKCS`, which has no hash name the portal's `Sign` will
  accept and no DigestInfo to parse. It is refused with `CKR_MECHANISM_INVALID`. Both protocols
  are long dead.

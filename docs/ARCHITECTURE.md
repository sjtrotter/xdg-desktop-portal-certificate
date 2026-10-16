# Architecture

The experimental backend and client-side PKCS#11 module are implemented. The
Certificate interface is defined on the xdg-desktop-portal fork's
[experimental/integration](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/integration)
branch and is not merged upstream. [SPIKES.md](SPIKES.md) records feasibility questions.
[ADR 0010](decisions/0010-backend-only-frontend-lives-upstream.md) assigns the frontend to
xdg-desktop-portal; [ADR 0008](decisions/0008-build-to-the-upstream-shape.md) records the split.

Applications acquire a credential and request brokered operations. They receive neither a
private key nor a PIN. Consumers can call D-Bus directly, use a D-Bus library, or load the
[client-side PKCS#11 module](decisions/0011-client-side-pkcs11-module.md). The module exposes
synthetic handles in the application's process and holds no card session.

<a id="who-does-what"></a>

## Responsibilities

| Concern | Frontend: xdg-desktop-portal | Backend: this repository |
|---|---|---|
| Caller identity | `xdp_invocation_get_app_info()` derives `app_id` and `app_identity_level` (`sandboxed`, `host`, `unidentified`) | Receives identity as arguments and displays it |
| Bus name | `org.freedesktop.portal.Desktop` | `org.freedesktop.impl.portal.desktop.certificate` |
| Interface | `org.freedesktop.portal.experimental.Certificate1` | `org.freedesktop.impl.portal.experimental.Certificate1` |
| Object path | `/org/freedesktop/portal/desktop`; Request and Session handles beneath `/request/` and `/session/` | `/org/freedesktop/portal/desktop` on its own bus name |
| Options and policy | Validates purpose, interaction mode, mechanism, reason length (256 characters) and data size (1 MiB); drops unknown top-level keys | Revalidates fields and applies device limits; never widens permissions |
| Grant lifetime | Default 300 s, ceiling 3600 s; forwards the decision as `lifetime` | Enforces the same monotonic deadline, with a delayed teardown backstop |
| Result limits | Intersects mechanisms and operations with its allowed sets before returning and recording the grant | Reports supported mechanisms and operations |
| Permissions | No selection memory on the Certificate interface | Never accesses the permission store |
| Ownership | Each grant belongs to one D-Bus peer; no process-tree delegation | Binds sessions to the supplied app id |
| Request lifecycle | Owns the public Request and its terminal `Response`; forwards cancellation | Exports an impl Request with `Close()` at the supplied path; returns results directly |
| Session lifecycle | Owns grant state; one acquisition per session, no renewal | Owns token session, login state and handles |
| Backend selection | `.portal` files and `portals.conf`, through `xdp-portal-config.c` | Declares `data/certificate.portal` |
| UI | No windows | Chooser and PIN interaction |
| Device access | No PKCS#11 loading or card serials | Discovery, certificate reading, `C_Login`, `C_Sign` and removal detection |
| PIN | No PIN field on either Certificate interface | Collects locally or through the system prompter and passes it to the token |
| Logging | Caller, identity level, purpose and decision | Token presence, mechanism and PIN outcome codes |

The frontend needs a configured backend and `Certificate1` in its startup
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` list. See
[PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md) for the export conditions and protocol.

Camera and USB have frontend-owned device access: a PipeWire remote or an opened device fd.
Certificate uses backend-owned device access, as ScreenCast and RemoteDesktop do. A PKCS#11
session includes login state and object handles and cannot be transferred as a device fd.

| Step | Frontend | Backend |
|---|---|---|
| `CreateSession` | Creates Request and Session; returns session handle in `Response` | Creates impl session |
| `AcquireCredential` | Identifies caller, validates options and selects backend | Discovers tokens, filters certificates and asks for consent |
| Successful acquisition | Records owner, expiry, mechanism and operation limits | Returns leaf DER, chain status, token display and key capabilities |
| `Sign` | Checks grant, owner, operation and mechanism | Validates digest and parameters; prompts for login at first use; calls `C_Sign` |
| `Session.Close` | Releases grant | Cancels interaction and releases token session |

## Deferred endpoint

`OpenPkcs11Endpoint` is absent from both interfaces. A served facade would require review
of fd transfer, a working endpoint test beyond python-dbusmock, and the
[facade requirements](SECURITY.md#grant-scoping). No current consumer depends on it:
WebKitGTK through glib-networking and NSS consumers use the client module.
[`src/export/facade.h`](../src/export/facade.h) points to that design.
[ADR 0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) records forwarding limits.

## PKCS#11 forwarding constraints

`p11-kit server` exposes tokens selected by token URI. It provides no supported object-scoping
guarantee and forwards creation, key generation, wrapping and derivation. Login state does not
transfer to a consumer's independently opened sessions. Device-wide authentication caching is
provider behavior and cannot define this API.

`p11-kit-client.so` resolves its endpoint from process-level configuration, including
`P11_KIT_SERVER_ADDRESS` and per-module `server-address:`. Static endpoints can be configured;
per-request grants do not fit that initialization model. A PKCS#11 URI cannot name a socket,
and `g_tls_certificate_new_from_pkcs11_uris()` has no module parameter.
[ADR 0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) lists the failure modes;
[ADR 0007](decisions/0007-brokered-operations-are-the-core.md) defines brokered operations.

### PC/SC, middleware and certificate access

Frank Morgner distinguishes the layers in
[xdg-desktop-portal#662, 2023-03-22](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1479992623)
[[S30](SOURCES.md)]: `vicc`/`vpcd` expose the token over PC/SC; `pkcs11-proxy` exposes
middleware over PKCS#11. `p11-kit server` and `p11-kit-client.so` also separate applications
from middleware. This portal exposes a higher-level capability: use of one certificate's
key, with specified mechanisms, operations and expiry.

### Transport and policy

The p11-kit
[RPC call table](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/rpc-message.h)
includes `C_InitToken` (line 61), `C_InitPIN` (66), `C_SetPIN` (67), `C_Login` (70) and
`C_LoginUser` (119). Its signatures include:

```text
line 178   { P11_RPC_CALL_C_InitToken,  "C_InitToken",  "uayz",  "" },
line 184   { P11_RPC_CALL_C_SetPIN,     "C_SetPIN",     "uayay", "" },
line 187   { P11_RPC_CALL_C_Login,      "C_Login",      "uuay",  "" },
```

`ay` carries a plain byte array, including PIN arguments. The server dispatches administrative
calls [[S4](SOURCES.md)]. Filtering requires a separate component. Daiki Ueno's 2023 design
uses wrappers inside and outside the sandbox for that purpose.

## Components

### Impl skeleton

[`certificate-impl.h`](../src/certificate-impl.h), [`request-impl.h`](../src/request-impl.h)
and [`session-impl.h`](../src/session-impl.h) define the backend objects. The backend owns
its bus name on the session bus and exports the desktop path [[S35](SOURCES.md)]. Impl
Requests return method results and have no `Response` signal; the public Request owns the
at-most-one-terminal-response rule.

The frontend's `xdp_request_dex_new()` needs a separate `xdp_request_dex_export()` call.
Shared request/session dependencies are in [UPSTREAMING.md](UPSTREAMING.md#frontend-dependencies).

### Token discovery

[`tokens/discovery.h`](../src/tokens/discovery.h) loads p11-kit managed modules,
enumerates asynchronously under a `GCancellable` and watches insertion and removal.
Discovery uses the p11-kit API directly.

The Remmina RDP plugin's
[PKCS#11 patches](https://gitlab.com/Remmina/Remmina), GPL-2.0-or-later, are prior art;
no code is copied [[S58](SOURCES.md)]. Its hardware-derived requirements cover:

- Cancellable, time-bounded discovery with bounded results and certificate loading off the UI thread.
- Skipping p11-kit trust tokens (`model=p11-kit-trust`), which hold no client keys [[S8](SOURCES.md)].
- Distinguishing empty-token results from token-list failures, signal death and output-limit failures.
- Resolving external tools at runtime when using a subprocess. The plugin uses fixed argv
  (`p11tool --list-certs --only-urls`); this backend uses managed modules.
- `g_tls_certificate_new_from_pkcs11_uris()` producing a usable `GTlsCertificate`
  ([GLib 2.68+](https://docs.gtk.org/gio/ctor.TlsCertificate.new_from_pkcs11_uris.html),
  [S20](SOURCES.md)); [SPIKES.md](SPIKES.md) S3 covers the WebKit path.
- A PIN response bounded to one challenge plus one engine-initiated retry in that plugin;
  this backend's attempt rules are in [SECURITY.md](SECURITY.md#pin-handling).
- Logging counts and reason codes without URIs, labels, serials or PINs.

### Certificate filtering

[`tokens/filter.h`](../src/tokens/filter.h) applies purpose and optional restrictions.

| Field | Meaning |
|---|---|
| `purpose` | `client_auth`: clientAuth (`1.3.6.1.5.5.7.3.2`) or smart-card logon; `signing`: signing-compatible EKUs including codeSigning (`1.3.6.1.5.5.7.3.3`); `email`: emailProtection (`1.3.6.1.5.5.7.3.4`); `ssh`: raw RSA/EC signing key |
| `eku` | Explicit OID list |
| `issuers` | DER issuer DNs, as in a TLS `CertificateRequest` |
| `key_usage` | Required X.509 key-usage bits |
| `key_algorithms` | Acceptable key types |
| `token_label` | One token label |
| `piv_slot` | `authentication` (9A), `signature` (9C), `key_management` (9D), `card_authentication` (9E) [[S45](SOURCES.md)] |

For EKU-constrained purposes, absent EKU and anyExtendedKeyUsage are unrestricted;
an explicit empty EKU grants none of those purposes.
`signing` also accepts clientAuth, emailProtection and smart-card logon, excluding serverAuth-only
credentials. Signing key usage accepts digitalSignature or contentCommitment; decryption accepts
keyEncipherment or dataEncipherment. Absent key usage is unrestricted. SSH ignores X.509 usage.

The frontend requires a supported purpose. Expired and not-yet-valid certificates remain
selectable and are marked. [IMPL-INTERFACE.md](IMPL-INTERFACE.md#interaction-and-consent) defines
chooser requirements; [grant lifetime](SECURITY.md#grant-lifetime-and-delegation) covers ownership.

### Chooser UI

[`ui/chooser.h`](../src/ui/chooser.h) defines the backend-owned window, parented to a valid
`parent_window` when available and unparented otherwise. Its contents follow the
[trusted-dialog requirements](SECURITY.md#trusted-dialog) and
[accessibility criteria](PUBLIC-INTERFACE.md#accessibility-criteria).

### PIN UI and broker

[`ui/pin.h`](../src/ui/pin.h) supplies PIN interaction at first private-key use.
The backend logs into its own session; protected-path tokens collect the secret on the token
or reader. PIN memory, retries, serialization, cancellation and system-prompter transport
are specified in [SECURITY.md](SECURITY.md#pin-handling).

[`broker/operations.h`](../src/broker/operations.h) owns device operations. The
[security checklist](SECURITY.md#missing-controls-and-evidence) records the consent gap.
The intended policy allows short client-auth grants, explicit mail-session
policy and a separate SSH policy; unattended or high-volume signing requires configured policy.
A cached card login cannot authorize another application or purpose.

Signing permits `RSA_PKCS1_V1_5`, `RSA_PSS` and `ECDSA`. The frontend intersects advertised
mechanisms in its own order; the backend checks parameters against the key, including RSA-PSS
hash, MGF and salt length. [Operation logs](SECURITY.md#logging) carry the session handle
and the optional `operation_id` supplied with Sign.

RSA-OAEP decryption code exists in the broker and client module but is unreachable through
D-Bus. No interface exposes `Decrypt`.

### Client-side PKCS#11 module

[`src/module/`](../src/module/) builds `libpkcs11-portal-certificate.so`, installed with
`xdg-desktop-portal-certificate.module`. p11-kit loads it into the application; it links no
backend code. NSS can also load the shared object directly.

The module exposes one slot and a token labelled `Portal Certificate` while the portal answers
`GetCapabilities`. With no portal or backend, it reports zero slots and `C_Initialize` succeeds.
Credential-intent searches trigger `C_FindObjectsInit` acquisition; trust and unrelated-class
searches do not. Cancelled/refused acquisitions with the same search fingerprint are cached for ten seconds. `CKA_TOKEN == CK_TRUE` is ignored when
classifying intent because all synthetic objects are persistent. Class-only enumeration needs
`PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1`; see [TESTING.md](TESTING.md).

The module sets `CKF_PROTECTED_AUTHENTICATION_PATH` and clears `CKF_LOGIN_REQUIRED`.
The first successful `C_Login(CKU_USER, ...)` returns `CKR_OK`; a repeated login returns
`CKR_USER_ALREADY_LOGGED_IN`. The module ignores PIN bytes; the backend collects the real
PIN at `Sign`. NSS authenticates before listing when `CKF_LOGIN_REQUIRED` is set; Firefox
then displays a modal alert.

`CKA_LABEL` is constant so applications can construct a single-object URI in advance.
GnuTLS requires `object=` or `id=` [[S17](SOURCES.md)]. The shared
[`portal-token.h`](../src/module/portal-token.h) contract includes
`;object=Portal%20Certificate` and is copied verbatim into the web-auth backend.

`CKM_RSA_PKCS` input is parsed as DigestInfo; `CKM_SHA*_` mechanisms hash locally.
`CKM_RSA_PKCS_PSS` maps parameters to `mgf` and `salt_length`. `CKM_ECDSA` infers the hash
from digest length and returns raw `r || s`. OAEP is the only implemented decryption mapping,
with no callable portal method. Unsupported mechanisms return `CKR_MECHANISM_INVALID`;
unsupported functions, including token writes, return `CKR_FUNCTION_NOT_SUPPORTED`.

Recursion is blocked by `certificate_module_is_portal_module()` in discovery, the module's
refusal to run in either portal executable, and an `enable-in:` allowlist naming neither.
That allowlist is not a security boundary [[S5](SOURCES.md)]. Portal-side validation remains
necessary; module input parsing also protects the consumer's process. See
[ADR 0011](decisions/0011-client-side-pkcs11-module.md) and [SECURITY.md](SECURITY.md).

### Grant registry

`desktop-portal/certificate.c` owns grant identity, peer binding, operation limits, expiry
and invalidation. The backend owns the associated token session. Frontend loss or replacement
cancels pending windows and closes sessions; backend loss invalidates grants with
`backend_gone`.

[IMPL-INTERFACE.md](IMPL-INTERFACE.md#invalidation-vocabulary) defines invalidation reasons.
Removal behavior and polling limitations are in
[SECURITY.md](SECURITY.md#card-removal-and-grants).
[Selection memory](SECURITY.md#selection-memory) requires a frontend design.

### Logging

[`redact.h`](../src/redact.h) defines the structured logging API.
[SECURITY.md](SECURITY.md#logging) specifies permitted fields, redaction and session and
operation ids for correlation.

## Process model

The backend is a per-user service activated through
`data/org.freedesktop.impl.portal.desktop.certificate.service`. It does not require root.
The implementation has no idle-exit timer; [ROADMAP.md](ROADMAP.md) records lifecycle work.
The frontend is the desktop's xdg-desktop-portal process. Applications use its public interface;
[IMPL-INTERFACE.md](IMPL-INTERFACE.md) describes sender checks and same-UID limitations.

GTK 4 supplies this backend's UI. A Qt/KDE implementation would be a separate backend
package with its own `.portal` file, selected by `portals.conf`. KDE support and equivalent
PIN integration remain unimplemented.

## Scope limits

The frontend branch owns the public XML; the impl XML here tracks it. The backend performs
no TLS handshakes, cipher selection or chain trust validation. `purpose` cannot attest what
signed data is used for. [Chain results](IMPL-INTERFACE.md#token-display-and-chain) remain incomplete.

Application progress and results UI, key generation, enrolment, PIN change or unblock,
certificate import, CA trust-store management and PIN caching are outside the interface.
The token or middleware may cache authentication independently. Hardware coverage is limited
to OpenSC-compatible PIV; pcscd, OpenSC and firmware failures remain dependencies' failures.

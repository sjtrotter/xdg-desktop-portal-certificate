# Implementation interface

`org.freedesktop.impl.portal.experimental.Certificate1` is the experimental, versioned
frontend-to-backend contract. It carries no stability promise for applications.
xdg-desktop-portal calls bus name `org.freedesktop.impl.portal.desktop.certificate`, object
path `/org/freedesktop/portal/desktop`. The frontend needs a configured backend and
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=Certificate1` at startup.

## XML ownership

[`data/org.freedesktop.impl.portal.experimental.Certificate1.xml`](../data/org.freedesktop.impl.portal.experimental.Certificate1.xml)
tracks that file on
[experimental/integration](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/integration),
apart from its provenance comment. Update the interface in the frontend branch and copy it here.
The declared interface must match `data/certificate.portal`.

Released backends normally read impl XML from xdg-desktop-portal's pkg-config interfaces
directory, as `xdg-desktop-portal-gtk/data/meson.build` does. This tracking copy is needed
until a release ships the interface. The public contract is in
[PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md), responsibilities in
[ARCHITECTURE.md](ARCHITECTURE.md#responsibilities), and proposal work in
[UPSTREAMING.md](UPSTREAMING.md).

## Portal conventions

Interactive methods receive frontend-selected paths and return `(u response, a{sv} results)`.
The backend exports `org.freedesktop.impl.portal.Request` at `handle` during an interaction;
it has `Close()` and no `Response` signal. The public Request sends the terminal response.
Compare [Usb.AcquireDevices](https://github.com/flatpak/xdg-desktop-portal/blob/main/data/org.freedesktop.impl.portal.Usb.xml).

Every impl call receives `app_id`; the backend never derives it from the bus peer or `/proc`,
which would identify the frontend. Long-lived state uses an
`org.freedesktop.impl.portal.Session` with `Close()` and `Closed` at the supplied path.
Backend registration uses `.portal` files and `portals.conf`:
[backend guide](https://flatpak.github.io/xdg-desktop-portal/docs/writing-a-new-backend.html),
[configuration reference](https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html).

## Methods

| Method | Signature and behavior |
|---|---|
| `CreateSession` | `(o handle, o session_handle, s app_id, a{sv} options) -> (u, a{sv})`; creates empty state without prompting. `options` is unused, successful results are empty. Token and display checks occur during acquisition. |
| `AcquireCredential` | `(o handle, o session_handle, s app_id, s parent_window, a{sv} options) -> (u, a{sv})`; discovers, filters and asks for consent. |
| `Sign` | `(o handle, o session_handle, s app_id, s parent_window, a{sv} options) -> (u, a{sv})`; signs and may prompt for login. |
| `GetCapabilities` | `(s app_id, a{sv} options) -> a{sv}`; reports supported capabilities without prompting. |
| `SessionInvalidated` | Signal `(o session_handle, s reason)`; frontend emits owner-only `GrantInvalidated` and closes the session. |

There is no `Decrypt`, `RenewGrant`, `ReleaseGrant`, `OpenPkcs11Endpoint` or public token-presence
signal. A grant ends with `Session.Close()`. The client-side module serves PKCS#11 consumers;
[`src/export/facade.h`](../src/export/facade.h) points to requirements for a possible served facade.

### Frontend-supplied identity and lifetime

| Field | Contract |
|---|---|
| `app_id` | Derived by `xdp_invocation_get_app_info()`; empty when unidentified. |
| `app_identity_level` | `sandboxed`, `host` or `unidentified`; the backend displays it. |
| `lifetime` | Frontend-approved seconds, after the 3600 s ceiling; operations stop at its monotonic deadline. Backend teardown waits `CERTIFICATE_EXPIRY_GRACE_SECONDS` longer than the frontend timer. |

There is no `app_display_name`: the backend may derive a human-readable name from `app_id`.
There is no destination `context` option. The application-provided explanation is `reason`.
The backend never writes selection memory; the interface has no `certificate_id` or
`remember_selection` result.

### Acquisition results

The frontend requires `certificate_der`, `supported_mechanisms` and `permitted_operations`
and type-checks optional results against the public XML. It intersects mechanisms with
`RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA`, in that order, and operations with the request's
`operation_policy` and purpose. Empty intersections fail acquisition. `expires_at` is generated
by the frontend. The frontend test `test_grant_is_bounded_by_the_request` covers these limits.

## Backend behavior

### Digest and hash

`Sign.data` is the bare digest. `parameters.hash` is required: `SHA1`, `SHA224`, `SHA256`,
`SHA384` or `SHA512`; spellings such as `SHA-256` are accepted. Digest length must match.
RSA PKCS#1 v1.5 builds RFC 8017 DigestInfo and calls `CKM_RSA_PKCS`; RSA-PSS builds
`CK_RSA_PKCS_PSS_PARAMS`; ECDSA passes the digest to `CKM_ECDSA`.

The API does not accept an arbitrary-length blob for raw v1.5 padding. It cannot establish that
a caller hashed the submitted bytes: any input of the required length can be signed
under the grant. TLS 1.0/1.1's raw MD5+SHA1 `CertificateVerify` concatenation is unsupported.

### ECDSA encoding

ECDSA defaults to PKCS#11's raw `r || s`, with each integer padded to the curve-order byte
length. X.509 and TLS use DER `ECDSA-Sig-Value`. Request DER with:

```text
parameters = {'hash': <'SHA256'>, 'signature_encoding': <'der'>}
```

Both encodings are required by the XML. The frontend validates `signature_encoding` as `raw`
or `der`; other values fail.

### RSA-PSS parameters

The frontend forwards parameters for backend checks against modulus size.
`mgf` (`s`) accepts `MGF1-<hash>`, for example `MGF1-SHA256`. Plain `MGF1` or omission uses
MGF1 over `hash`; bare hash names are refused. `salt_length` (`u`) defaults to digest length
and must satisfy RFC 8017 9.1.1 step 3: `emLen >= hLen + sLen + 2`.

### Interaction and consent

`required` and `allowed` always open the chooser, including for one candidate.
`forbidden` fails acquisition with response `2`. There is no delegation or remembered
selection that bypasses the chooser. The
[security checklist](SECURITY.md#missing-controls-and-evidence) records the signing-consent gap.

### Invalidation vocabulary

The public vocabulary is `expired`, `token_removed`, `policy`, `backend_gone`, `error`.
`xcc_session_invalidate()` in `src/core/session.c` logs a `g_critical()` for
an unknown reason and sends `error`.

| Reason | Backend behavior |
|---|---|
| `token_removed` | Detected removal, replacement, or a login failure indicating token loss. |
| `policy` | Legal value; this backend does not emit it. |
| `backend_gone` | Backend shutdown. |
| `error` | Invalid internal reason value. |
| `expired` | Backstop teardown after the frontend deadline plus `CERTIFICATE_EXPIRY_GRACE_SECONDS`. |

Frontend loss or replacement closes old sessions without an invalidation signal; no remaining
frontend owns those sessions. Backend bus-name loss is independently detected by the frontend.
A device error mid-operation fails that operation without necessarily invalidating a still-present
token's grant. `device_error` is not an invalidation reason.

### Decryption implementation

`src/broker/mechanism.c` implements RSA-OAEP and refuses PKCS#1 v1.5 decryption.
`tests/test-broker-decrypt.c` checks indistinguishable failures and a per-grant budget.
No D-Bus method reaches that code and capabilities advertise only `sign`.
PKCS#1 v1.5 decryption can expose a Bleichenbacher oracle; see [SECURITY.md](SECURITY.md).

### Email-purpose matching

`email` accepts an EKU permitting `emailProtection`, or no EKU restriction, and usable signing or encipherment key usage. Signing permits `digitalSignature` or
`contentCommitment`; decryption permits `keyEncipherment` or `dataEncipherment`.
Absent key usage imposes no restriction. Signing and decryption capabilities are
computed separately, then intersected with allowed operations. A PIV key-management certificate
can match `email` for decryption, but cannot be offered through the current sign-only interface.
S/MIME and eID cards can have separate signing and decryption credentials.

`certificate_purpose_operations()` returns an operation set, enabling `--list-tokens` to print
`email (decrypt only)`. Certificate key usage also restricts a token's `CKA_SIGN` claim.
`client_auth`, `signing` and `ssh` require signing capability; SSH uses the raw RSA or EC key
without X.509 key-usage restrictions. No extra purpose such as `email_decrypt` is defined.

### Session ownership and identity

Acquisition and signing compare `app_id` with the session's creating id; a mismatch answers
`2` / `no_such_session`. The frontend also checks peer ownership. The backend records identity
level at first acquisition; it may fall on later calls but cannot rise from an unverified level
to a verified one.

### Option validation

A present value with a wrong type, an unknown enum, or an unknown key in `operation_policy`,
`certificate_filter` or `parameters` fails with `2` / `invalid_request` or `invalid_filter`.
Defaults apply only to absent fields. Unknown top-level keys are ignored for compatibility with
frontend additions.

### Session close and path reuse

`Close()` is idempotent. Invalidation leaves the Session skeleton exported so the frontend can
close it. Paths include the caller's unique name and `session_handle_token`; a closed session
can be replaced at the same path, while a live session prevents reuse.

### Device rebinding

The frontend permits one acquisition per session. The backend also handles reacquisition:
`CertificateDevice` remembers its candidate and closes and logs out the old token session
before opening a different one. Login state and key handles cannot carry over to a new
certificate. Reacquisition resets the decryption budget and lifetime timer.

`tools/certificate-e2e.py --regrant <key algorithm>` exercises a second frontend session and
checks its signature against the second certificate. `tools/ui-smoke.sh` drives both prompts.

### Token display and chain

`token_display` includes `label`, `manufacturer`, `model`, `reader` and
`protected_authentication_path`. It excludes the serial, a stable identifier that could
correlate a user across applications. `chain_der` is empty and `chain_status` is `leaf_only`;
chain construction is a [roadmap item](ROADMAP.md).

### Capabilities and absence

`GetCapabilities` reports backend support, independent of inserted tokens and reader flags.
`mechanisms` lists all mechanisms the backend can drive; `protected_authentication_path=true`
means the backend supports readers with a protected authentication path. Chosen-key support
is returned as `supported_mechanisms` after consent.

After successful enumeration, forbidden interaction always returns `2`/`interaction_required`;
otherwise no display always returns `2`/`no_display`, independent of purpose/filter matches.
With a display, acquisition always opens the chooser. An empty list says "Insert your security
token"; usable tokens without matches add a dialog-only explanation. Token events re-enumerate on a worker and reapply
the request filter. Cancelling an empty or populated chooser returns `1`.

### Failure results

Failure responses include a string `reason`: `no_such_session`, `invalid_purpose`,
`invalid_filter`, `interaction_required`, `no_display`,
`device_error`, `token_removed`, `pin_locked`, `invalid_request`, `cancelled`, `owner_gone`,
`backend_gone`. The frontend forwards backend reasons unchanged for acquisition and signing
failures while the grant remains current. It can replace a signing failure with `grant_gone`
if the session closes or the grant expires. CreateSession does not forward backend reasons.

### Discovery before login

Discovery never logs in. When private keys are hidden by `CKA_PRIVATE`, a public key with the
same `CKA_ID` establishes a pair. With neither key visible and `CKF_LOGIN_REQUIRED` set,
the certificate can still be offered. Capabilities come from private `CKA_SIGN`/`CKA_DECRYPT`,
public `CKA_VERIFY`/`CKA_ENCRYPT`, or certificate key usage as a last resort. The first operation
checks the opened private key.

### PIV slot mapping

`piv_slot` derives from `CKA_ID`. OpenSC uses `0x01` through `0x04`; other middleware uses
PIV key references [[S45](SOURCES.md), [S46](SOURCES.md)]. Accepted pairs are:

| IDs | Slot |
|---|---|
| `0x9a`, `0x01` | `authentication` |
| `0x9c`, `0x02` | `signature` |
| `0x9d`, `0x03` | `key_management` |
| `0x9e`, `0x04` | `card_authentication` |

Other IDs produce no slot. A slot filter never matches an undetermined slot.

## Frontend-only access

Flatpak's D-Bus proxy permits the public portal and does not grant access to this impl bus name.
The backend also restricts every method, including `Request.Close()` and `Session.Close()`,
to the unique owner of `org.freedesktop.portal.Desktop`. Other senders receive
`org.freedesktop.DBus.Error.AccessDenied`, logged by reason code. See
[`certificate_impl_sender_is_frontend`](../src/certificate-impl.h).

Rejections use the cached owner without a bus round trip, so hostile messages cannot force a
synchronous lookup per message. Acceptance resolves `GetNameOwner` directly: D-Bus does not
order `NameOwnerChanged` against a former owner's queued messages. Unique names are never reused.
A successor's first call can be refused before the owner watch updates; the frontend retries.
Owner change cancels old windows and invalidates old sessions before accepting the successor.
No owner means every method is refused.

The lookup is a snapshot; ownership can change between authorization and work. See
[SECURITY.md](SECURITY.md#open-problems).
[The threat model](SECURITY.md#boundary-and-threat-model) covers host-process access and external
hardening requirements.

The backend permits replacement only under `--allow-replacement`; `--replace` merely asks to
replace an owner that permits it. D-Bus cannot authenticate who requests replacement. The
installed activation file passes neither flag. Upgrades require stopping the process and allowing
activation of the new executable. Development `tools/dev-stack.sh --live` passes both flags;
[TESTING.md](TESTING.md) §3.8 covers restoration.


## Internal core boundary

The wire contract is unchanged. `certificate-impl.c` keeps generated skeleton handlers,
wire validation, current-owner resolution, path registries and result serialization.
`Request.Close` cancels its `XccRequest`; `Session.Close` closes its `XccSession`. Both
methods still require a fresh successful frontend-owner check. Owner replacement advances
the core generation and drops the old adapter sessions and requests. Core also checks the
generation and app ID and refuses any increase in identity assurance. Sign inherits the
session's assurance because its wire options contain no identity or activation token.

Transactions live in `src/core/acquire.c` and `src/core/sign.c`. Their specifications contain
copied strings, byte spans and explicit presence flags. Core errors map to the existing
response codes and diagnostic strings: user cancellation is `1`; owner loss and other
failures are `2`. Acquisition cancellation has empty results; signing cancellation retains
`reason=cancelled`, including cancellation on a PIN-pad reader. A PIN provider's
`NO_DISPLAY` remains `no_display` through signing. `PIN_INCORRECT` and `LOGIN_TIMEOUT`
remain `device_error` on the wire; `NOT_SUPPORTED` remains `invalid_request`.
Capabilities retain their dictionary-only reply.

The private coordinator owns transaction policy. UI views, close/hide calls, invalidations
and completions are queued in order to the desktop dispatcher. No UI callback runs with a
device lock held. Chooser replies carry an interaction ID, revision and candidate ID;
PIN replies transfer an `XccSecret`. Stale replies are ignored and their secrets are wiped.
Chooser close is now observed asynchronously by the adapter's UI, while deferred consent
still waits for its refresh worker before granting or replying.
Acceptance drains the discovery event queue before granting, including without an active
refresh. This ordering covers watcher emissions and injected events already queued at the
drain's lock boundary; physical removals still inside polling/debounce are discovered later.
PIN providers acknowledge readiness with `xcc_pin_ready()` before core requests a
protected-path warning. Late and duplicate readiness replies are ignored.

Chooser views and candidate rows, PIN views, warnings and candidate information include
`struct_size` and `abi_version` using `XCC_ABI_VERSION`. Consume known fields from a supported
version and size; skip appended fields. Use `xcc_chooser_view_candidate()` for the producer's
candidate-row stride. Core headers used by adapters and providers have C++ linkage guards.

The internal headers remain uninstalled in this slice. Installation, dependency separation
and the exported SDK belong to slice 6.

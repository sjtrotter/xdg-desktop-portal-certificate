# Public interface

`org.freedesktop.portal.experimental.Certificate1` is defined by the xdg-desktop-portal fork's
[experimental/integration](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/integration)
branch. Its XML is authoritative.

## Frontend files

| File on the frontend branch | Purpose |
|---|---|
| `data/org.freedesktop.portal.experimental.Certificate1.xml` | Public interface |
| `data/org.freedesktop.impl.portal.experimental.Certificate1.xml` | Backend interface |
| `desktop-portal/certificate.c` | Frontend implementation |
| `tests/templates/certificate.py` | Mock backend |
| `tests/test_certificate.py` | Frontend tests |

The [impl XML](../data/org.freedesktop.impl.portal.experimental.Certificate1.xml) is a tracking
copy in this repository. The public XML belongs only to the frontend.

## Contract

| Property | Value |
|---|---|
| Interface | `org.freedesktop.portal.experimental.Certificate1` |
| Bus name | `org.freedesktop.portal.Desktop` |
| Object path | `/org/freedesktop/portal/desktop` |
| `version` | `1` |
| Request handles | `/org/freedesktop/portal/desktop/request/...` |
| Session handles | `/org/freedesktop/portal/desktop/session/...` |

The frontend exports the interface only with a configured backend for
`org.freedesktop.impl.portal.experimental.Certificate1` and `Certificate1` listed in
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` at startup. Values are comma separated with no
spaces. Without both conditions, the interface
is absent from introspection and `Properties.Get` fails. Breaking changes increment the
trailing interface number; compatible changes increment `version`.

| Method or signal | Shape |
|---|---|
| `CreateSession` | `(a{sv} options) -> o handle`, Request |
| `AcquireCredential` | `(o session, s parent_window, a{sv} options) -> o handle`, Request |
| `Sign` | `(o session, s parent_window, a{sv} options) -> o handle`, Request |
| `GetCapabilities` | `(a{sv} options) -> a{sv} capabilities` |
| `GrantInvalidated` | `(o session_handle, s reason)`, sent only to the owning connection |

`CreateSession` returns a Request handle; the Session handle arrives in its `Response`.
`AcquireCredential` fills that Session with the user's selected credential; `Session.Close()`
ends the grant. A grant is bound to its creating D-Bus connection, token, permitted operations,
mechanisms and expiry. A session acquires once: another acquisition answers `2` with reason
`grant_already_held`. A second credential requires a second session and consent.

`Sign` returns a Request because login or consent may require a prompt. The caller can cancel
with `Request.Close()`. The acquisition result's `may_prompt_later` describes later interaction.

### Options

Standard Request options include `handle_token` and `activation_token`.
`AcquireCredential` also accepts:

- `purpose`, required: `client_auth`, `signing`, `email` or `ssh`.
- `interaction_mode`: `required`, `allowed` (default) or `forbidden`.
- `requested_lifetime`: seconds, default 300 and clamped to 3600 by the frontend.
- `reason`: at most 256 characters of application-provided text, displayed outside trusted identity.
- `certificate_filter`: `issuers`, `key_usage`, `eku`, `key_algorithms`, `token_label`, `piv_slot`.
- `operation_policy`: only `sign` is supported.

Filters only narrow selection and are not a security boundary. Unknown keys in
`certificate_filter` and `operation_policy` are errors.

`Sign` requires a granted `mechanism`: `RSA_PKCS1_V1_5`, `RSA_PSS` or `ECDSA`. Its `data`
is a digest with the exact length named by `parameters.hash`. The backend constructs the
mechanism's encoding, including DigestInfo for RSA PKCS#1 v1.5. The caller can submit any bytes
of the required length; this validates shape and cannot prove how the input was computed or used.
See [IMPL-INTERFACE.md](IMPL-INTERFACE.md) for parameter rules.

### Results

Acquisition requires `certificate_der`, non-empty `supported_mechanisms` and non-empty
`permitted_operations`. Optional results are `chain_der`, `chain_status`, `token_display`,
`key_type`, `key_size`, `key_curve` and `may_prompt_later`. The frontend adds `expires_at`.
`chain_status` is `complete`, `partial` or `leaf_only`; it describes completeness without
asserting trust. The frontend type-checks results; a protocol violation answers `2` with
reason `backend_protocol_error`.

`GetCapabilities` returns `purposes`, `operations`, `mechanisms`,
`protected_authentication_path`, `has_display` and `max_grant_lifetime`. The frontend
intersects the three lists with its own policy and forwards the booleans.

## Lifetime

A grant has no renewal. Its acquisition fixes a lifetime of at most 3600 seconds; further use
requires a fresh session and consent. `expires_at` is a frontend-generated wall-clock value
for display. Enforcement uses a monotonic clock, so wall-clock adjustments cannot extend the
grant and can make the displayed value disagree with the remaining time.

The frontend's monotonic timer emits `GrantInvalidated(expired)` and closes the Session.
The backend stops operations at the same deadline; its teardown timer runs
`CERTIFICATE_EXPIRY_GRACE_SECONDS` later as a backstop. Backend activity cannot extend a grant.

`GrantInvalidated` reasons are `expired`, `token_removed`, `policy`, `backend_gone` and `error`.
Consumers must tolerate unknown values. The signal is sent only to the owner because a session
path contains its unique bus name. Sessions with no acquired credential close without that signal.

## Accessibility criteria

The backend owns the chooser and PIN interaction. Required behavior includes AT-SPI exposure,
keyboard operation, meaningful focus order, screen-reader announcement of caller, purpose and
operation class, scalable text, high contrast, reduced animation, textual state indicators, accessible errors and
cancellation, and focus restoration to the caller. PIN entry must hide its contents from AT-SPI;
errors and retry warnings must be announced. See [ARCHITECTURE.md](ARCHITECTURE.md) and
[SECURITY.md](SECURITY.md).

## Absent methods and options

Neither interface exposes `OpenPkcs11Endpoint`; PKCS#11 consumers use the client module.
See [the endpoint design](ARCHITECTURE.md#deferred-endpoint) and
[ADR 0011](decisions/0011-client-side-pkcs11-module.md).
There is no `context` destination hint; `reason` carries application-provided explanatory text.

## Manual calls

[`trigger-certificate.sh`](../tools/trigger-certificate.sh) calls methods with `gdbus`.
[`dev-stack.sh`](../tools/dev-stack.sh) starts a configured frontend and backend; see
[TESTING.md](TESTING.md).

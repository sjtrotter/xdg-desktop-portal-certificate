# io.github.sjtrotter.Smartcard1

Status: EXPERIMENTAL. This interface is **not stable**, has **not** been proposed to anyone, and
will change. The publication gates that must be passed before any part of it is frozen are in
[ROADMAP.md](ROADMAP.md).

Bus name `io.github.sjtrotter.Smartcard1`, object `/io/github/sjtrotter/Smartcard1`, interface
version 1. Declared in [`../data/io.github.sjtrotter.Smartcard1.xml`](../data/io.github.sjtrotter.Smartcard1.xml).

This is **not** `org.freedesktop.portal.Smartcard`. That namespace belongs to xdg-desktop-portal and
using it would imply an acceptance that does not exist. The transaction pattern below is copied
closely from [`org.freedesktop.portal.Request`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Request.html);
copying a pattern is not claiming a namespace.

## Model

The interface has three parts, in decreasing order of confidence:

1. **Credential selection** — `AcquireCredential` returns a *grant*: a chosen certificate, its
   chain, what the key can do, and for how long. No key material, no PIN, no handle.
2. **Brokered operations** — `Sign`, and optionally `Decrypt`, performed by the service on the
   grant's key. **This is the core contract.**
3. **A PKCS#11 compatibility endpoint** — `OpenPkcs11Endpoint`, **experimental**, requested
   explicitly by a caller that has no way to use (2), backed by a broker-controlled synthetic
   facade. Never returned automatically. See
   [decisions/0007](decisions/0007-brokered-operations-are-the-core.md).

## Methods

### AcquireCredential

```
AcquireCredential (IN  s     parent_window,
                   IN  a{sv} options,
                   OUT o     request_handle)
```

Asks the user to select a credential and grants its use for a bounded purpose and time.

`parent_window` uses the
[portal window identifier convention](https://flatpak.github.io/xdg-desktop-portal/docs/window-identifiers.html):
`wayland:<handle>` from `xdg_foreign`, `x11:<xid>`, or empty when the caller genuinely has no
parent. An invalid or expired parent **must not** fail the request; the service degrades to an
unparented, service-controlled window.

**Options**

| Key | Type | Meaning |
|---|---|---|
| `handle_token` | `s` | Caller-chosen unguessable token forming the request object path, so the caller can subscribe before the call returns. Required in practice. |
| `activation_token` | `s` | XDG activation token authorising focus. Distinct from `parent_window`: the parent makes the window transient, the activation token permits it to come forward. A background caller without one does not steal focus. |
| `purpose` | `s` | `client_auth`, `signing`, `email`, or `ssh`. **Required. There is no `any`.** A request that will not say what it is for cannot be described to the user in the service's own words or given a consent policy, and is rejected. |
| `certificate_filter` | `a{sv}` | `issuers` `aay` (DER issuer DNs), `key_usage` `as`, `eku` `as` (OIDs), `key_algorithms` `as`, `token_label` `s`, `piv_slot` `s` (`authentication`, `signature`, `key_management`, `card_authentication`). All optional, all AND-ed. |
| `operation_policy` | `a{sv}` | `sign` `b`, `decrypt` `b` — the operations the caller is asking for. Defaults to `{sign: true}`. Asking for `decrypt` changes the consent language and is refused for purposes that do not justify it. |
| `requested_lifetime` | `u` | Seconds requested. **A ceiling request, not a floor**: service policy may grant less and never grants more. |
| `interaction_mode` | `s` | `required` — always prompt; `allowed` — prompt if needed (default); `forbidden` — never prompt, so a request that would need a chooser or a PIN fails with `interaction_required`. |
| `allow_selection_memory` | `b` | Permits the user to be *offered* a "use this certificate next time" choice. Preselection only. It never skips consent and never skips a PIN. Ignored for callers whose identity could not be verified. |
| `reason` | `s` | Caller-supplied hint. **Untrusted.** Displayed subordinate to and visibly labelled as application-provided text; never in the trusted identity position; never logged. |
| `context` | `s` | Caller-supplied destination context, e.g. the host a client certificate is for. **Untrusted**, displayed as *requested* destination. The service sees a D-Bus peer, not a TLS connection, and cannot verify it. |
| `interface_version` | `u` | Version negotiation; the caller's maximum understood version. |
| `correlation` | `s` | Opaque caller token returned unchanged in the response. |

**Results** (in `Request.Response`, response `0`)

| Key | Type | Meaning |
|---|---|---|
| `grant_id` | `s` | Names the grant in every later call. Not a capability: possession without the owning connection grants nothing. |
| `certificate_der` | `ay` | The chosen leaf certificate, DER. |
| `chain_der` | `aay` | Ordered intermediates, best effort. |
| `chain_status` | `s` | `complete`, `partial`, or `leaf_only`. Many tokens hold only the leaf; the service may assemble the rest from system stores. **This is a description of completeness, not a trust claim.** |
| `token_display` | `a{sv}` | Token and reader identity **for display**: label, manufacturer, model, reader name. For showing the user which card was used — not for long-term authorisation and not a stable key. |
| `key_type` | `s` | `RSA`, `EC`. |
| `key_size` | `u` | Modulus bits, or curve size. |
| `key_curve` | `s` | Curve name for EC keys. |
| `supported_mechanisms` | `as` | The mechanisms this grant will actually accept, already intersected with the service's allow-list and the key's capabilities. |
| `permitted_operations` | `as` | Subset of `sign`, `decrypt`. |
| `expires_at` | `t` | Real expiry, seconds since the epoch. May be sooner than requested. |
| `may_prompt_later` | `b` | **Whether a later `Sign` or `Decrypt` may show a window.** True whenever lazy login has not happened yet or the purpose's policy is per-operation. A caller must never be able to say it was promised silence. |
| `correlation` | `s` | Returned unchanged. |

### Sign

```
Sign (IN  s     grant_id,
      IN  s     operation_id,
      IN  s     mechanism,
      IN  a{sv} parameters,
      IN  ay    data,
      OUT ay    signature)
```

Performs one signature with the grant's key. May prompt — for the first login, or for per-operation
consent — so callers must not assume it returns promptly. `operation_id` is caller-chosen and lets a
cancellation, a result and a log line be correlated without correlating them by content.

`mechanism` is a name from the grant's `supported_mechanisms`. `parameters` carries what the
mechanism needs — for RSA-PSS the hash, MGF and salt length — and **is validated against the
mechanism and the key rather than passed through**. `data` is the digest or the message, as the
mechanism requires; a size limit applies.

Consent policy depends on the grant's purpose: `client_auth` is normally covered by the grant,
`signing` asks per operation and shows a digest or fingerprint of what is being signed, `decrypt` is
per operation or tightly bounded, `ssh` has its own policy. See
[ARCHITECTURE.md](ARCHITECTURE.md#broker--srcbrokeroperationsh).

**A signature is not an attestation of purpose.** The service cannot prove that a `Sign` input came
from a TLS handshake rather than from arbitrary data. `purpose` constrains selection and consent
language, nothing more.

### Decrypt

```
Decrypt (IN  s grant_id, IN s operation_id, IN s mechanism,
         IN  a{sv} parameters, IN ay ciphertext,
         OUT ay plaintext)
```

Optional, refused unless the grant's `permitted_operations` includes `decrypt`. Consent is
per-operation or tightly bounded, because decryption exposes confidential data rather than producing
an authentication artefact. Not in v1.

### RenewGrant

```
RenewGrant (IN s grant_id, IN a{sv} options, OUT t expires_at)
```

Extends a grant **only** while the caller identity and token binding are unchanged, and **never**
expands its permitted operations or mechanisms. Reauthorisation — a fresh `AcquireCredential` — is
required after long inactivity, token removal and reinsertion, a policy change, or a change in
application identity.

### ReleaseGrant

```
ReleaseGrant (IN s grant_id)
```

Ends a grant immediately: sessions closed, logged out where the token supports it, endpoints
poisoned, in-flight operations cancelled. Only the owning connection may release a grant. Calling it
on an already-dead grant succeeds.

### GetCapabilities

```
GetCapabilities (OUT a{sv} capabilities)
```

What this implementation actually supports: `interface_version`, `purposes`, `operations`,
`mechanisms`, `pkcs11_endpoint` `b` and `endpoint_version` `u`, `selection_memory` `b`,
`protected_authentication_path` `b`, `max_grant_lifetime` `u`. Callers negotiate rather than probe
by failing.

### OpenPkcs11Endpoint — EXPERIMENTAL

```
OpenPkcs11Endpoint (IN  s     grant_id,
                    IN  a{sv} options,
                    OUT h     endpoint_fd,
                    OUT s     certificate_uri,
                    OUT s     private_key_uri,
                    OUT u     endpoint_version)
```

For consumers that cannot use brokered operations because their TLS stack wants a PKCS#11 module.
**Never returned automatically; the caller asks, and `GetCapabilities` says whether it is available
at all.**

`endpoint_fd` is a **Unix socket file descriptor, not a path**. A path is discoverable, races on the
filesystem, and needs a bind mount to cross a sandbox; an fd passed over D-Bus is the capability and
already crosses. It speaks the p11-kit RPC protocol and is served by a broker-controlled **synthetic
module** — one slot, one token, the granted objects, read-only sessions, a mechanism allow-list,
handle mapping, and refusal of every administrative and key-management function
([ARCHITECTURE.md](ARCHITECTURE.md#the-synthetic-pkcs11-facade--srcexportfacadeh)). It is **not**
the card forwarded.

`certificate_uri` and `private_key_uri` are [RFC 7512](https://www.rfc-editor.org/rfc/rfc7512.html)
URIs **valid only on this endpoint**. A URI without an endpoint that resolves it is not a
capability and is never returned alone. **No `pin-value` or `pin-source` attribute ever appears in a
URI this service emits**, and any URI arriving with one is truncated before it can reach a log.

Two things are unresolved and are why this is experimental:

- **Consumers may not be able to load it.** A PKCS#11 URI cannot name a socket,
  `g_tls_certificate_new_from_pkcs11_uris()` has no module parameter, and a browser's network
  process may have started before the endpoint existed. The likely resolution is the opposite shape
  — one permanently registered broker module exposing synthetic grant-bound slots, with this call
  returning a URI that module can resolve rather than a new module. [SPIKES.md](SPIKES.md) S3
  decides, and `endpoint_version` exists so the answer can change the wire format.
- **Endpoint holders are not the owner.** The connection that opens the endpoint may be a subprocess
  of the caller. See the lifetime rules below.

## The Request object

`io.github.sjtrotter.Smartcard1.Request`, at
`/io/github/sjtrotter/Smartcard1/request/<sender>/<handle_token>`, where `<sender>` is the caller's
unique bus name with the leading colon removed and dots replaced by underscores — the same
construction xdg-desktop-portal uses, so the caller can subscribe before calling and never race the
response.

```
Close ()
Response (u response, a{sv} results)
```

`Close()` cancels. There is no separate `Cancel`. After `Close()` no success response follows, per
portal convention.

| `response` | Meaning |
|---|---|
| `0` | Success. `results` as documented per method. |
| `1` | Cancelled by the user, or by `Close()`. |
| `2` | Ended some other way. `results` carries `error` and `error_message`. |

## Error names and result codes

Errors on the initial method call use these D-Bus names; failures after the request object exists
arrive as response `2` with the same string in `results["error"]`.

| Name | Meaning |
|---|---|
| `io.github.sjtrotter.Smartcard1.Error.NoToken` | No token present at all. |
| `io.github.sjtrotter.Smartcard1.Error.TokenAbsent` | The named token is not present. |
| `io.github.sjtrotter.Smartcard1.Error.TokenRemoved` | Removed during the operation. |
| `io.github.sjtrotter.Smartcard1.Error.NoMatchingCertificate` | Tokens present, nothing satisfies the filter. Distinct from `NoToken`: the user needs to know which. |
| `io.github.sjtrotter.Smartcard1.Error.PinIncorrect` | Wrong PIN. Retries remaining reported only if the token reports them reliably. |
| `io.github.sjtrotter.Smartcard1.Error.PinLocked` | PIN blocked. This service cannot unblock it. |
| `io.github.sjtrotter.Smartcard1.Error.InteractionRequired` | A prompt was needed and `interaction_mode` was `forbidden`. |
| `io.github.sjtrotter.Smartcard1.Error.NoDisplay` | No usable display. **The service never falls back to reading a PIN from stdin.** |
| `io.github.sjtrotter.Smartcard1.Error.UnsupportedMechanism` | Mechanism or parameters not in the grant's allow-list, or invalid for the key. |
| `io.github.sjtrotter.Smartcard1.Error.GrantExpired` | Expired, released or invalidated. |
| `io.github.sjtrotter.Smartcard1.Error.NotPermitted` | Operation outside the grant's `permitted_operations`, or a caller acting on a grant it does not own. |
| `io.github.sjtrotter.Smartcard1.Error.RateLimited` | Too many operations or too many requests. |
| `io.github.sjtrotter.Smartcard1.Error.DeviceError` | Reader or middleware failure. Deliberately distinct from a wrong PIN. |
| `io.github.sjtrotter.Smartcard1.Error.BackendUnavailable` | No p11-kit, no pcscd, no module. |

## Signals

```
TokenAdded      (a{sv} token)
TokenRemoved    (a{sv} token)
GrantInvalidated(s grant_id, s reason)
```

`token` carries display identity only. `reason` is one of `released`, `expired`, `token_removed`,
`owner_gone`, `policy`, `service_shutdown`, `error`.

**`ListTokens` is deliberately absent from v1.** Enumerating a user's tokens without any UI is
itself a disclosure — which cards, how many readers, which employer's issuance — to a caller that
has not yet been through a consent dialog. `TokenAdded`/`TokenRemoved` exist because a consumer must
be able to react to removal mid-flow and to offer "insert your card" at a sensible moment; they are
justified by need, and enumeration on demand is not, yet. If a consumer demonstrates that it needs
it, it can be added behind the same consent as anything else.

## Fixed behaviour, versus what a caller may choose

**Fixed. Not options, not negotiable.**

- The request handle, the transaction binding, and the response codes.
- **The PIN never crosses D-Bus, in either direction, ever.**
- **No `pin-value` or `pin-source` in any URI emitted.**
- The verified caller identity shown to the user, and its position in the window.
- Sandboxed-versus-unsandboxed status shown, with a warning for unverified callers.
- The purpose stated in the service's own words.
- One terminal response per request, at most.
- Caller disconnect ends the transaction; grant lifetime follows the owner/holder rules below.
- No URI, label, serial, subject, signed data, `reason` or `context` in logs.
- Maximum request and operation sizes, and rate limits.
- Which mechanisms are allowed, and validation of their parameters.
- Read-only sessions and the refused-function list on the facade.
- A default timeout and a hard maximum.
- Cleanup on crash.

**A caller may choose:** `handle_token`, `activation_token`, `purpose`, `certificate_filter`,
`operation_policy` (as a request), a *shorter* `requested_lifetime`, `interaction_mode`,
`allow_selection_memory` (as an offer to the user), `reason` and `context` (untrusted hints),
`interface_version`, `correlation`, and whether to ask for a PKCS#11 endpoint.

**A caller may never control:** PIN persistence; whether consent is shown; the text identifying the
application; whether sandbox status is shown; the mechanism allow-list; unlimited lifetime; which
certificate is used without the user choosing it; whether a signature is logged; another
application's grant.

## Lifetime

A grant has **one owner connection** and **zero or more delegated endpoint holders**. Binding to the
owner's D-Bus connection alone is not enough: the process doing the cryptography may be a browser's
network subprocess with its own connection to the endpoint. Killing the grant when the owner's
connection drops can kill a valid handshake; keeping it alive for the subprocess lets it be used
after the request that authorised it ended. So:

- the grant dies when the owner calls `ReleaseGrant`, **or** when all permitted holders have gone;
- a **short orphan grace period** covers the gap between acquisition and the subprocess connecting,
  after which an unclaimed grant is destroyed;
- `expires_at` always applies;
- card removal invalidates immediately, cancels in-flight operations, poisons the endpoint against a
  reinserted card, and requires explicit reselection — even if the label and slot number match,
  because they prove nothing;
- service shutdown invalidates everything.

Timeouts: a five-minute default for an interactive request with a hard ceiling around fifteen
minutes. Smart-card and MFA flows make very short fixed timeouts hostile, and a user hunting for a
card reader is a normal user.

## Accessibility as acceptance criteria

Not implementation detail, and not deferrable — these controls *carry* the security decision.

- AT-SPI exposure for every service-owned control.
- Complete keyboard-only certificate selection and PIN entry.
- Meaningful focus order, and focus restored to the calling application afterwards.
- Screen-reader announcement of the verified requesting application, its sandbox status, the purpose
  and the operation class.
- Scalable text, high contrast, reduced-animation behaviour.
- No information conveyed by colour alone — including "this certificate has expired".
- Accessible error and cancellation states, including "incorrect PIN, N attempts remaining".
- The PIN field is never echoed and its contents never enter the accessibility tree.

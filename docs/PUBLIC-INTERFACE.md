# The public interface is not in this repository

This document used to specify `org.freedesktop.portal.experimental.Certificate`'s
predecessor at length, because this repository shipped the frontend that exported it. It
does not any more: the frontend is a branch of xdg-desktop-portal, and **the XML on that
branch is the specification**. See
[decisions/0010-backend-only-frontend-lives-upstream.md](decisions/0010-backend-only-frontend-lives-upstream.md).

## Where it is

```
repository   a local checkout of xdg-desktop-portal   (remote: flatpak/xdg-desktop-portal)
branch       experimental/certificate-webauthentication
commit       703fb22  certificate: Add an experimental Certificate portal
public XML   data/org.freedesktop.portal.experimental.Certificate.xml
impl XML     data/org.freedesktop.impl.portal.experimental.Certificate.xml
frontend     desktop-portal/certificate.c
mock backend tests/templates/certificate.py
tests        tests/test_certificate.py
```

The impl half is also here, as a verbatim tracking copy:
[`../data/org.freedesktop.impl.portal.experimental.Certificate.xml`](../data/org.freedesktop.impl.portal.experimental.Certificate.xml).
The public half is deliberately **not** copied: this repository has no reason to hold a
second copy of an interface it does not implement, and a stale one would be worse than
none.

Everything below is a summary for orientation. Where it disagrees with the XML, the XML is
right.

## Summary

Interface `org.freedesktop.portal.experimental.Certificate`, on bus name
`org.freedesktop.portal.Desktop`, object path `/org/freedesktop/portal/desktop`,
`version` property `1`.

**It is not exported unless xdg-desktop-portal was started with
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` containing `certificate`** (or `all`). With the
gate off it is absent from introspection and `Properties.Get` fails. It is experimental and
can change or be removed without a version bump.

```
CreateSession      (a{sv} options)                            → o handle          [Request]
AcquireCredential  (o session, s parent_window, a{sv} options) → o handle          [Request]
Sign               (o session, s parent_window, a{sv} options) → o handle          [Request]
Decrypt            (o session, s parent_window, a{sv} options) → o handle          [Request]
RenewGrant         (o session, a{sv} options)                  → t expires_at
ReleaseGrant       (o session)
GetCapabilities    (a{sv} options)                             → a{sv} capabilities
signals: TokenAdded(a{sv}), TokenRemoved(a{sv}), GrantInvalidated(o, s)
```

**A grant is a `Session`.** `CreateSession` makes an empty one, `AcquireCredential` fills
it in with a certificate the user chose, and `Session.Close()` — or `ReleaseGrant`, its
alias — ends it. A grant is bound to the D-Bus connection that created it, to the token
that backs it, and to the operations and mechanisms the frontend allowed; a grant always
has an expiry.

`Sign` and `Decrypt` are `Request`-shaped because they may prompt — a lazy login, or
per-operation consent — and upstream's convention is that anything which can show a window
returns a `Request` the caller can `Close()`. The acquire response carries
`may_prompt_later` so a caller can never claim it was promised silence.

### Options that matter

- `purpose` is **required** on `AcquireCredential`, and is one of `client_auth`,
  `signing`, `email`, `ssh`. **There is deliberately no value meaning "anything".**
- `interaction_mode` is `required`, `allowed` (default) or `forbidden`.
- `requested_lifetime` is a ceiling *request*: the frontend clamps it to 3600 s (default
  300) and hands the backend its own decision.
- `mechanism` must be one the grant reported, and the allow list is now **per operation**:
  `Sign` takes `RSA_PKCS1_V1_5`, `RSA_PSS` or `ECDSA`; `Decrypt` takes `RSA_OAEP` and
  nothing else. A v1.5 decryption whose outcome the caller can observe is a padding
  oracle over the card's key, so it is a signing mechanism here and not a decryption one.
- `data` on `Sign` is **always a digest** of the `hash` named in `parameters`, and its
  length must be exactly that digest's length. What that buys is narrow and worth stating
  exactly: a caller cannot get a signature over bytes it did not hash itself, and cannot
  have an arbitrary blob wrapped in raw PKCS#1 v1.5 padding and signed. It is still a
  signing capability over any message the caller chooses to hash, as every signing API is;
  the grant's purpose, expiry and `permitted_operations` are what bound it.
- `reason` (≤ 256 chars) is application-supplied text, shown as such and never in the
  trusted identity position.
- `allow_selection_memory` permits *preselection only*, is ignored for applications whose
  identity could not be verified, and never skips consent or a PIN.
- `certificate_filter` narrows what is offered (`issuers`, `key_usage`, `eku`,
  `key_algorithms`, `token_label`, `piv_slot`). A filter never widens, and is not a
  security boundary.

### Results that matter

`grant_id` (a diagnostic identifier, not a capability — the session handle is the
capability), `certificate_der`, `chain_der`, `chain_status` (`complete` / `partial` /
`leaf_only`, which describes completeness and not trust), `token_display`, `key_type`,
`key_size`, `key_curve`, `supported_mechanisms`, `permitted_operations`, `expires_at`,
`may_prompt_later`.

`GetCapabilities` answers `purposes`, `operations`, `mechanisms`, `selection_memory`,
`protected_authentication_path`, `max_grant_lifetime`.

## Lifetime

A grant always expires. `expires_at` is frontend-generated and can be sooner than
`requested_lifetime` asked for. `RenewGrant` is decided **entirely** in the frontend — the
backend is never asked and no window appears — and never expands the permitted operations
or mechanisms. `GrantInvalidated(o session_handle, s reason)` says why a grant stopped
being usable before it was released; `reason` is one of `released`, `expired`,
`token_removed`, `owner_gone`, `policy`, `service_shutdown`, `backend_gone`, `error`, and
consumers must tolerate values they do not know.

## Accessibility as acceptance criteria

The chooser and the PIN prompt carry the security decision, and a dialog a screen-reader
user cannot navigate cannot carry informed consent. AT-SPI exposure for every control,
complete keyboard-only operation, meaningful focus order, screen-reader announcement of
the verified caller, purpose and operation class, scalable text, high contrast,
reduced-animation behaviour, no information carried by colour alone, accessible error and
cancellation states, focus restored to the calling application afterwards. These are
**backend** obligations — this repository's — and they are acceptance criteria rather than
polish. See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## What is not on the interface, and why

`OpenPkcs11Endpoint` — the experimental PKCS#11 compatibility endpoint the earlier sketch
specified here — **is not in the branch at all**, on either the public or the impl side. An
fd-returning method needs its own review, and a python-dbusmock backend cannot hand back a
usable endpoint fd, so a first version carrying it would have shipped untested. It is a
follow-up, to land with the facade rules in [SECURITY.md](SECURITY.md).

`context` — the "requested destination host" hint — is not there either. The only
caller-supplied text on the interface is `reason`.

## Poking it by hand

[`../tools/trigger-certificate.sh`](../tools/trigger-certificate.sh) makes each of these
calls with `gdbus`, and [`../tools/dev-stack.sh`](../tools/dev-stack.sh) starts a
development frontend and this backend on a private bus first.

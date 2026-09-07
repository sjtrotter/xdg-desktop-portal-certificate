# The public interface is not in this repository

This document used to specify `org.freedesktop.portal.experimental.Certificate`'s
predecessor at length, because this repository shipped the frontend that exported it. It
does not any more: the frontend is a branch of xdg-desktop-portal, and **the XML on that
branch is the specification**. See
[decisions/0010-backend-only-frontend-lives-upstream.md](decisions/0010-backend-only-frontend-lives-upstream.md).

## Where it is

```
repository   a local checkout of xdg-desktop-portal   (origin: sjtrotter/xdg-desktop-portal)
branch       experimental/certificate-webauthentication
commit       a4c1f62  certificate: Add an experimental Certificate portal
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
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` containing `certificate`.** With the gate off it
is absent from introspection and `Properties.Get` fails. It is experimental and can change
or be removed without a version bump.

```
CreateSession      (a{sv} options)                            → o handle          [Request]
AcquireCredential  (o session, s parent_window, a{sv} options) → o handle          [Request]
Sign               (o session, s parent_window, a{sv} options) → o handle          [Request]
GetCapabilities    (a{sv} options)                             → a{sv} capabilities
signals: GrantInvalidated(o, s), to the session's owner only
```

**A grant is a `Session`.** `CreateSession` makes an empty one, `AcquireCredential` fills
it in with a certificate the user chose, and `Session.Close()` ends it. A grant is bound to
the D-Bus connection that created it, to the token that backs it, and to the operations and
mechanisms the frontend allowed; a grant always has an expiry. **A session acquires once**:
a second `AcquireCredential` on it answers `2` with `reason` `grant_already_held`, and a
second credential means a second session and a second consent.

`Sign` is `Request`-shaped because it may prompt — a lazy login, or per-operation consent —
and upstream's convention is that anything which can show a window returns a `Request` the
caller can `Close()`. The acquire response carries `may_prompt_later` so a caller can never
claim it was promised silence.

### Options that matter

- `purpose` is **required** on `AcquireCredential`, and is one of `client_auth`,
  `signing`, `email`, `ssh`. **There is deliberately no value meaning "anything".**
- `interaction_mode` is `required`, `allowed` (default) or `forbidden`.
- `requested_lifetime` is a ceiling *request*: the frontend clamps it to 3600 s (default
  300) and hands the backend its own decision.
- `mechanism` must be one the grant reported: `RSA_PKCS1_V1_5`, `RSA_PSS` or `ECDSA`.
- `data` on `Sign` is **always a digest** of the `hash` named in `parameters`, and its
  length must be exactly that digest's length. What that buys is narrow and worth stating
  exactly: a caller cannot get a signature over bytes it did not hash itself, and cannot
  have an arbitrary blob wrapped in raw PKCS#1 v1.5 padding and signed. It is still a
  signing capability over any message the caller chooses to hash, as every signing API is;
  the grant's purpose, expiry and `permitted_operations` are what bound it.
- `reason` (≤ 256 chars) is application-supplied text, shown as such and never in the
  trusted identity position.
- `certificate_filter` narrows what is offered (`issuers`, `key_usage`, `eku`,
  `key_algorithms`, `token_label`, `piv_slot`). A filter never widens, and is not a
  security boundary. It and `operation_policy` are **closed vocabularies**: a key the
  frontend does not know is an error, because a filter that is silently ignored offers the
  user more than the application asked for.

### Results that matter

`certificate_der` (required), `supported_mechanisms` and `permitted_operations` (required
and non-empty), `chain_der`, `chain_status` (`complete` / `partial` / `leaf_only`, which
describes completeness and not trust), `token_display`, `key_type`, `key_size`,
`key_curve`, `expires_at` and `may_prompt_later`. Every one of them is type-checked against
the type the interface declares, and an acquisition whose results do not satisfy that
answers `2` with `reason` `backend_protocol_error`.

`GetCapabilities` answers `purposes`, `operations`, `mechanisms`,
`protected_authentication_path`, `has_display` and `max_grant_lifetime`. The first three
are this backend's lists intersected with the frontend's own; `has_display` is forwarded
as this backend reported it, because an application that cannot be shown a chooser needs
to know before it asks for one.

## Lifetime

A grant always expires, and **there is no renewal**: the lifetime is fixed at acquisition,
clamped to 3600 s, and the only way on is a fresh session and a fresh consent. `expires_at`
is frontend-generated, can be sooner than `requested_lifetime` asked for, and is a wall-clock
value for display — the frontend enforces the lifetime on the monotonic clock, so moving the
system clock afterwards changes neither the grant nor that number, and the two stop agreeing.

**Announcing the expiry is the frontend's.** It arms a monotonic timer at the lifetime it
decided; when the timer fires it emits `GrantInvalidated(expired)` to the session's owner and
closes the session, and that `Close()` is what ends this backend's card session. This backend
keeps its own copy of the deadline — operations stop at it — but its own teardown timer runs
`CERTIFICATE_EXPIRY_GRACE_SECONDS` later, so the ordinary path is the frontend's and an
application hears about one expiry once. The timer here is the backstop for a frontend that
never called.

Nothing in this backend can extend a grant; it is recorded here because a backend must not
assume a grant it was told about lives as long as its own `Sign` calls keep arriving.
`GrantInvalidated(o session_handle, s reason)` says why a grant stopped being usable before
it was released, and is emitted **to the session's owner alone**: a session object path
carries the owner's unique bus name, so a broadcast would tell every application on the bus
which peers hold certificate grants. `reason` is one of `expired`, `token_removed`, `policy`,
`backend_gone` or `error`, and consumers must tolerate values they do not know. A session
which never acquired a credential has no grant to invalidate: the frontend closes it without
the signal.

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

# The implementation interface — `org.freedesktop.impl.portal.experimental.Certificate`

Status: EXPERIMENTAL, and **more** unstable than the public interface, deliberately. Upstream
treats the `org.freedesktop.impl.portal.*` interfaces as an internal contract between a frontend
and the backends of the same release, versioned but not promised to applications. This one is the
same, with less of a track record and an `experimental` infix that says so on the wire.

**This interface is not for applications.** It is what xdg-desktop-portal calls on a backend it
selected — here, `xdg-desktop-portal-certificate` on bus name
`org.freedesktop.impl.portal.desktop.certificate`, object path `/org/freedesktop/portal/desktop`.

## The XML this repository ships is a copy, and it must track its source

[`../data/org.freedesktop.impl.portal.experimental.Certificate.xml`](../data/org.freedesktop.impl.portal.experimental.Certificate.xml)
is a **verbatim copy**, apart from a header comment saying so, of

```
xdg-desktop-portal, branch experimental/certificate-webauthentication, commit 703fb22
data/org.freedesktop.impl.portal.experimental.Certificate.xml
```

The interface belongs to the frontend. This repository does not get to change it, and a
divergence between the two files is not a difference of opinion — it is a backend that no longer
implements the interface it claims in `data/certificate.portal`. To update: copy the branch's file
again and change the commit id in the header.

Upstream keeps `org.freedesktop.impl.portal.*.xml` in xdg-desktop-portal itself and backends
consume it from that project's pkg-config interfaces directory —
`xdg-desktop-portal-gtk/data/meson.build` reads exactly that. This copy exists only because the
branch is unmerged and no released xdg-desktop-portal ships the file. When the branch lands, the
copy is deleted and the file comes from the interfaces directory like every other backend's.

The public interface applications call is [PUBLIC-INTERFACE.md](PUBLIC-INTERFACE.md), which is
itself a pointer to the branch. Which side is responsible for what is the table in
[ARCHITECTURE.md](ARCHITECTURE.md#who-does-what). What is left before any of this could be a pull
request is [UPSTREAMING.md](UPSTREAMING.md).

## The conventions, all borrowed

Every one of these is xdg-desktop-portal's, and none of them is an improvement on it:

- **Interactive methods take `handle`, `session_handle`, `app_id` and `parent_window`, and return
  `(u response, a{sv} results)`.** The frontend picks the `handle` path; the backend exports an
  `org.freedesktop.impl.portal.Request` there for the duration of the interaction. Compare
  [`org.freedesktop.impl.portal.Usb.AcquireDevices`](https://github.com/flatpak/xdg-desktop-portal/blob/main/data/org.freedesktop.impl.portal.Usb.xml).
- **The app id is an argument.** The backend never derives it, never asks the bus who is calling,
  never reads `/proc`. If it did, the answer would be "xdg-desktop-portal".
- **The impl `Request` has `Close()` and no `Response` signal.** The result comes back as the
  method's return value. Exactly one object — the frontend's `Request` — is responsible for the
  at-most-one-terminal-response rule.
- **Long-lived state hangs off an `org.freedesktop.impl.portal.Session`** at the path the
  frontend chose, with `Close()` and `Closed`.
- **Backends declare themselves in a `.portal` file** and are selected by `portals.conf`, per
  [writing a new backend](https://flatpak.github.io/xdg-desktop-portal/docs/writing-a-new-backend.html)
  and [portals.conf](https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html).

## Methods

| Method | Shape | Notes |
|---|---|---|
| `CreateSession(o handle, o session_handle, s app_id, a{sv} options) → (u, a{sv})` | non-interactive | Creates the backend-side state for a grant. `options` is unused and `results` is empty. Fails early when there is no p11-kit, no reader, no display. |
| `AcquireCredential(o handle, o session_handle, s app_id, s parent_window, a{sv} options) → (u, a{sv})` | **interactive** | Discovery, filtering, and **the chooser**. |
| `Sign(o handle, o session_handle, s app_id, s parent_window, a{sv} options) → (u, a{sv})` | **interactive** | The signature, and the PIN prompt if this is the first private-key use. |
| `Decrypt(...)` | **interactive** | As `Sign`, with `ciphertext` in place of `data` and `plaintext` in place of `signature`. Not in v1. |
| `GetCapabilities(s app_id, a{sv} options) → a{sv}` | non-interactive | What this backend can do on this hardware. **Note the `app_id`** — see below. |
| `TokenAdded(a{sv})`, `TokenRemoved(a{sv})` | signals | To the frontend. The frontend decides who else hears. |
| `SessionInvalidated(o session_handle, s reason)` | signal | The hardware behind a grant went away: `token_removed`, `device_error`, `backend_shutdown`. The frontend turns it into `GrantInvalidated` and closes the Session. |

**`GetCapabilities` carries `app_id`, and that is a change** from what this repository used to
document. The old sketch had `GetCapabilities(a{sv}) → a{sv}` on both interfaces. The branch made
the impl side `GetCapabilities(s app_id, a{sv}) → a{sv}` because *every* impl call upstream carries
`app_id`; the public side is unchanged. A backend is not obliged to vary its answer by application,
but it is told which one is asking, and it is now impossible to implement the impl interface while
forgetting that the question has a subject.

**There is no `OpenPkcs11Endpoint`.** The earlier sketch had one on both interfaces, returning
`(h endpoint_fd, s certificate_uri, s private_key_uri, u endpoint_version)`. The branch left it out
of both, deliberately: an fd-returning method needs its own review, and the python-dbusmock backend
the frontend is tested against cannot produce a usable endpoint fd, so a first version with it would
have had no test. It is a follow-up. [`../src/export/facade.h`](../src/export/facade.h) still holds
the requirements, and they are still the acceptance criteria for that follow-up.

### What the frontend sends that the public interface does not have

These are the fields that exist *because* of the split, and they are the reason it is worth its
cost:

| Key | Why |
|---|---|
| `app_id` | Established by the frontend from `xdp_invocation_get_app_info()`. Empty string when unidentified. |
| `app_identity_level` | `verified_sandboxed` \| `derived_host` \| `unidentified`. **The backend must display this.** An application name shown without saying how it was established is a lie by omission. |
| `lifetime` | Seconds the frontend has *decided* to allow, after applying its 3600 s ceiling — not the caller's `requested_lifetime`. |
| `preselect_certificate` | A stable certificate id the frontend read from the permission store. Preselection only. |

**And two fields that are gone.** `app_display_name` is not on the branch interface: the backend
gets an app id and an identity level, and any human-readable name is its own to derive or to omit.
`context` — the destination-host hint — is not on either interface: the only caller-supplied text
that reaches a backend is `reason`.

### What the backend returns that the frontend does not simply pass on

`certificate_id` (the key a permission-store entry would use) and `remember_selection` (what the
user said). The frontend decides whether to store anything, in its `certificate` permission table
keyed on the app id, because the app id is the frontend's. A backend never writes the permission
store.

The frontend also **intersects** everything else: `supported_mechanisms` against its allow list
(`RSA_PKCS1_V1_5`, `RSA_PSS`, `ECDSA`), `permitted_operations` against what the purpose permits,
and `expires_at` is not the backend's to send at all — it is frontend-generated. A backend that
returns more than it was allowed to does not get more; it gets clamped, and the branch has a test
for exactly that (`test_backend_results_are_clamped`).

## What the XML left ambiguous, and how this backend resolved it

The interface XML and the python-dbusmock backend it is tested against are an executable
specification of the *shape* of every call. They are silent on several things a real backend has to
decide, because a mock that returns `b"signature"` never had to. Each of these is a decision this
repository made and can be argued with; each is here so that arguing with it does not require
reading the source.

### `data` is always the digest, and `parameters.hash` is required

The public XML says `data` is "the digest or the message, as the mechanism requires" and stops
there. This backend resolves it one way, for every mechanism:

- **`data` is the bare digest.** Never a message, never a pre-built `DigestInfo`.
- **`parameters.hash` is required** and names which digest it is: `SHA1`, `SHA224`, `SHA256`,
  `SHA384` or `SHA512` (`SHA-256` is accepted as a spelling of `SHA256`).
- A digest whose length is not the one that hash produces is **refused**, not signed.
- For `RSA_PKCS1_V1_5` the backend builds the RFC 8017 `DigestInfo` around the digest itself and
  calls `CKM_RSA_PKCS`. For `RSA_PSS` it builds `CK_RSA_PKCS_PSS_PARAMS`. For `ECDSA` it passes the
  digest through, which is what `CKM_ECDSA` wants.

**Why not accept a raw blob under `CKM_RSA_PKCS`.** Because that is a signing oracle over
unstructured bytes, and it is a materially larger thing for a user to consent to than a signature
over a digest of known length: with it, a caller can have the card produce a signature over
anything, including a structure that means something in a protocol nobody was thinking about.
Requiring a named hash and a matching length costs a caller one option and removes that.

The cost is that a TLS 1.1-and-earlier `CertificateVerify`, which signs a raw MD5+SHA1
concatenation with no `DigestInfo`, cannot be produced through this interface. That is not a
regression anybody will notice.

### An ECDSA signature comes back raw, unless asked otherwise

PKCS#11's `CKM_ECDSA` produces the raw `r || s` pair. X.509 and TLS want a DER `ECDSA-Sig-Value`.
The interface does not say which crosses it, and both are defensible.

This backend returns **the PKCS#11-native raw form by default**, because that is what anyone who
has used PKCS#11 expects and because silently re-encoding what the card produced is the kind of
helpfulness that hides bugs. A caller that wants the DER form asks for it:

```
parameters = {'hash': <'SHA256'>, 'signature_encoding': <'der'>}
```

`signature_encoding` is `raw` (the default) or `der`; anything else is an error rather than a
silent fallback. It is an addition to the interface's `parameters` vardict, which the frontend
passes through unexamined, so it needs no change on the frontend side — but it is an addition, and
if the interface ever grows an opinion of its own, the interface wins.

### `interaction_mode` never skips the chooser

The XML says `required` means always prompt, `allowed` means prompt if needed, and `forbidden`
means never prompt and fail instead. It does not say whether a single matching certificate, or a
`preselect_certificate` that matches one, may skip the consent window.

**It may not.** For `required` and `allowed` the chooser always opens, even with exactly one
candidate and a remembered selection. The chooser is where the application's identity, its identity
*level*, and the purpose are shown; skipping it because there was only one certificate turns a
consent dialog into a PIN dialog, which is the failure mode this project exists to end.
`preselect_certificate` preselects the row and nothing more.

For `forbidden` there is no path to a grant at all, and `AcquireCredential` answers 2. That is the
XML's own reading: consent here *is* a prompt.

### `SessionInvalidated` is emitted with `expired`

The impl XML's prose lists three reasons — `token_removed`, `device_error`, `backend_shutdown` —
and the public `GrantInvalidated` lists eight, including `expired`. The frontend forwards the
backend's string through unchanged.

This backend emits `expired` when a grant's lifetime runs out. It is not in the impl XML's list, it
*is* in the public one, and the alternative — saying `device_error` about a healthy card, or saying
nothing — is worse. **The backend enforces the lifetime too**, even though the frontend refuses an
expired grant before this backend is called: the check here is not what stops the operation, it is
what stops this process from sitting on a logged-in card session after the authorisation for it has
run out.

The other reasons are emitted as the XML has them: `token_removed` when the card leaves the reader
or a different card takes its place, `backend_shutdown` on the way out, and `device_error` is not
currently emitted at all — a device that fails mid-operation fails that operation and keeps the
grant, because the card may still be there.

### `token_display` does not carry the serial

The XML says `token_display` is "token and reader identity for display only" and does not enumerate
the keys. This backend sends `label`, `manufacturer`, `model`, `reader` and
`protected_authentication_path`, and **deliberately omits the serial number**. A card serial is a
stable hardware identifier: every application that ever obtained a grant could use it to correlate
this user across all of them, and nothing a human reads needs it — the label and the reader are what
tell two cards apart on a desk.

### `chain_der` is empty and `chain_status` is `leaf_only`

Honest rather than empty-handed: this backend reads the leaf certificate off the token and does not
go looking for intermediates, so it says `leaf_only` rather than claiming a completeness it has not
established. Building a chain from the other certificates on the token is a known gap; see
[ROADMAP.md](ROADMAP.md).

### `GetCapabilities` answers with no token present

`GetCapabilities` reports the mechanisms this backend can drive, not the ones a card in the reader
happens to support right now. With a token present the answer is narrowed to what that token
advertises; with none, the answer is the full set rather than the empty one.

Reporting nothing because the card is in the user's pocket would make every caller conclude the
feature does not exist. **`AcquireCredential` is where the absence of a card is reported**, and it
reports it honestly, distinguishing `no_token` from `no_matching_certificate` — a user needs to know
whether to insert a card or to talk to whoever issued the one they have.

### The `results` vardict carries an `error` key on failure

On a response of 2, this backend adds `error` to `results`: `no_token`,
`no_matching_certificate`, `no_such_session`, `invalid_purpose`, `invalid_filter`,
`interaction_required`, `no_display`, `device_error`, `token_removed`, `pin_locked`,
`invalid_request`, `cancelled`. **The frontend drops it**, because it passes through only the keys
it knows. It is a diagnostic for a direct impl call and for the journal, not a channel to the
application, and it must not become one: an error string is caller-visible text and the frontend is
the side that decides what applications learn.

### A certificate whose private key cannot be seen is still offered

Discovery does not log in — enumerating what is on a card must not spend the user's presence — and
on some tokens `CKA_PRIVATE` hides the private key object until it does. Where that happens the
matching **public** key stands in as proof that a key pair with that `CKA_ID` exists; where neither
can be seen and the token says `CKF_LOGIN_REQUIRED`, the certificate is offered anyway rather than
the card being reported as empty. `can_sign` and `can_decrypt` come from the private key's
`CKA_SIGN`/`CKA_DECRYPT` where it is visible, the public key's `CKA_VERIFY`/`CKA_ENCRYPT` where it
is not, and the certificate's key usage as a last resort — which is why the grant re-checks
everything at `Sign` time against the key it actually opened.

### PIV slots are best effort, and a filter that names one is strict

`piv_slot` is derived from `CKA_ID`: `0x9a`/`0x01` is `authentication`, `0x9c`/`0x02` is
`signature`, `0x9d`/`0x03` is `key_management`, `0x9e`/`0x04` is `card_authentication`. Anything
else yields no slot rather than a guess. A `certificate_filter` that names a slot therefore does
**not** match a certificate whose slot could not be determined: guessing would offer the wrong key,
and a caller that asked for the signature slot and got the authentication one has been lied to.

## Why an application cannot call this

This is the question a reviewer asks first, and the honest answer has three parts.

**1. The mechanism upstream actually relies on.** The impl bus names are not something an
application has any reason to hold, they are not proxied into sandboxes by the portal machinery,
and a Flatpak's D-Bus policy does not grant them: a sandboxed application talks to
`org.freedesktop.portal.Desktop` through the proxy and cannot see
`org.freedesktop.impl.portal.desktop.certificate` at all. This is now literally the same mechanism
upstream relies on, rather than an analogue of it under our own names.

**2. The check this backend adds on top.** Every impl method compares the sender against the
unique name that currently owns `org.freedesktop.portal.Desktop`, and refuses anything else with
`org.freedesktop.DBus.Error.AccessDenied`, logged by reason code
([`../src/certificate-impl.h`](../src/certificate-impl.h),
`certificate_impl_sender_is_frontend`). The owner is *watched* rather than asked per call, so the
comparison in every handler is a string compare and not a round trip; when nothing owns the name,
every method is refused, because with no frontend on the bus there is nobody who may legitimately
call. When the frontend goes away, every grant goes with it and every card session is closed.
Upstream backends do not all do this. It is cheap, and the failure it prevents — an unsandboxed
application calling `AcquireCredential` with an `app_id` of its own invention, and getting a consent
dialog that names somebody else — would destroy the entire consent model rather than degrade it.

**3. What none of that fixes.** On a conventional desktop, an unsandboxed process running as the
user may be able to interfere with either process by means that have nothing to do with D-Bus
names: `ptrace`, environment manipulation, runtime files, input injection. The split does not
change that, and [SECURITY.md](SECURITY.md) says so in the same words it used before the split.
What the split *does* fix is the case that used to be unfixable: one service both deriving an
application's identity and drawing the window that asserts it.

A deployment that wants more can add a D-Bus policy rule denying this backend's name to everything
but the portal's uid. That is not in v1; it is recorded here so that "we could tighten this" is
written down rather than assumed.

## What the backend must never do

Repeated here because it is the whole contract:

- **Derive the caller's identity.** It arrives as an argument.
- **Decide policy.** Purpose validity, lifetime ceilings, operation sets, rate limits: frontend.
- **Write the permission store.** The key is the app id.
- **Widen anything.** A backend returns what it can do; the frontend decides what is allowed.
- **Trust the caller directly.** The only legitimate caller is xdg-desktop-portal, and it is checked.
- **Edit the interface XML in `data/`.** It belongs to the frontend.

And what it must always do: display the app id **with** its identity level, render the purpose in
its own words, keep the caller-supplied `reason` out of the trusted identity position, and
re-validate every mechanism and parameter even though the frontend already did. Two checks against
a hostile caller is the correct number.

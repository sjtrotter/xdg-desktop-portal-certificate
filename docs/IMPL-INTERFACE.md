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
xdg-desktop-portal, branch experimental/certificate-webauthentication, commit 7635aa8
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
| `Decrypt(...)` | **interactive** | As `Sign`, with `ciphertext` in place of `data` and `plaintext` in place of `signature`. `RSA_OAEP` only — see "Decrypt is RSA_OAEP, and nothing else" below. |
| `GetCapabilities(s app_id, a{sv} options) → a{sv}` | non-interactive | What this backend can do on this hardware. **Note the `app_id`** — see below. |
| `TokenAdded(a{sv})`, `TokenRemoved(a{sv})` | signals | To the frontend, which re-emits them to every client. **Presence only**: see "The token signals carry presence, not identity". |
| `SessionInvalidated(o session_handle, s reason)` | signal | A grant can no longer be honoured. `reason` is one of the interface's eight and nothing else: see "`SessionInvalidated` speaks the public vocabulary". The frontend turns it into `GrantInvalidated` and closes the Session. |

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
| `allow_selection_memory` | Whether the backend may offer to remember this selection. The **effective** value: the application asked for it *and* the identity level is not `unidentified`. |

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
silent fallback. It began as this backend's own addition to the `parameters` vardict, which the
frontend passed through unexamined. **It is now in both XML files**, with `raw` as the documented
default and a requirement that a backend implementing ECDSA implement both — the frontend
validates the enum value as well. The interface grew the opinion, and it agrees with what was
here.

### `RSA_PSS` takes `mgf` and `salt_length`, spelled the interface's way

Neither can be checked without the modulus size, so the frontend forwards both untouched and this
backend is where they are validated:

- **`mgf` (`s`)** is `MGF1-<hash>`, for example `MGF1-SHA256`. Plain `MGF1` means MGF1 over
  `hash`, and so does leaving the key out. Anything else is an error. A bare hash name — `SHA256`
  — used to be accepted here as well; it was leniency the interface does not describe and a second
  backend would not implement, so a caller relying on it would have found its requests refused
  elsewhere. It is now refused here too.
- **`salt_length` (`u`)** defaults to the digest's length, and is checked against RFC 8017 9.1.1
  step 3: `emLen >= hLen + sLen + 2`.

The `mgf` spelling was added to both XML files on the frontend branch, because a value that goes
straight into a PKCS#11 mechanism parameter is not a good thing for each backend to name for
itself.

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

### `SessionInvalidated` speaks the public vocabulary

The impl XML used to list three reasons — `token_removed`, `device_error`, `backend_shutdown` —
where the public `GrantInvalidated` lists eight. The frontend does not translate: it forwards the
backend's string through unchanged, so the smaller list was a trap in both directions. `expired`,
the ordinary case, was not in it; `backend_shutdown` was in it and is not a value any application
has ever been told about. The impl XML now carries the public list verbatim:

> `released`, `expired`, `token_removed`, `owner_gone`, `policy`, `service_shutdown`,
> `backend_gone`, `error`

**A value outside it is a `g_critical()` and goes on the bus as `error`.** The list is in
`src/session-impl.c`, checked in `certificate_impl_session_invalidate()`, because a typo in a
string literal is otherwise a word applications receive as though it were part of the contract.

What this backend actually emits, and when:

| Reason | When |
|---|---|
| `token_removed` | the card leaves the reader, or a different card takes its place, or a login fails because the token is gone |
| `expired` | the grant's lifetime ran out. **The backend enforces it too**, even though the frontend refuses an expired grant before this process is called: the check here is not what stops the operation, it is what stops this process sitting on a logged-in card session after the authorisation for it has run out |
| `owner_gone` | `org.freedesktop.portal.Desktop` changed hands and the grant belonged to the previous owner. A grant belongs to the frontend connection that created it; a replacement portal must not inherit a logged-in card session it never asked for |
| `service_shutdown` | this backend is exiting. It was spelled `backend_shutdown`, which is in neither vocabulary |

The other four are not this backend's to emit. `released` and `policy` are frontend decisions,
`backend_gone` is what the frontend says *about* this process, and `error` is the fallback above.
`device_error` is gone from the interface and was never emitted anyway — a device that fails
mid-operation fails that operation and keeps the grant, because the card may still be there.

**One case is deliberately silent.** When the portal name loses its owner altogether, every grant
is still closed and the card session released, but nothing is emitted: there is no longer anybody
subscribed to hear it.

### `Decrypt` is `RSA_OAEP`, and nothing else

`Decrypt` was refused outright until the frontend branch grew a decryption mechanism. It now has
one, and only one, and this backend implements exactly that.

**Why v1.5 is not on the list.** `C_Decrypt` under `CKM_RSA_PKCS` answers "padding valid, here is
the plaintext" or "that failed" — two outcomes that are distinguishable on the wire. Against a key
the user consented to once, repeated, that is Bleichenbacher's attack: it recovers plaintext and
can forge a signature with the same key, for as long as the grant lasts, with no further consent
and no rate limit on either side of the boundary. `Sign` is deliberately constrained to a digest of
a named length so that it cannot be a signing oracle; letting `Decrypt` hand over the equivalent
capability through a different door would make that constraint decorative. The impl XML says a
backend **must not implement v1.5 decryption behind some other mechanism name either**, and the one
branch in `src/broker/mechanism.c` that decrypts accepts one name.

**The parameters**, validated here against the key rather than forwarded, because `pParameter` goes
straight into the module:

| Key | |
|---|---|
| `hash` (`s`) | Required. `SHA1`, `SHA224`, `SHA256`, `SHA384` or `SHA512`; the `SHA-256` spelling too. Becomes `CK_RSA_PKCS_OAEP_PARAMS.hashAlg`. |
| `mgf1_hash` (`s`) | Optional, and must name the same hash. PKCS#1 allows them to differ; this interface does not. `mgf` is `CKG_MGF1_<hash>`. |
| `label` (`ay`) | Optional, at most 256 bytes — the frontend's cap, applied again here so a request it accepted is not refused for a reason it could have applied itself. `source` is `CKZ_DATA_SPECIFIED` with the label, or with nothing, which is the empty label OAEP defaults to. |

**The ciphertext must be exactly one modulus long.** It is the only length an RSA ciphertext can
have, and the frontend cannot check it, because it does not know the modulus size. This is the same
class of check as the PSS salt.

**Every other failure is one error.** The module distinguishes a malformed encoding from wrong
parameters from a device fault; the caller is told "the decryption failed", in the same words, every
time, and the real reason goes to the journal. OAEP is not a padding oracle the way v1.5 is, but
that is a property of OAEP rather than of this code, and it survives only as long as nobody rebuilds
the distinction by hand. This equalises the *answer*, not the time it took to produce it — nothing
here can equalise a card's timing.

**A grant buys 32 decryptions.** Every practical attack on RSA decryption — padding oracles, fault
injection, timing — needs thousands to millions of queries against one key, and nothing on either
side of the portal boundary counts them. Real use of a card decryption key is unwrapping: one
`C_Decrypt`, occasionally a handful when a client retries or a message has several recipients.
Thirty-two is far above that and four orders of magnitude below what an attack needs. It is charged
per *attempt*, not per success — a failed decryption is exactly the query an attacker wants — and it
is per grant rather than per unit time on purpose: re-consenting is what buys more, and a user who
is asked again is a user who finds out. The number is
`CERTIFICATE_MAX_DECRYPTS_PER_GRANT` in `src/session-impl.h`.

**`GetCapabilities` now reports `decrypt`** alongside `sign`. Whether a *particular* card can do it
is a separate question, answered by `mechanisms` — `RSA_OAEP` appears there only where a token
really has `CKM_RSA_PKCS_OAEP` — and, per grant, by `permitted_operations`, which is the key's
`CKA_DECRYPT` intersected with the caller's `operation_policy`.

**What is not covered by an automated test.** SoftHSM 2.x implements OAEP with SHA-1 and no label
and refuses everything else at `C_DecryptInit`, so the round-trip test in
`tests/test-broker-device.c` runs SHA-1 without a label; the SHA-256 mapping and the label are
asserted against `CK_RSA_PKCS_OAEP_PARAMS` in `tests/test-mechanism.c` instead, and the labelled
half of the round trip skips itself with a message. A real card is
[TESTING.md](TESTING.md) tier 3.

### `email` is the one purpose that does not end in a signature

`certificate_purpose_matches()` in `src/tokens/filter.c` used to require `can_sign` for **every**
purpose, `email` included, on the reasoning that every purpose here ends in a signature. That is
true for `client_auth`, `signing` and `ssh`, and false for a certificate whose only role is
unwrapping mail: a PIV "key management" certificate, `keyEncipherment` with no `digitalSignature`,
backed by a private key that will decrypt and never sign. Such a certificate matched **no purpose
at all**, so an email client asking for `email` in order to decrypt an incoming message could
never be offered it — even though brokered `Decrypt` (`RSA_OAEP`, above) is exactly the operation
it would need. Belgian and Estonian eID cards are laid out the same way as PIV here.

**The rule now**, settled on the frontend branch's public XML first
(`7635aa8 certificate: Let email cover a decryption-only certificate`) and implemented here:

- a certificate matches `email` when its extended key usage permits `emailProtection` — or it
  carries no extended key usage extension at all — **and** its key usage permits either
  `digitalSignature` or `keyEncipherment`;
- which of the two it matched decides which operations it can serve: signing, decryption, or both;
- it is offered only if one of those operations is one the request's `operation_policy` permits,
  so a decrypt-only certificate reaches an application that asked to decrypt and nobody else;
- and because such a certificate's key will not sign, the grant's `permitted_operations` holds
  `decrypt` alone.

`client_auth`, `signing` and `ssh` are unchanged and still require a key that will sign.

The purpose vocabulary was kept at four rather than gaining `decrypt` or `email_decrypt`: the
consent sentence the user reads is "use a certificate for mail" either way, and the sign/decrypt
split already exists in `operation_policy`, which is where an application states it.

Two consequences inside this repository. `certificate_purpose_operations()` returns the set rather
than a yes/no, which is what lets `--list-tokens` print `email (decrypt only)`. And the key usage
now restricts what the *card* claims: a token that sets `CKA_SIGN` on every key it holds cannot
turn a key-management certificate into a signing credential.

### The token signals carry presence, not identity

`TokenAdded` and `TokenRemoved` send `token_id` (`s`) and `protected_authentication_path` (`b`),
and nothing else — the two keys the interface names, and no third key even for a frontend that
would discard it, because the next frontend might not. `token_id` is a SHA-256 over the token's
stable attributes salted with a value this process generates at startup and never publishes:
stable for as long as the token is present, stable enough to pair an insertion with its removal,
and **not derivable from the card**, which the interface requires in as many words. A serial, or a
hash of one another party can recompute, would be a correlation handle across every application on
the bus.

The reason is the audience. The frontend re-emits these signals on its own public interface, to
**every client on the bus**, before anybody has consented to anything. On PIV
deployments a token label is routinely the cardholder's name, an EDIPI or an issuing agency — which
is exactly the correlation the serial is withheld to prevent, delivered to a strictly larger
audience than `token_display`, which goes only to the application that obtained a grant. The full
`token_display` still goes there, in the `AcquireCredential` results.

Gating or filtering the public signal is the frontend's half of this; it is on that branch's list.

### A session is bound to its app id, and its identity level may not rise

`AcquireCredential`, `Sign` and `Decrypt` all compare `app_id` against the one the session was
created with and answer `2` / `no_such_session` when they differ. The frontend enforces session
ownership too, and that is the point: it is the check this backend can make for free, and a
frontend regression or a second frontend implementation would otherwise turn a session handle into
cross-application key use.

`app_identity_level` is recorded on the session at the first `AcquireCredential` and may **fall** —
the frontend can legitimately know less about a caller later — but never **rise**. A session
created for an unidentified caller does not become a session for a verified one because a later
call said so.

### Options are validated strictly, and defaults apply only to absent fields

A field that is **present with the wrong type**, an unknown value for an enumerated field, or an
unknown key in `operation_policy`, `certificate_filter` or `parameters` is refused with `2` /
`invalid_request` (or `invalid_filter`). It used to be treated as absent, which meant an unknown
`interaction_mode` became "prompting is allowed", a mistyped `certificate_filter` stopped filtering,
and a `lifetime` of the wrong type became 300 seconds.

**Unknown keys at the top level are still ignored**, deliberately: that is where the frontend adds
fields, and a backend that refused them could not be upgraded past. Unknown keys in the three nested
dictionaries above are refused, because a key nobody understood may have been the one that said
"less".

### `Session.Close()` is idempotent, and a session path can be used again

`SessionInvalidated` leaves the Session skeleton **on the bus**. The frontend answers that signal
with `Session.Close()` and returns its result to the application, so a backend that had already
unexported the object turned a clean close into `UnknownObject`.

The frontend's session paths are built from the caller's unique name and its
`session_handle_token`, and applications pass a fixed token — so the same application gets the same
path every time. A closed entry left in the table therefore made every later `CreateSession` from
that application fail for the life of the backend process. A **closed** session at a path is now
replaced; a **live** one is still refused.

### A second `AcquireCredential` on a live session rebinds the device

The interface does not forbid it and the frontend does not refuse it: an application may ask again
on a session handle it already holds, and the user may choose a different certificate. The backend
therefore has to treat the grant, not the session, as what the open token session belongs to.

It does: the open `CertificateDevice` remembers the candidate it was opened for, and the next
operation that finds a different one **logs out, closes the PKCS#11 session and opens a new one** —
so the login does not carry over, the private key handle does not carry over, and the first
operation after the re-grant shows a PIN window again. That is not a nicety. Reusing the open
session meant the frontend was handed certificate B's DER and the next `Sign` went to certificate
A's key, with no prompt: a signature that does not verify against the certificate the portal
returned, produced silently. If the new grant is on a *different token*, the operation would have
been submitted to the first token's session entirely.

`remember_selection` and the decryption budget are reset by the re-grant, and the lifetime timer
restarts. `tools/certificate-e2e.py --regrant <key algorithm>` drives the whole thing and checks
the second signature against the second certificate; `tools/ui-smoke.sh` runs it with the windows.

### Selection memory is offered only where it cannot lie

The frontend stores a remembered selection only when the application passed
`allow_selection_memory` *and* the caller's identity level is not `unidentified`. It now forwards
that decision as `allow_selection_memory` (`b`) in the impl `AcquireCredential` options, and the
interface says a backend **must not** offer selection memory when it is false — the frontend
discards `remember_selection` in that case, so a checkbox drawn anyway is a promise nothing keeps.

This backend draws the "use this certificate next time" checkbox only when that key is true. Two
notes on how it reads it:

- **Absent means false.** The key is the frontend's effective answer; a frontend that does not send
  it is one whose permission store this backend cannot reason about, and the safe reading of
  silence is that nothing would be stored. Present but not a boolean is `invalid_request`, not a
  default.
- **The identity level is checked again**, even though the frontend has already folded it in. It
  costs nothing, and this backend does not draw a "remember this for that application" checkbox on
  behalf of an application it cannot name.

The user's answer is clamped to the same condition on the way back out: `remember_selection` is
false whenever the checkbox was not offered.

The interim heuristic — offering the checkbox only when `preselect_certificate` was supplied — is
gone. It under-approximated in exactly the case that mattered, a caller that asked for memory and
did not have any yet.

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
`invalid_request`, `cancelled`, `owner_gone`, `backend_gone`. **The frontend drops it**, because it passes through only the keys
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
`certificate_impl_sender_is_frontend`). **"Every method" includes `Request.Close()` and
`Session.Close()`** on the objects this backend exports at the paths the frontend chose: those
paths are guessable, and a `Session.Close()` from a stranger logs the card out and destroys a
grant.

The owner is **resolved from the bus** with `GetNameOwner` before any sender is *accepted*, never
taken from the name watcher's cache: D-Bus does not order `NameOwnerChanged` against the messages of
the process that lost the name, so a former frontend that is still connected would otherwise be
compared equal to a stale cached owner and admitted.

A **refusal** is the other way round: it is decided from the cached owner, with no bus call at all.
The asymmetry is deliberate. Anything on the session bus can send this backend a message, and a
synchronous `GetNameOwner` per stranger's message is a main-thread stall that an open PIN window
feels — a denial of service reached by a different door. A stranger's unique name can never equal
the cached owner's, because the bus assigns unique names and never reuses one, so a stranger never
reaches the bus call. What it costs is one refused call at the moment a replacement portal takes the
name over before this process has processed the change; the frontend retries.

The watcher is kept for what it is good at: when the name changes hands or goes away, every session
belonging to the old owner is invalidated, and every chooser and PIN window that old owner asked for
is cancelled, before the new owner is accepted.

What that still does not provide is atomicity: the answer is a snapshot, and the name can change
hands between the check and the work the call authorises. That is the ordinary check-then-use
property of every bus check; the residual risk is recorded in
[SECURITY.md](SECURITY.md#open-problems).

When nothing owns the name, every method is refused, because with no frontend on the bus there is
nobody who may legitimately call. When the frontend goes away, every grant goes with it and every
card session is closed.
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

**The bus name is not offered for replacement unless `--allow-replacement` was passed.** Every other
backend sets `ALLOW_REPLACEMENT` unconditionally, and for a file chooser that is reasonable; here it
meant any process running as the user could take
`org.freedesktop.impl.portal.desktop.certificate` with one call and become the thing the portal
calls — receiving `AcquireCredential` and `Sign` with a real app id and identity level, and drawing
the window that asks for the PIN.

D-Bus cannot authenticate a replacement. `ALLOW_REPLACEMENT` is not "let the package manager replace
me"; it is "let whoever asks next replace me", and the bus offers the current owner no way to
inspect who is asking. So the two halves are separate flags — `--allow-replacement` to be
replaceable, `--replace` to ask to replace — and **the installed `.service` file passes neither**.
An upgrade is therefore a restart: stop the old process and let D-Bus activation start the new one.
`tools/dev-stack.sh --live` passes both, which is a development loop and not a deployment recipe.
[TESTING.md](TESTING.md) §3.5 has the commands.

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

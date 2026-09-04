# 2. The PIN prompt belongs to the service

Date: 2026-09-03
Status: accepted (for the sketch)

> **Note, after [0008](0008-build-to-the-upstream-shape.md):** "service-owned" now means
> **backend-owned**. The PIN prompt is drawn by `smartcard-portal-gtk`, in the process that holds
> the PKCS#11 session, and the frontend cannot see a PIN because it has neither a window nor a
> token session. Everything below is unchanged in substance: the point was always that the prompt
> belongs to the system rather than to the application asking, and that a second desktop needs a
> second implementation rather than a fork — which is now a second *backend package* selected by
> `portals.conf`.

## Context

The PIN prompt is the moment a person authorises a hardware token to act as them. On Linux it is
drawn by whichever application happens to need it, which means it looks different every time, is
drawn by the party asking for the authorisation, and is therefore trivially imitable. A user cannot
learn to trust a window that never looks the same twice.

Three precedents matter.

**GNOME's gcr system prompter.** [gcr](https://gitlab.gnome.org/GNOME/gcr) provides `GcrPrompt`,
`GcrSystemPrompt` and the implementor-side `GcrSystemPrompter`, communicating over a D-Bus interface
(`org.gnome.keyring.Prompter`, with a `.service` file activating `gcr-prompter`). gnome-keyring uses
it, and both gnome-shell and `gcr-prompter` implement the prompter side. It is a genuine precedent
for a **system-owned, system-modal prompt whose implementation is separable from the thing needing
it** — and it is GNOME's, shaped around gnome-keyring's needs, with no KDE equivalent.

**Windows and macOS.** The Base CSP / smart card KSP layer owns PIN entry and caching on Windows;
CryptoTokenKit and the Keychain own it on macOS. In neither case does the application see the PIN,
and in neither case does the application draw the prompt.

**Remmina's RDP plugin.** The working prior art this project builds on had to draw its own PIN
prompt, because there was nothing to delegate to — and it did the hard parts right: the PIN bound to
one challenge, one engine-initiated retry and no more, expiry, never logged, never retained. That is
the behaviour to keep and the situation to end.

## Decision

**This service draws its own chooser and its own PIN prompt, and does not implement or impersonate
`org.gnome.keyring.SystemPrompter`.**

- The PIN exists only inside this service. It never crosses D-Bus in either direction, never enters
  a `GVariant`, a `GError`, a URI, or a log.
- **No `pin-value` or `pin-source` appears in any PKCS#11 URI this service emits**, ever.
- The buffer is wiped on every exit path and lives in locked memory where the platform allows.
- **Login is lazy**: the service logs into its **own** session at first private-key use, not at grant
  time. Across a PKCS#11 forwarding boundary, login state does not transfer anyway
  ([0006](0006-failure-modes-of-naive-p11kit-forwarding.md)); on the facade, a consumer's `C_Login`
  is an authorisation-state transition carrying no PIN.
- **Protected authentication path is honoured, not emulated**: when the token sets
  `CKF_PROTECTED_AUTHENTICATION_PATH`, the login uses a null PIN, the token or reader collects the
  secret, and the service shows an instructional dialog with **no editable PIN field**.
- **A PIN prompt is not consent.** Consent is the chooser: verified caller, sandbox status, purpose
  in the service's words, certificate, token, duration, and whether later operations may happen
  silently. A design where the PIN prompt is the only user-visible moment has taught the user to type
  their PIN whenever asked.

## Alternatives considered

**Implement `org.gnome.keyring.SystemPrompter`.** Rejected. It would mean inheriting GNOME's
semantics without GNOME's maintainers, breaking when either project changed, and offering nothing to
KDE — where there is no equivalent to defer to. Citing gcr as prior art is the honest relationship,
and it is also the better argument when this is eventually proposed upstream: a second project
reaching the same shape independently is evidence the shape is right.

**Ask gnome-keyring to prompt on our behalf.** Rejected for now. It couples a cross-desktop service
to one desktop's daemon, and gcr's prompt vocabulary is built for passwords and keyrings rather than
for "this application wants to authenticate as you to this host, using this certificate, for this
long".

**Let the application draw the prompt and pass us the PIN.** Rejected absolutely. It is the status
quo, it puts the PIN in the least trustworthy process, and no amount of interface documentation
makes it safe.

## Consequences

- **Two prompts must be written and maintained** — GTK4 now, Qt/KDE for phase 2 — and they must
  agree on wording and behaviour, or the consistency argument collapses.
- **Accessibility is an acceptance criterion**, not polish: these controls carry the security
  decision, and a dialog a screen-reader user cannot navigate cannot carry informed consent.
- **Users will see two windows** in the `webauth-service` case: the web view's security chrome and
  this service's chooser. Two independent statements of the same true thing is acceptable. Two
  windows asking for a PIN would not be.
- **We cannot promise forgetting.** Some tokens and middleware cache authentication internally.
  `C_Logout` is issued at grant end; the design never claims the card has forgotten.

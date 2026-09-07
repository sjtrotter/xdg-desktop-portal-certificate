# 9. Name it Certificate, not Smartcard, ClientCertificate or Credentials

Date: 2026-09-04
Status: accepted (for the sketch), amended by [0010](0010-backend-only-frontend-lives-upstream.md)

> **Amendment (0010).** `Certificate` is still the name, and the reasoning below is why.
> Every *fully qualified* name in this ADR is historical: the project-controlled
> `io.github.sjtrotter.*` interfaces it renamed no longer exist on either side of the
> arrow, because this repository stopped shipping a frontend or a public interface at all.
> The interface is now `org.freedesktop.portal.experimental.Certificate` /
> `org.freedesktop.impl.portal.experimental.Certificate`, defined by the xdg-desktop-portal
> branch, and the binaries are one binary, `xdg-desktop-portal-certificate`. This ADR is
> retained as the record of *why the word is "Certificate"*, which the branch adopted.

## Context

[0003](0003-own-namespace-before-freedesktop.md) flagged, before a line of the frontend/backend
split existed, that the interface's device-derived name was "probably wrong": the conceptual
boundary this broker mediates is a certificate-backed private key, and the backing key might live
on a smart card, in a TPM, in a software token, on a phone, or behind a remote HSM. Naming a portal
after one physical device it can serve is exactly the pattern that ages badly the day a second
device type is the more common one.

That was a prediction. It has now come due for a concrete reason: [0008](0008-build-to-the-upstream-shape.md)
gave this project's frontend and the sibling `entra-token-helper` project's frontend each their own
incubating bus name, which forced writing down, in full, what each name actually claims to mediate.
Doing that made the old name's mismatch impossible to keep deferring — the interface's `purpose`
enum already listed `client_auth`, `signing`, `email` and `ssh`, none of which is "insert a card,"
and the chooser, the PIN prompt, the brokered `Sign`, and the synthetic PKCS#11 facade all operate
on whatever PKCS#11 token is present, not specifically a smart card.

## Decision

Rename the interface, project-wide:

- `io.github.sjtrotter.portal.Smartcard1` → `io.github.sjtrotter.portal.Certificate1`
- `io.github.sjtrotter.impl.portal.Smartcard1` → `io.github.sjtrotter.impl.portal.Certificate1`
- the binaries, `smartcard-portal-frontend` / `smartcard-portal-gtk` →
  `certificate-portal-frontend` / `certificate-portal-gtk`
- the per-half header each binary is built around, `smartcard.h` → `certificate.h`
- the data directory used for `.portal` file and `portals.conf` lookup,
  `${datadir}/smartcard-portal/portals` → `${datadir}/certificate-portal/portals`
- the eventual upstream destination named in [UPSTREAMING.md](../UPSTREAMING.md):
  `org.freedesktop.portal.Smartcard` / `org.freedesktop.impl.portal.Smartcard` →
  `org.freedesktop.portal.Certificate` / `org.freedesktop.impl.portal.Certificate`

## Why `Certificate` and not the alternatives

**Why not keep naming it after the hardware.** Because the broker already does not care where the
key lives. It mediates certificate-backed key operations — selection, brokered signing, and
(behind the experimental facade) a scoped PKCS#11 view — regardless of whether the credential
turns out to be a PIV card, a TPM-resident key, a software-protected key store, or eventually
something with no card-shaped hardware in it at all. A name that says "smart card" makes every one
of those other cases look like an exception to the interface's own name, when they are exactly what
it was designed to cover from [0006](0006-failure-modes-of-naive-p11kit-forwarding.md) onward.

**Why not `ClientCertificate`.** It describes exactly one of the four supported purposes. `signing`,
`email` and `ssh` are not TLS client authentication, and a caller asking this interface to sign an
email or authorize an SSH connection would be reaching through a name that only advertises the
narrowest of the four. The interface's own `purpose` enum already disproves the narrower name.

**Why not `Credentials`.** It is the most tempting alternative, and it is taken: the
[linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) project is
already proposing a credentials portal for FIDO2 and passkeys [[S44](../SOURCES.md)] — the name
under discussion upstream is `org.freedesktop.portal.experimental.Credentials`
[[S27](../SOURCES.md)] — referenced
repeatedly in this repository's own documents ([0003](0003-own-namespace-before-freedesktop.md),
README "Relation to xdg-desktop-portal", [ROADMAP.md](../ROADMAP.md) phase 3). Shipping our own
`io.github.sjtrotter.portal.Credentials` would collide with that name in exactly the namespace
squatting sense [0003](0003-own-namespace-before-freedesktop.md) already argues against for
`org.freedesktop.*` — and would misrepresent this interface as a peer of a FIDO2/passkey broker
rather than what it actually is, which is plausibly a credential *type* that could live *under*
that broader proposal once the conversation with its maintainers happens. That conversation is
still phase 3, not this ADR; see [0003](0003-own-namespace-before-freedesktop.md), "The order of
conversations."

**`Certificate`**, by contrast, names the artifact the broker actually hands back — a certificate,
its chain, and the operations its key permits — without claiming a device or overclaiming a
category that already belongs to somebody else's proposal.

## The repository name

**Update, 2026-09-04.** The GitHub repository was renamed `xdg-desktop-portal-certificate` to
match the binary. The paragraph below is the record of the original decision to defer that
rename; it no longer describes the current state.

The git repository stayed `smartcard-portal` at first. That was a directory name and a URL, not
an interface claim, and [0003](0003-own-namespace-before-freedesktop.md) already establishes the
distinction. Renaming the GitHub repository itself was a separate decision, was the author's call
to make on its own schedule, and was not decided by this ADR. Places in this repository's own
prose that genuinely mean the physical hardware — "a private key on a smart card," "a PIV smart
card" — keep that wording; only the interface, the binaries, the header and the data directory
changed names here.

## Consequences

- Every doc, XML comment, build file and C identifier that named the interface, the binaries or the
  lookup directory after the device now names it after the certificate instead; the mechanical
  mapping is in [UPSTREAMING.md](../UPSTREAMING.md).
- [0003](0003-own-namespace-before-freedesktop.md)'s prediction is resolved, not superseded: its
  actual subject — that the *namespace* stays project-controlled regardless of what the `<Name>`
  slot says — is unchanged by this rename.
- The sibling `xdg-desktop-portal-webauth` repository (renamed from `entra-token-helper` on
  2026-09-06) follows this rename in lockstep in its own
  cross-repository references — `client_cert_portal.h`, its own ADR 0007 and ADR 0008, its README —
  as a parallel change in that repository, not something this ADR needs to detail further.
- **`Certificate` is still an incubation name.** [0003](0003-own-namespace-before-freedesktop.md)'s
  "order of conversations" still applies: whether `Certificate` is also the name an upstream
  maintainer accepts, or whether certificate-backed signing instead becomes a credential type under
  `org.freedesktop.portal.Credentials`, is a question for that conversation, not one this project
  settles by choosing a better name for itself first.

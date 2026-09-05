# 3. A project-controlled namespace, and a name that is expected to change

Date: 2026-09-03
Status: accepted (for the sketch), amended by [0010](0010-backend-only-frontend-lives-upstream.md)

> **Amendment (0010).** The namespace argument below stands; the names it chose are gone.
> This repository no longer ships a frontend or a public interface, so it no longer picks
> an interface name at all: the impl interface it implements is **dictated by the
> frontend**, which is now the xdg-desktop-portal branch
> `experimental/certificate-webauthentication`, and is
> `org.freedesktop.impl.portal.experimental.Certificate`.
>
> That is not the squatting this ADR argues against. `org.freedesktop.portal.experimental.*`
> and `org.freedesktop.impl.portal.experimental.*` are the namespace upstream **set aside
> for unfinished portals** — see [PR #1889](https://github.com/flatpak/xdg-desktop-portal/pull/1889),
> which is open rather than merged [[S27](../SOURCES.md)],
> quoted in [0010](0010-backend-only-frontend-lives-upstream.md) — and an interface in it
> carries no claim of acceptance: it is not exported at all unless the portal is started
> with `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate`, and it may change or be
> removed without a version bump. Writing an experimental portal *inside* xdg-desktop-portal
> is how upstream asks for it to be done; writing one under `io.github.sjtrotter.*` outside
> it is what this ADR was recommending instead, in the absence of that knowledge.
>
> The backend's own bus name, `org.freedesktop.impl.portal.desktop.certificate`, follows the
> ordinary out-of-tree backend convention (`org.freedesktop.impl.portal.desktop.<backend>`,
> as `xdg-desktop-portal-gtk` and `xdg-desktop-portal-termfilechooser` use). A backend name
> has never been a namespace claim; it is how the frontend activates a backend.
>
> What survives unchanged is this ADR's actual subject: **a name is not an acceptance**,
> the rename is still expected, and "the order of conversations" below — talk to the
> credentials people before freezing anything — is still the ordering constraint.

## Context

The temptation is to ship `org.freedesktop.portal.Certificate` immediately. It reads as legitimate, it
is what applications would eventually call, and it saves a rename.

It is also a claim of ownership and acceptance that does not exist. The
[D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names)
recommends a reverse-domain namespace the project actually controls [[S42](../SOURCES.md)], and
xdg-desktop-portal's
namespace belongs to xdg-desktop-portal. Squatting it means either the eventual real interface
collides with a prototype, or the prototype's mistakes become the standard by accident.

There was also a second problem: this interface's first name, chosen for the sketch's original
smart-card-only incarnation, named the hardware rather than the capability, and a portal named
after a physical device is exactly the pattern that ages badly once the same broker turns out to
mediate keys on a TPM or a software token just as well. [0009](0009-name-it-certificate.md)
resolved that specific problem by renaming to a capability-scoped interface name. What is
unresolved, and is this ADR's actual subject, is the *namespace*: whichever name we pick stays
project-controlled until an upstream maintainer accepts it, because that acceptance isn't ours to
claim in advance. The credentials/FIDO2 maintainers are, separately, unlikely to want one portal
per device type at all — see "The order of conversations" below.

## Decision

Ship **`io.github.sjtrotter.portal.Certificate1`** — and, since
[0008](0008-build-to-the-upstream-shape.md), its private counterpart
**`io.github.sjtrotter.impl.portal.Certificate1`** — on the bus name
`io.github.sjtrotter.portal.Certificate` at `/io/github/sjtrotter/portal/Certificate`, with the major
version in the interface name, from a domain the author controls.

The `portal` and `impl.portal` infixes mirror `org.freedesktop.portal.*` and
`org.freedesktop.impl.portal.*` position for position, which is the point: the *shape* is copied so
that the mapping in [UPSTREAMING.md](../UPSTREAMING.md) is mechanical, while the *namespace* stays
one the project actually controls. Mirroring a naming scheme inside your own domain is not
squatting; putting `org.freedesktop.` in front of it would be.

Copy the `org.freedesktop.portal.Request` and `org.freedesktop.portal.Session` patterns closely — handle token, precomputable
object path, `Close()` rather than a bespoke `Cancel`, one terminal `Response`, the three response
codes — because that pattern is correct and callers already know it. **Copying a pattern is not
claiming a namespace.**

Document, in the README, the XML and here, that the name is an **incubation name expected to
change**, and that the likely destination is not a device-named portal at all.

## The order of conversations

The acceptance path in [ROADMAP.md](../ROADMAP.md) phase 3 has one ordering constraint that matters
more than the rest: **talk to the credentials people before freezing anything.**

The [linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) project is
already proposing a credentials portal for FIDO2 and passkeys — a D-Bus service and reference UI
mediating authenticator access for sandboxed applications [[S44](../SOURCES.md)]. The name
actually under discussion upstream is `org.freedesktop.portal.experimental.Credentials`, on
PR #1889 [[S27](../SOURCES.md)]; `org.freedesktop.portal.Credentials` is where it would land, not
where it is. Certificate-backed signing
is plausibly a **credential type** under that proposal, sharing its request, identity and consent
machinery, rather than a rival portal beside it. The specific question to ask is exactly that, and it
should be asked before any name or signature is frozen.

The expectation should be that maintainers prefer a coherent credential-use model to a portal named
after hardware; that `ClientCertificate` or `CryptographicCredential` is the better boundary; and
that "return a PKCS#11 module" will not be accepted as the generic credential abstraction — which is
one more reason [0007](0007-brokered-operations-are-the-core.md) makes brokered operations the core.

## Consequences

- **A rename is expected**, not merely possible, and every consumer must be prepared for it. The
  version suffix means the change can be made without breaking a running system.
- Early adopters get an unstable interface, clearly labelled — which is honest, and which is why
  `webauth-service` keeps an internal adapter around its use of this one.
- The freedesktop conversation, when it happens, is about a design with an implementation and
  consumers behind it rather than a name.
- The repository directory was called `smartcard-portal` at first; the GitHub repository was
  renamed `xdg-desktop-portal-certificate` on 2026-09-04, see
  [0009](0009-name-it-certificate.md).
- **The interface itself was later renamed**, from its original hardware-derived name to a
  capability-scoped one; see [0009](0009-name-it-certificate.md). This ADR's argument about
  namespace ownership is unaffected — only the `<Name>` slot changed, not the shape.
- **The mapping is now written down rather than implied.** [UPSTREAMING.md](../UPSTREAMING.md) lists
  every interface, bus name, object path and file against what it would become upstream, and the
  handful of places where the change would be more than a rename. That document is the check on
  this one: if the mapping ever stops being mechanical, the incubating names have drifted from the
  thing they are incubating.

# 3. A project-controlled namespace, and a name that is expected to change

Date: 2026-09-03
Status: accepted (for the sketch)

## Context

The temptation is to ship `org.freedesktop.portal.Smartcard` immediately. It reads as legitimate, it
is what applications would eventually call, and it saves a rename.

It is also a claim of ownership and acceptance that does not exist. The
[D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names)
recommends a reverse-domain namespace the project actually controls, and xdg-desktop-portal's
namespace belongs to xdg-desktop-portal. Squatting it means either the eventual real interface
collides with a prototype, or the prototype's mistakes become the standard by accident.

There is a second problem, which is that **`Smartcard` is probably the wrong name**. The conceptual
boundary is a **client certificate** or **cryptographic credential**: the backing key might be a
smart card, a TPM, a software token, a phone, or a remote HSM. Naming a portal after a physical
device is exactly the pattern that ages badly, and the credentials/FIDO2 maintainers are unlikely to
want one portal per device type.

## Decision

Ship **`io.github.sjtrotter.Smartcard1`** at `/io/github/sjtrotter/Smartcard1`, with the major
version in the name, from a domain the author controls.

Copy the `org.freedesktop.portal.Request` transaction pattern closely — handle token, precomputable
object path, `Close()` rather than a bespoke `Cancel`, one terminal `Response`, the three response
codes — because that pattern is correct and callers already know it. **Copying a pattern is not
claiming a namespace.**

Document, in the README, the XML and here, that the name is an **incubation name expected to
change**, and that the likely destination is not a device-named portal at all.

## The order of conversations

The acceptance path in [ROADMAP.md](../ROADMAP.md) phase 3 has one ordering constraint that matters
more than the rest: **talk to the credentials people before freezing anything.**

The [linux-credentials / credentialsd](https://github.com/linux-credentials/credentialsd) project is
already proposing `org.freedesktop.portal.Credentials` for FIDO2 and passkeys — a D-Bus service and
reference UI mediating authenticator access for sandboxed applications. Certificate-backed signing
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
- The repository directory is still called `smartcard-portal`. It is a directory name; the README
  says so.

# 12. Follow the merged experimental-portal convention

Date: 2026-10-15
Status: accepted; supersedes in part 0003, 0005, 0009, 0010 and 0011

> Status, 2026-10-20: The active frontend is `experimental/certificate`. WebAuthentication
> development stopped on 2026-10-16. WebAuthentication and `experimental/integration`
> references and the two-interface examples below are historical.

## Context

Upstream merged experimental-portal support in PR #2129 and fixed the opt-in check in
PR #2173, included in `main` at `8eba842`. The merged convention differs from the draft
followed by ADR 0010. The Certificate frontend is on the fork's
`experimental/integration` branch.

## Decision

Use `org.freedesktop.portal.experimental.Certificate1` for the frontend and
`org.freedesktop.impl.portal.experimental.Certificate1` for the backend. WebAuthentication
uses `org.freedesktop.portal.experimental.WebAuthentication1` and
`org.freedesktop.impl.portal.experimental.WebAuthentication1`.

Export both frontend and backend interfaces at `/org/freedesktop/portal/desktop`.
Request and Session objects retain their `/request/...` and `/session/...` handle paths
beneath it.

The frontend exports an experimental portal only with a configured backend and its name
listed in `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` at startup. Values are comma separated,
with no spaces: `Certificate1` or `Certificate1,WebAuthentication1`.

Copy `data/org.freedesktop.impl.portal.experimental.Certificate1.xml` byte for byte from
the frontend branch, keeping the provenance comment block and updating its commit id. Retain one codegen run and the `org.freedesktop.impl.portal.` prefix.

## Consequences

The frontend must start with the opt-in variable in its own environment. Development
scripts preserve the caller's list and append missing names.

A breaking interface change increments the trailing number. Non-breaking changes increment
the `version` property.

The client-side PKCS#11 module and the sibling web-auth backend must follow the frontend's
names and path in step. The web-auth backend is maintained in its own repository.

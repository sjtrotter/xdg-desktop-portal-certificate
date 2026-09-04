# Security

The security model, threat model, PIN handling rules, grant scoping requirements, caller identity
model and logging rules live in **[docs/SECURITY.md](docs/SECURITY.md)**.

Three things are worth saying here, where people look first.

**This is an experimental design sketch.** Nothing is implemented. There is no attack surface yet
because there is no code yet — and correspondingly, nothing in `docs/SECURITY.md` has been reviewed
by anyone but its authors.

**The boundary this intends to provide is narrower than it sounds.** For **sandboxed** applications
it can be a strong boundary. For ordinary **host** applications it is a useful identity-and-consent
boundary. It is **not** absolute same-UID isolation, and this project must never claim otherwise: a
hostile unsandboxed process running as the user may be able to inspect other processes, manipulate
their environment, reach runtime files or inject input, depending on how the system is hardened.

**Reporting.** Once there is code, report security issues privately to the repository owner rather
than in a public issue. Until then, the most valuable report is a hole in the design — especially in
[docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md),
which exists because an independent review found that this project's founding claim was wrong. That
kind of correction is worth more than a bug.

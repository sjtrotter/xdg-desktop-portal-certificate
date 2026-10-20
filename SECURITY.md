# Security

This project is experimental and has no independent security review. The backend loads
PKCS#11 modules, displays consent and PIN prompts, holds logged-in token sessions and signs
on request. Hardware evidence covers one PIV card and reader; dated results and unrun checks
are in [docs/TESTING.md](docs/TESTING.md).

The [security model](docs/SECURITY.md) distinguishes implemented controls from requirements
and records threat assumptions, PIN handling, grant scoping, caller identity and logging.
See [the impl contract](docs/IMPL-INTERFACE.md) and
[ADR 0010](docs/decisions/0010-backend-only-frontend-lives-upstream.md).

[The threat model](docs/SECURITY.md#boundary-and-threat-model) describes sandbox containment
and the limits of protection against hostile host processes.

Email vulnerabilities privately to [Stephen J. Trotter](mailto:stephen.j.trotter@gmail.com).
Design flaws are security issues;
[ADR 0006](docs/decisions/0006-failure-modes-of-naive-p11kit-forwarding.md) records risks in
PKCS#11 forwarding.

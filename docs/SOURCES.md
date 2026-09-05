<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
-->

# Sources

Every claim this repository makes about **another system** — a specification, a library, a
protocol, an upstream discussion — is either cited here or is marked in the text as
unverified. Claims about *this* repository are not here; they are verifiable in the tree, and
[TESTING.md](TESTING.md) says how.

Each entry gives the claim as this repository states it, the primary source, what the source
actually confirms, and the date the source was read. Where the source confirms less than the
claim, or contradicts part of it, that is written down rather than smoothed over — the text
elsewhere has been corrected to match.

Line numbers in source-code citations are pinned to a commit, because branch tips move.

Checked 2026-09-05 unless an entry says otherwise.

## p11-kit

**[S1] `p11-kit server`'s unit of exposure is a token, not an object.**
[p11-kit(8), "Server" section](https://p11-glue.github.io/p11-glue/p11-kit/manual/p11-kit.html);
[`p11-kit/server.c`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/server.c#L751);
[`p11-kit/filter.h`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/filter.h#L49).
The manual: "This launches a server that exposes the given PKCS#11 tokens on a local socket. The
tokens must belong to the same module." The usage string is `p11-kit server <token> ...`; the
whole filter API is `p11_filter_allow_token()` / `p11_filter_deny_token()`, matching
`CK_TOKEN_INFO`, and `server.c` contains no object or attribute selection at all.

**[S2] p11-kit's remoting is a faithful PKCS#11 pass-through, not a policy layer.**
[p11-kit remoting manual](https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html).
"We can similarly generate, copy objects or test certificates to the card using the same
command. Any applications which support PKCS#11 can perform cryptographic operations through
the client module." The worked example generates a key over the forwarded token with `p11tool
--generate-ecc`.

**[S3] `p11-kit-client.so` finds its endpoint through process-level configuration, which cannot
express a per-request grant.**
[`p11-kit/client.c`, `get_server_address()`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/client.c#L61);
[pkcs11.conf(5), `server-address`](https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html).
**Confirms less than the claim once did.** There are three sources, not one:
`P11_KIT_SERVER_ADDRESS`, which wins and discards any other; a per-module `server-address:`
field in a `.module` file; and `$XDG_RUNTIME_DIR/p11-kit/pkcs11`. Several *statically configured*
endpoints are therefore expressible, one `.module` file each. What is not expressible is a
per-request one: the address is consumed once into a file-scope static at module
initialisation. The text in [0006](decisions/0006-failure-modes-of-naive-p11kit-forwarding.md)
and [ARCHITECTURE.md](ARCHITECTURE.md) was corrected to say that.

**[S4] p11-kit's RPC protocol carries the destructive and administrative calls, and the PIN
crosses it as a plain byte array.**
[`p11-kit/rpc-message.h`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/rpc-message.h)
— enumeration at lines 61 (`C_InitToken`), 66 (`C_InitPIN`), 67 (`C_SetPIN`), 70 (`C_Login`),
119 (`C_LoginUser`), 142 (`C_InitToken2`); signature table at lines 178, 183, 184, 187, 236,
259, where `C_Login` is `"uuay"` and `C_SetPIN` is `"uayay"`. The server dispatches all of them:
[`p11-kit/rpc-server.c`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/rpc-server.c#L2410).

**[S5] `enable-in`/`disable-in` match the base name of `argv[0]`, are not a security feature,
and must not both be set.**
[pkcs11.conf(5)](https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html): "The base
name of the process executable should be used here, for example seahorse, ssh." … "This is not a
security feature." … "Do not specify both enable-in and disable-in for the same module."

**[S6] With both set, p11-kit never consults `disable-in`.**
[`p11-kit/modules.c`, `is_module_enabled_unlocked()`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/modules.c#L592).
It warns, then takes `if (enable_in)`; the `else if (disable_in)` branch is unreachable. The base
name comes from `_p11_get_progname_unlocked()`
([`util.c`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/util.c#L229)),
which a caller can override at run time with `p11_kit_set_progname()` — which is why the manual
says it is not a security feature.

**[S7] A user `.module` file in `~/.config/pkcs11/modules` takes precedence over the system file
of the same name — field by field, not wholesale.**
[pkcs11.conf(5)](https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html) and
[`p11-kit/conf.c`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/conf.c#L465).
The user directory is read first and `_p11_conf_merge_defaults()` copies a system key only when
the user file did not set it; `user-config: merge` is the default, with `none` and `only` the
alternatives. A user file therefore overrides the *fields* it names and inherits the rest. The
manual's own suggested override is `module:` left blank. Text saying the user file "overrides the
system one entirely" was corrected.

**[S8] p11-kit's trust tokens report `model=p11-kit-trust` and hold anchors, not client
credentials.**
[`trust/module.c`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/trust/module.c#L70)
(`#define TOKEN_MODEL "p11-kit-trust    "`, returned from `C_GetTokenInfo`);
[p11-kit-trust(8)](https://p11-glue.github.io/p11-glue/p11-kit/manual/p11-kit-trust.html): "The
trust module provides system certificate anchors, blocklists and other trust policy". The token
reports no PIN and no read/write sessions, and the module handles no private keys.

**[S9] p11-kit#294 asks for PKCS#11 modules to be sandboxed and is still open.**
[p11-glue/p11-kit#294](https://github.com/p11-glue/p11-kit/issues/294), opened by frankmorgner
2020-05-01, state open. Ueno,
[comment 622359664](https://github.com/p11-glue/p11-kit/issues/294#issuecomment-622359664):
"Part of that is already possible with the `remote` configuration option and bubblewrap". Ueno,
[comment 968077421](https://github.com/p11-glue/p11-kit/issues/294#issuecomment-968077421): "The
current configuration syntax is a bit too limited for that; maybe adding a new option to refer
external policy settings would be nice (e.g., `sandbox-profile:`)." That option does not exist in
the tree.

**[S10] `p11_kit_remote_serve_module()` exists.**
[`p11-kit/remote.h`](https://github.com/p11-glue/p11-kit/blob/120050e353e8f43d7c40bbcc047f667f903f4de5/p11-kit/remote.h#L46),
behind `P11_KIT_FUTURE_UNSTABLE_API`, alongside `p11_kit_remote_serve_tokens()`, which builds a
filtered virtual module and delegates to it — the code path behind [S1].

## The PKCS#11 specification

All references are to
[PKCS #11 Specification Version 3.1, OASIS Standard](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html),
cited by section because the published HTML carries no anchors.

**[S11] `CKF_HW_SLOT` is a slot flag; `CKF_HW` is a mechanism flag. They are different things.**
§3.2, Table 5 (Slot Information Flags): `CKF_HW_SLOT` — "True if the slot is a hardware slot, as
opposed to a software slot implementing a 'soft token'". §3.5, Table 8 (Mechanism Information
Flags): `CKF_HW` — "True if the mechanism is performed by the device; false if the mechanism is
performed in software". Note a third flag, `CKF_REMOVABLE_DEVICE`, carries the "removable
hardware" meaning; `CKF_HW_SLOT` does not.

**[S12] A protected authentication path means `C_Login` is called with a null PIN and the token
collects the secret.**
§3.2, Table 6: `CKF_PROTECTED_AUTHENTICATION_PATH` — "True if token has a 'protected
authentication path', whereby a user can log into the token without passing a PIN through the
Cryptoki library". §5.6.8 `C_Login`: "To log into a token with a protected authentication path,
the pPin parameter to C_Login should be NULL_PTR. When C_Login returns, whatever authentication
method supported by the token will have been performed". The spec constrains `pPin` only; passing
`ulPinLen = 0` alongside is universal practice, not spec text.

**[S13] `CKF_USER_PIN_COUNT_LOW`, `CKF_USER_PIN_FINAL_TRY` and `CKF_USER_PIN_LOCKED` exist, and a
token may always report them false.**
§3.2, Table 6. `CKF_USER_PIN_FINAL_TRY` — "True if supplying an incorrect user PIN will cause it
to become locked." The following paragraph: these flags "may always be set to false if the token
does not support the functionality or will not reveal the information because of its security
policy." **The spec does not say when the flags are updated.** This repository's statement that
`FINAL_TRY` is "normally set by the attempt that just failed", and that the flags must be re-read
after every refusal, is an operational observation, not something the specification promises.

**[S14] Login state is shared among the sessions of one application, not device-wide.**
§5.6: "Since all sessions an application has with a token have a shared login state, C_Login only
needs to be called for one of the sessions." §5.6.2 `C_CloseSession`: closing the last session
returns "the login state of the token **for the application** … to public sessions."

**[S15] A sensitive or unextractable private-key attribute answers `CKR_ATTRIBUTE_SENSITIVE`.**
§4.1, Table 11, footnote 7: "Cannot be revealed if object has its CKA_SENSITIVE attribute set to
CK_TRUE or its CKA_EXTRACTABLE attribute set to CK_FALSE." §5.7.5 `C_GetAttributeValue`: "If case
1 applies to any of the requested attributes, then the call should return the value
CKR_ATTRIBUTE_SENSITIVE." Note that an *RSA* private key has no `CKA_VALUE` in the specification —
the footnote-7 attributes there are `CKA_PRIVATE_EXPONENT` and the factors. Where this repository
says `CKA_VALUE` on the private key answers `CKR_ATTRIBUTE_SENSITIVE`, it is describing the
synthetic object **this module** presents (`src/module/objects.c`, `add_sensitive()`), not a
requirement on real tokens.

**[S16] PKCS#11 v3 adds interface tables beside the v2 function list, so a facade has to filter
both — three entry points, not two.**
§3.6 (`CK_INTERFACE`, and the rule that new functions must not be appended to
`CK_FUNCTION_LIST`), §5.4.4 `C_GetFunctionList`, §5.4.5 `C_GetInterfaceList`, §5.4.6
`C_GetInterface`: "C_GetFunctionList, C_GetInterfaceList, and C_GetInterface are the only
Cryptoki functions which an application may call before calling C_Initialize."

## GnuTLS, GLib and WebKitGTK

**[S17] GnuTLS's single-object PKCS#11 import refuses a URI that names no object: it needs
`object=` (`CKA_LABEL`) or `id=`.**
[`lib/pkcs11.c`, `add_obj_attrs()`](https://gitlab.com/gnutls/gnutls/-/blob/12919dc7db736467987a3254a452b1d10e20b79e/lib/pkcs11.c#L523):
the function collects `CKA_ID` and `CKA_LABEL` from the URI and returns
`GNUTLS_E_INVALID_REQUEST` when it found neither. It is reached from
`gnutls_x509_crt_import_url()` → `_gnutls_x509_crt_import_pkcs11_url()` →
`gnutls_pkcs11_obj_import_url()` → `find_single_obj_cb()`
([`lib/pkcs11.c#L2448`](https://gitlab.com/gnutls/gnutls/-/blob/12919dc7db736467987a3254a452b1d10e20b79e/lib/pkcs11.c#L2448)).
**Correction to the error code this repository used to name:** the caller does not see
`GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILABLE`. That constant is spelled
`GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILBLE` upstream and is raised elsewhere; on this path
`_pkcs11_traverse_tokens()` makes a final call with no token and `find_single_obj_cb` answers
`GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE`.

**[S18] Enumeration accepts a token-only URI.**
[`lib/pkcs11.c`, `gnutls_pkcs11_obj_list_import_url4()`](https://gitlab.com/gnutls/gnutls/-/blob/12919dc7db736467987a3254a452b1d10e20b79e/lib/pkcs11.c#L3725):
an empty URI is replaced with `"pkcs11:"`, and the enumerating callback never calls
`add_obj_attrs()`.

**[S19] Verifying a server's chain makes GnuTLS search PKCS#11 for certificates by
`CKA_SUBJECT`, `CKA_ISSUER` and trust category, per handshake.**
[`lib/x509/verify.c`, `_gnutls_pkcs11_verify_crt_status()`](https://gitlab.com/gnutls/gnutls/-/blob/12919dc7db736467987a3254a452b1d10e20b79e/lib/x509/verify.c#L1192),
reached from
[`gnutls_x509_trust_list_verify_crt2()`](https://gitlab.com/gnutls/gnutls/-/blob/12919dc7db736467987a3254a452b1d10e20b79e/lib/x509/verify-high.c#L1584);
the searches are built in `find_cert_cb()`
([`lib/pkcs11.c#L4316`](https://gitlab.com/gnutls/gnutls/-/blob/12919dc7db736467987a3254a452b1d10e20b79e/lib/pkcs11.c#L4316)),
used by `gnutls_pkcs11_get_raw_issuer()` and `_gnutls_pkcs11_crt_is_known()`.
**Confirms less than "every configured module".** Those call sites are guarded by
`list->pkcs11_token`, i.e. they run only when the trust list is PKCS#11-backed (the
`--with-default-trust-store-pkcs11` build, which is the usual distribution configuration), and
they pass `GNUTLS_PKCS11_OBJ_FLAG_PRESENT_IN_TRUSTED_MODULE`, which makes
`_pkcs11_traverse_tokens()` skip providers not marked trusted. This repository's claim that the
searches reach *this* module is a **measurement** on one system
([TESTING.md](TESTING.md) §2.55, the live run of 2026-09-05), not a general statement about every
GnuTLS build, and the text was narrowed to say so.

**[S20] `g_tls_certificate_new_from_pkcs11_uris()` arrived in GLib 2.68 and has no module
parameter.**
[`gio/gtlscertificate.c`](https://gitlab.gnome.org/GNOME/glib/-/blob/6f98b0b8ad9cb7f9be237b4a0dba3833331a8f37/gio/gtlscertificate.c#L913)
— `Since: 2.68`, three arguments (`pkcs11_uri`, `private_key_pkcs11_uri`, `error`), resolved
against `g_tls_backend_get_default()`. The module must therefore already be configured in
p11-kit; the URI cannot name it.
[API documentation](https://docs.gtk.org/gio/ctor.TlsCertificate.new_from_pkcs11_uris.html).

**[S21] glib-networking resolves those URIs through GnuTLS, on the single-object path of [S17].**
[`tls/gnutls/gtlscertificate-gnutls.c`](https://gitlab.gnome.org/GNOME/glib-networking/-/blob/70b3aab443bdcb2646d10128f3b8e69c25147dc5/tls/gnutls/gtlscertificate-gnutls.c#L598)
— `PROP_PKCS11_URI` calls `gnutls_x509_crt_import_url()`, and the private key
`gnutls_privkey_import_pkcs11_url()`. The OpenSSL backend has no PKCS#11 handling.

**[S22] WebKitGTK sends the `private-key-pkcs11-uri` to its network process, which re-resolves
it there.**
[`Source/WebKit/Shared/glib/CoreIPCGTlsCertificate.cpp`](https://github.com/WebKit/WebKit/blob/41557f449ef5b3805fdabf6f24939083ba273db3/Source/WebKit/Shared/glib/CoreIPCGTlsCertificate.cpp#L52)
— the encoder reads `private-key-pkcs11-uri` off the certificate, and the decoder rebuilds a
`GTlsCertificate` from the string. The URI, not the key, is what crosses; the receiving process
resolves it through its own p11-kit.

**[S23] WebKitGTK has an authentication scheme for a client-certificate PIN.**
[`WebKitAuthenticationRequest.h.in`](https://github.com/WebKit/WebKit/blob/41557f449ef5b3805fdabf6f24939083ba273db3/Source/WebKit/UIProcess/API/glib/WebKitAuthenticationRequest.h.in#L64)
— `WEBKIT_AUTHENTICATION_SCHEME_CLIENT_CERTIFICATE_PIN_REQUESTED = 9`, "Client certificate PIN
required for use. Since: 2.34". The network process raises it from
`NetworkDataTaskSoup::requestCertificatePasswordCallback()` and writes the application's answer
into the `GTlsPassword`. This is the request a token that sets
`CKF_PROTECTED_AUTHENTICATION_PATH` never provokes.

**[S24] `webkit_credential_new_for_certificate()` takes a `GTlsCertificate`; there is no URI
variant.**
[WebKitGTK 6.0 API reference,
`WebKitCredential`](https://webkitgtk.org/reference/webkitgtk/stable/struct.Credential.html) —
the three constructors are `webkit_credential_new`, `webkit_credential_new_for_certificate` and
`webkit_credential_new_for_certificate_pin`. Source:
[`WebKitCredential.h.in`](https://github.com/WebKit/WebKit/blob/41557f449ef5b3805fdabf6f24939083ba273db3/Source/WebKit/UIProcess/API/glib/WebKitCredential.h.in#L62).
This is why the application process must build the certificate itself, and why the module is
loaded twice for one handshake.

**[S25] TLS 1.3 makes an RSA `CertificateVerify` use RSASSA-PSS.**
[RFC 8446 §4.4.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3): "RSA signatures MUST
use an RSASSA-PSS algorithm, regardless of whether RSASSA-PKCS1-v1_5 algorithms appear in
'signature_algorithms'." [§4.2.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3) adds
that the `rsa_pkcs1_*` code points "are not defined for use in signed TLS handshake messages".

**[S26] TLS 1.0 and 1.1 sign a concatenated MD5 ‖ SHA-1 with no DigestInfo.**
[RFC 4346 §7.4.3 and §7.4.8](https://www.rfc-editor.org/rfc/rfc4346.html#section-7.4.8) give the
structure (`opaque md5_hash[16]; opaque sha_hash[20];`);
[§4.7](https://www.rfc-editor.org/rfc/rfc4346.html#section-4.7) gives the encoding: "In RSA
signing, a 36-byte structure of two hashes (one SHA and one MD5) is signed … It is encoded with
PKCS #1 block type 1" — padding only, no `DigestInfo` wrapper. RFC 2246 is the same. The mapping
of that operation onto `CKM_RSA_PKCS` is GnuTLS's
([`lib/pkcs11_int.h`, `pk_to_mech()`](https://gitlab.com/gnutls/gnutls/-/blob/12919dc7db736467987a3254a452b1d10e20b79e/lib/pkcs11_int.h#L253)),
not the RFC's.

## xdg-desktop-portal

**[S27] The experimental namespace and the `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` gate are
what upstream asked for, on PR #1889.**
[flatpak/xdg-desktop-portal#1889](https://github.com/flatpak/xdg-desktop-portal/pull/1889),
"Introduce Credentials portal (experimental)", opened by **iinuwa** 2026-01-23 and **still open,
not merged**. Sebastian Wick,
[comment 3811673138](https://github.com/flatpak/xdg-desktop-portal/pull/1889#issuecomment-3811673138),
2026-01-28, verbatim: "As for the interface name, let's call it something like
`org.freedesktop.portal.experimental.Credentials`. It should also not be exposed by default and
have a environment variable to turn it on (e.g.
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=credentials`)."
**Scope of what this confirms:** the convention exists as a maintainer's instruction on an open
pull request. It is **not** in `main` — a checkout of `main` at `86bd3e26` contains no
`experimental` namespace and no such environment variable. The gate and the
`org.freedesktop.portal.experimental.*` XML exist only on that PR's branch, where the flag value
implemented is `credential`, singular.

**[S28] xdg-desktop-portal#662, "PKCS#11 portal", is the prior discussion.**
[flatpak/xdg-desktop-portal#662](https://github.com/flatpak/xdg-desktop-portal/issues/662),
opened by **yoe** 2021-11-17, **still open**, 22 comments. The issue body — not a comment —
carries yoe's proposal ("This portal could just use p11-kit on the unconfined side, and then
export all modules that are registered in p11-kit"), the consumer list ("not only by browsers,
but also by email clients (e.g., thunderbird and evolution support PKCS#11), office suites
(libreoffice)"), and the motivation ("I work on supporting the Belgian eID software … but
Estonia's infrastructure uses a similar method"), with a link to
[`Fedict/eid-mw`](https://github.com/Fedict/eid-mw).
**Substantive discussion ended 2023-07-11.** The issue's "last updated" is now 2026-09-05,
because this project's author posted
[comment 5553242646](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-5553242646)
announcing this work, crossposted from
[flatpak/flatpak#5756](https://github.com/flatpak/flatpak/issues/5756#issuecomment-5553235336).
Those two comments are the only contact this project has had with upstream; no new-portal issue
has been opened.

**[S29] The positions attributed to individual commenters in #662.** Each is quoted from its own
comment:
[jmaris, 2023-04-04](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1496008450)
("the European Union is in the process of adopting this as a standard for Digital Identity
Documents (extending the existing eIDAS system)");
[ueno, 2023-06-23](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1604126162)
("a malicious application could brick smartcards by calling destructive functions like
C_InitToken or by repeatedly providing incorrect PIN");
[frankmorgner, 2023-06-23](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1604916424)
(permission fatigue: "Apple has started to enforce this a couple of years back as well and
received a lot of anger for this. And I think it was in Windows Vista, where MS tried the same
and rolled it back") and
[four minutes later](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1604920580)
("you may want to consider *whitelisting* known *friendly* applications");
[mcatanzaro, 2023-06-23](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1605122316)
("The security model is to protect against compromised applications");
[Mikenux, 2023-06-28](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1610582233);
[jmpolom, 2023-07-11](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1631249619)
("The rate limit should be lower down in the stack, closer to where the hardware is interacted
with (so maybe p11-kit, opensc or pcsc?)").

**[S30] The two-layer diagram is Frank Morgner's, 2023-03-22.**
[Comment 1479992623](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1479992623):
"vpcd/vicc are exposing the token itself. pkcs11-proxy is exposing the middleware that is making
the token accessible", with an ASCII diagram of smart card → PC/SC → PKCS#11 middleware →
PKCS#11 → Firefox/Thunderbird/ssh/OpenSSL.

**[S31] Ueno's "Flatpak portal design for smartcard access" (2023).**
[Attached to #662](https://github.com/flatpak/xdg-desktop-portal/files/11847714/Flatpak.portal.design.for.smartcard.access.pdf),
four pages. Confirms: "The minimal unit of access control is PKCS#11 token, not object nor
certain operation"; the threat "repeated attempts to authenticate, which could turn smartcards
into an unusable state" and "allowing access to administrative functions, such as C_InitToken,
could invalidate private keys"; and that PIN entry deliberately stays with the application — "it
would be desirable to not interfere with the existing application level pop-up, such as the
password prompt implemented by Firefox."

**[S32] `valentindavid/pkcs11-demo` forwards every module, with no consent step.**
[valentindavid/pkcs11-demo](https://github.com/valentindavid/pkcs11-demo), cited into #662 by
[frankmorgner, 2022-02-28](https://github.com/flatpak/xdg-desktop-portal/issues/662#issuecomment-1054364138).
The `opensc` snap is `confinement: strict`, runs `pcscd` as a daemon, and its
`start-p11-kit-server` script is exactly `p11-kit server -f --name "${SNAP_DATA}/p11-kit/pkcs11"
pkcs11:` — the bare URI, every module. The consumer is a strictly-confined `nginx-pkcs` snap
whose only registered p11-kit module is `p11-kit-client.so`, joined by snapd's content
interface; authorisation is a one-time `snap connect`.

**[S33] A backend installs its `.portal` file into `$datadir/xdg-desktop-portal/portals`.**
[Writing a new backend](https://flatpak.github.io/xdg-desktop-portal/docs/writing-a-new-backend.html):
"Install `foo.portal` file under `{DATADIR}/xdg-desktop-portal/portals`. Usually, `{DATADIR}` is
`/usr/share`."

**[S34] `portals.conf` selects a backend per impl interface.**
[portals.conf](https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html): the
`[preferred]` group, keys named `org.freedesktop.impl.portal.*`, a `default` key, and the
special values `none` and `*`.

**[S35] Portals and their backends live at `/org/freedesktop/portal/desktop`.**
[API reference](https://flatpak.github.io/xdg-desktop-portal/docs/api-reference.html): "Desktop
portals appear under the bus name `org.freedesktop.portal.Desktop` and the object path
`/org/freedesktop/portal/desktop` on the session bus." The *backend* side is not stated in the
prose documentation; it is the code convention —
[`xdg-desktop-portal-gtk`, `src/utils.h`](https://github.com/flatpak/xdg-desktop-portal-gtk/blob/main/src/utils.h)
defines `DESKTOP_PORTAL_OBJECT_PATH "/org/freedesktop/portal/desktop"` and every backend
interface is exported there.

**[S36] xdg-desktop-portal, -gtk and -gnome are LGPL-2.1-or-later.**
[xdg-desktop-portal `LICENSES/LGPL-2.1-or-later.txt`](https://github.com/flatpak/xdg-desktop-portal/tree/main/LICENSES)
(the project is REUSE-annotated and has no `COPYING`; 192 of its source files carry
`LGPL-2.1-or-later`, though `meson.build` still declares `LGPL-2.0-or-later`);
[xdg-desktop-portal-gtk `COPYING`](https://github.com/flatpak/xdg-desktop-portal-gtk/blob/main/COPYING)
(the LGPL 2.1 text; `meson.build` declares `LGPL-2.1-or-later`, while the per-file headers say
"version 2 … or any later version");
[xdg-desktop-portal-gnome](https://gitlab.gnome.org/GNOME/xdg-desktop-portal-gnome) — on
gitlab.gnome.org, not GitHub — `COPYING` is the LGPL 2.1 text and `meson.build` declares
`LGPLv2.1+`. The claim holds at project level; the per-file headers of xdg-desktop-portal-gtk are
looser than the project declaration.

**[S37] The frontend derives the app id from the D-Bus peer and passes it to the backend as an
argument.**
[`shared/xdp-utils.c`, `xdp_invocation_get_app_info()`](https://github.com/flatpak/xdg-desktop-portal/blob/86bd3e26eabb7750ebb6f804e1e3ec122608a647/shared/xdp-utils.c#L278);
[`desktop-portal/screenshot.c`](https://github.com/flatpak/xdg-desktop-portal/blob/86bd3e26eabb7750ebb6f804e1e3ec122608a647/desktop-portal/screenshot.c#L421),
which passes `app_id` into the impl call; and
[`org.freedesktop.impl.portal.Screenshot`](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Screenshot.html),
whose signature is `(o handle, s app_id, s parent_window, …)`. The position of `app_id` varies
between impl interfaces; its presence does not.

**[S38] The Camera portal hands back a PipeWire file descriptor, not a device.**
[org.freedesktop.portal.Camera](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Camera.html):
`OpenPipeWireRemote` — "Open a file descriptor to the PipeWire remote where the camera nodes are
available." `AccessCamera` grants permission and nothing else; no device node appears in the
interface.

**[S39] The USB portal acquires devices and returns file descriptors, and documents their
lifetime.**
[org.freedesktop.impl.portal.Usb](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Usb.html)
(`AcquireDevices`) and
[org.freedesktop.portal.Usb](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Usb.html):
"xdg-desktop-portal tries to open the device file on the behalf of the requesting app, and pass
the file descriptor down." The descriptors are returned by the follow-up
`FinishAcquireDevices`, in a `fd (h)` result, not by `AcquireDevices` itself.

**[S40] The host app registry is documented as temporary.**
[API reference](https://flatpak.github.io/xdg-desktop-portal/docs/api-reference.html): "Disclaimer:
The host app registry is expected to eventually be deprecated and may be removed. Applications
should gracefully handle interface or method no longer being available to be forward compatible."
The warning is on that page, **not** on the
[Registry interface page](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.host.portal.Registry.html),
which carries no such text.

**[S41] `xdg-desktop-portal-termfilechooser` is an out-of-tree backend that installs into the
real portal directory.**
[GermainZ/xdg-desktop-portal-termfilechooser `meson.build`](https://github.com/GermainZ/xdg-desktop-portal-termfilechooser/blob/master/meson.build)
installs `termfilechooser.portal` into `datadir/xdg-desktop-portal/portals`.
**Confirms less than the claim once did:** the upstream README does not mention `portals.conf`
at all — it relies on the deprecated `UseIn` key. It is the widely used fork
[boydaihungst/xdg-desktop-portal-termfilechooser](https://github.com/boydaihungst/xdg-desktop-portal-termfilechooser)
whose README tells the user to write
`org.freedesktop.impl.portal.FileChooser=termfilechooser` into `portals.conf`.

**[S42] D-Bus names should be in a namespace the project controls.**
[D-Bus specification, "Bus names"](https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names):
bus names are recommended to "start with the reversed DNS domain name of the author of the
interface".

**[S43] `--socket=pcsc` is a Flatpak sandbox permission that reaches `pcscd` directly.**
[Flatpak sandbox permissions](https://docs.flatpak.org/en/latest/sandbox-permissions.html).

**[S44] `credentialsd` is proposing a credentials portal for FIDO2 and passkeys.**
[linux-credentials/credentialsd](https://github.com/linux-credentials/credentialsd), described by
its own repository as a "Proposal for a Linux credential management xdg portal D-Bus
specification, including webauthn/passkey support", with a service, a reference UI and packages.
Related to, and distinct from, [S27].

## PIV, OpenSC and the RFCs

**[S45] PIV key references: 9A authentication, 9C digital signature, 9D key management, 9E card
authentication.**
[NIST SP 800-73pt1-5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf),
§5.1, Table 5 "PIV Card Application key references". The table also gives 9B (card application
administration), 82–95 (retired key management) and 04 (secure messaging), and the differing
security conditions: 9A and 9D "PIN or OCC", 9C "PIN Always", 9E "Always".

**[S46] OpenSC's PIV driver does not use the key reference as `CKA_ID`.**
[`src/libopensc/pkcs15-piv.c`](https://github.com/OpenSC/OpenSC/blob/c4144598f38dd9839a20c336bdd907bc1f3822a5/src/libopensc/pkcs15-piv.c#L542):
the object id is `"01"`, `"02"`, `"03"`, `"04"` for 9A, 9C, 9D, 9E, hex-decoded to one byte and
copied out as `CKA_ID` by
[`src/pkcs11/framework-pkcs15.c`](https://github.com/OpenSC/OpenSC/blob/c4144598f38dd9839a20c336bdd907bc1f3822a5/src/pkcs11/framework-pkcs15.c#L4177);
the key reference `0x9A` is a separate field. Certificate, public key and private key of one slot
share the id. Other middleware does use the key reference, which is why this repository's
`piv_slot` derivation accepts **both** (`src/tokens/discovery.c`, `piv_slot_from_id()`).

**[S47] RFC 7512 defines the PKCS#11 URI, with `pin-value` and `pin-source` as *query*
attributes.**
[RFC 7512 §2.3](https://www.rfc-editor.org/rfc/rfc7512.html#section-2.3) — path attributes
include `token`, `manufacturer`, `model`, `serial`, `object`, `id` and `type`, where
`type = "public" / "private" / "cert" / "secret-key" / "data"`; query attributes are
`pin-source`, `pin-value`, `module-name`, `module-path`.
[§2.4](https://www.rfc-editor.org/rfc/rfc7512.html#section-2.4): a URI carrying both `pin-source`
and `pin-value` "SHALL be refused as invalid".

**[S48] `DigestInfo` and the RSA-PSS parameters.**
[RFC 8017 §9.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.2) (EMSA-PKCS1-v1_5):
`DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }`, DER, in
`EM = 0x00 || 0x01 || PS || 0x00 || T`.
[§9.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-9.1) (EMSA-PSS): "parameterized by the
choice of hash function, mask generation function, and salt length".
[Appendix A.2.3](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.2.3) gives
`RSASSA-PSS-params`, whose defaults are SHA-1, MGF1-SHA-1 and a salt length of 20.

**[S49] A distinguishable PKCS#1 v1.5 decryption failure is an oracle against the key.**
Daniel Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption
Standard PKCS #1", CRYPTO '98, LNCS 1462, pp. 1–12
([DOI 10.1007/BFb0055716](https://doi.org/10.1007/BFb0055716)). Abstract: "an RSA private-key
operation can be performed if the attacker has access to an oracle that, for any chosen
ciphertext, returns only one bit telling whether the ciphertext corresponds to some unknown block
of data encrypted using PKCS #1."
[RFC 8017 §7.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.2) and
[§7.2.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.2.2): "Care shall be taken to
ensure that an opponent cannot distinguish the different error conditions in Step 3, whether by
error message or timing."

**[S50] OAEP requires indistinguishable decryption failures too.**
[RFC 8017 §7.1.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1.2): "Care must be taken
to ensure that an opponent cannot distinguish the different error conditions in Step 3.g, whether
by error message or timing, and, more generally, that an opponent cannot learn partial
information about the encoded message EM." Step 3.g itself collapses three distinct failures into
one "decryption error".

## Other systems

**[S51] Windows: the Base CSP and the smart card KSP own PIN entry and caching; applications use
CryptoAPI/CNG and see certificates through propagation.**
[Smart card minidrivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/smart-card-minidrivers):
the architecture "splits the implementation of the CSP into two parts: The Base CSP/KSP (the
common part), which includes functionality for hashing, symmetric, and public key cryptographic
operations **in addition to personal identification number (PIN) entry and caching**. A series of
plug-ins, which are known as 'card minidrivers'".
[Smart card architecture](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture):
"The Base CSP internally maintains a per-process cache of the PIN."
[Certificate propagation service](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-propagation-service):
"activates when a user inserts a smart card in a reader… The certificates are then added to the
user's Personal store."

**[S52] macOS: a CryptoTokenKit extension publishes the token into the Keychain and draws no UI;
the system does.**
[Authenticating users with a cryptographic token](https://developer.apple.com/documentation/cryptotokenkit/authenticating-users-with-a-cryptographic-token):
"A smart card app extension has no UI component. **The system handles all user interaction
associated with authenticating the user.**"
[`TKTokenKeychainItem`](https://developer.apple.com/documentation/cryptotokenkit/tktokenkeychainitem)
is "an abstract base class for managing a token's contents as keychain items", and
[`kSecAttrAccessGroupToken`](https://developer.apple.com/documentation/security/ksecattraccessgrouptoken)
is the access group applications query to reach them: "Access to this group is granted by default".

**[S53] `--socket=pcsc` is how Firefox's Flatpak reaches a card. Chromium's does not use it.**
Firefox: the option is in Mozilla's own packaging,
[`python/mozbuild/mozbuild/repackaging/flatpak.py`](https://searchfox.org/mozilla-central/source/python/mozbuild/mozbuild/repackaging/flatpak.py)
(`"--socket=pcsc"` among the `flatpak build-finish` arguments), and the resulting permission set is
shown in the
[Flatpak build documentation](https://firefox-source-docs.mozilla.org/build/buildsystem/flatpak.html).
Chromium: [`org.chromium.Chromium.yaml`](https://github.com/flathub/org.chromium.Chromium/blob/master/org.chromium.Chromium.yaml)
has `--socket=cups`, `--socket=pulseaudio`, `--socket=x11` and `--socket=wayland` and **no
`--socket=pcsc`** — it holds `--device=all` and `--filesystem=home` instead. The text was
corrected: only Firefox's Flatpak was verified to take the PC/SC socket.

**[S54] Firefox and Thunderbird load PKCS#11 modules themselves. LibreOffice and Evolution do
not — they use NSS, and reach a card only where the distribution has made NSS load
`p11-kit-proxy.so`.**
Firefox: `SECMOD_AddNewModule()` in
[`security/manager/ssl/PKCS11ModuleDB.cpp`](https://searchfox.org/mozilla-central/source/security/manager/ssl/PKCS11ModuleDB.cpp),
a "Load PKCS#11 Device" dialog, and the
[`pkcs11` WebExtensions API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/pkcs11).
Thunderbird uses the same `nsIPKCS11ModuleDB`.
LibreOffice signs through NSS but initialises a **Mozilla profile** database and loads no module of
its own — [Applying digital signatures](https://help.libreoffice.org/latest/en-US/text/shared/guide/digitalsign_send.html):
"If you are using Linux, macOS or Solaris, you must install a recent version of Thunderbird or
Firefox. LibreOffice will then access their certificate storage." Evolution's S/MIME code likewise
loads only the root-certificate module.
The gap is closed distribution-side:
[Fedora's NSSLoadP11KitModules change](https://fedoraproject.org/wiki/Changes/NSSLoadP11KitModules)
— "PKCS#11 modules configured in the system's p11-kit will be automatically registered and visible
to NSS applications" — implemented by crypto-policies emitting `library=p11-kit-proxy.so` into
`/etc/crypto-policies/back-ends/nss.config`, which Fedora's NSS reads at `NSS_Init()`. Upstream NSS
has no such mechanism: [Mozilla bug 248722](https://bugzilla.mozilla.org/show_bug.cgi?id=248722),
"Need a system wide configuration for PKCS #11 modules", is **WONTFIX**.

**[S55] GNOME's gcr provides `GcrPrompt`, `GcrSystemPrompt` and `GcrSystemPrompter`, and
gnome-shell owns the prompter's bus name.**
[gcr](https://gitlab.gnome.org/GNOME/gcr): `gcr/gcr-dbus-constants.h` gives the names — the
well-known name is `org.gnome.keyring.SystemPrompter`, the object path is
`/org/gnome/keyring/Prompter`, and **the D-Bus interface is
`org.gnome.keyring.internal.Prompter`**, whose introspection XML warns "This is an internal
interface, and not a public API. It can change between releases." gcr itself never calls
`g_bus_own_name()`; the implementor does. gnome-shell is one:
[`js/ui/components/keyring.js`](https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/main/js/ui/components/keyring.js)
subclasses `Gcr.SystemPrompter` and calls
`Gio.DBus.session.own_name('org.gnome.keyring.SystemPrompter', …)`. gcr also ships a fallback:
on the machine this was checked, `/usr/share/dbus-1/services/org.gnome.keyring.SystemPrompter.service`
activates `/usr/libexec/gcr-prompter` (gcr 4.4.0.1, Fedora).
Text naming `org.gnome.keyring.Prompter` as the *interface* was corrected.

**[S56] `gcr_prompt_set_choice_label(NULL)` removes the checkbox.**
[`GcrPrompt.set_choice_label()`](https://gnome.pages.gitlab.gnome.org/gcr/gcr-4/method.Prompt.set_choice_label.html):
"If this is `NULL`, then no additional choice is being displayed."

**[S57] The gcr 4.4 double-completion this repository works around is NOT a reported upstream
defect.** A search of
[gcr's issues and merge requests](https://gitlab.gnome.org/GNOME/gcr/-/issues) and of its git log
found no report of a prompt round being completed twice, and nothing in the 4.0 → 4.4.0.1 NEWS
touches prompt completion. The claim rests on two things this repository can show: reading gcr
4.4's `gcr/gcr-system-prompt.c`, where `on_call_timeout()` calls
`gcr_system_prompt_close_async()` — which completes the pending result through `perform_close()` —
and then completes the same result itself; and `tests/test-pin-system.c`
`/pin-system/close-racing-a-transport-error`, which crashed before the workaround and now asserts
the `pin-prompt-round-completed-twice` log line. **Read it as this project's own analysis, not as
a citation.**

**[S58] The Remmina RDP plugin's PKCS#11 support is the prior art the discovery requirements came
from.** [Remmina](https://gitlab.com/Remmina/Remmina), GPL-2.0-or-later. No code from it is in
this repository; see [0004](decisions/0004-license.md). The edge-case list in
[ARCHITECTURE.md](ARCHITECTURE.md) is a description of that plugin's behaviour, recorded by this
project's author, who wrote the patches — it is not independently citable, and it is the one place
here where the "primary source" is the author's own prior work.

## What is deliberately not cited

- **Every claim about this repository's own code, tests, tools and runs.** Those are checkable in
  the tree and in [TESTING.md](TESTING.md), and a citation would add nothing.
- **The dates and outcomes of the hardware runs.** One person, one card, one reader; the record is
  [TESTING.md](TESTING.md) §3 and the journal it quotes. Nobody else has reproduced it.
- **Statements of opinion and intent** — that the split is worth its cost, that a rename is
  expected, that the facade would be substantial work. The decision records say which is which.

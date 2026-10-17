# Testing

Build checks, private-bus integration and software-token tests precede hardware tests.
[Test coverage](../tests/README.md) lists registered tests and their prerequisites.
Commands and dated evidence below are recorded from Fedora 44. Hardware tiers 3.1–3.4 have
one PIV-card/reader result; remaining hardware checks are unrun.

## 0. Build and test

```console
$ meson setup build -Dwarning_level=2 -Dwerror=false
$ ninja -C build
$ meson test -C build
```

[tests/README.md](../tests/README.md) lists registered suites, coverage and skip conditions.

### Sanitizer build

Run cancellation and parser coverage under AddressSanitizer and UndefinedBehaviorSanitizer:

```console
$ meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false
$ meson test -C build-asan
```

If tests exit 127, inspect `ldd build-asan/tests/test-mechanism` for missing sanitizer runtimes,
such as `libasan.so.8`. Fedora packages are `libasan` and `libubsan`. To unpack them without
system installation, keep download and extraction in the same scratch directory:

```console
$ mkdir -p ~/scratch/asan-rt
$ (cd ~/scratch/asan-rt && dnf download --arch=x86_64 libasan libubsan && for f in *.rpm; do rpm2cpio "$f" | cpio -idmu; done)
$ LD_LIBRARY_PATH=~/scratch/asan-rt/usr/lib64 meson test -C build-asan
```

`LD_LIBRARY_PATH` overrides the binary's `RUNPATH`. `tests/lsan.supp` covers process-lifetime
allocations in GTK, GnuTLS and p11-kit; it contains no broad GLib/GIO/GObject suppression that
could hide allocations from this backend. LSan matches any allocation-stack frame. Leaks in
`src/` require investigation.

`/cancel/during-login` checks deferred completion and worker-owned PIN storage. Immediate
completion with the prompt's buffer would violate its assertions. It briefly opens a real
backend PIN window without xdotool, and skips without a display. Xvfb can isolate that window.

```console
$ ./build/src/xdg-desktop-portal-certificate --help
$ ./build/src/xdg-desktop-portal-certificate --version
```

### Build without gcr

`--pin-prompt=gtk` and `auto` work without gcr-4. The `pin-system` test is skipped:

```console
$ meson setup build-nogcr -Dgcr=disabled -Dwerror=true && ninja -C build-nogcr
$ ./build-nogcr/src/xdg-desktop-portal-certificate --pin-prompt=gtk --version
$ ./build-nogcr/src/xdg-desktop-portal-certificate --pin-prompt=auto --version
$ meson test -C build-nogcr
```

Without gcr-4, `gtk` and `auto` use the backend's GTK window. `--pin-prompt=system` prints
`--pin-prompt=system requires a build with gcr-4` and exits 64. The `cli` test checks option
parsing and the usage error without a display or session bus.

## 1. Private bus without a card

The private-bus test checks backend selection, public-interface export and acquisition refusal.

### Prerequisites

Build the backend. `tools/dev-stack.sh` uses GTK on the private bus and works without gcr-4.

Build the frontend from
[experimental/integration](https://github.com/sjtrotter/xdg-desktop-portal/tree/experimental/integration).
It needs a configured backend and `Certificate1` in
`XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL` at startup. Development scripts preserve an existing
comma-separated list and append `Certificate1` if missing, including under `--live`.
Both portals use `Certificate1,WebAuthentication1`, with no spaces.

The stack needs `dbus-run-session`, Python 3 with PyGObject (`python3-gobject` on Fedora),
and a frontend build containing both xdg-desktop-portal and xdg-permission-store.
The end-to-end client verifies with python-cryptography or OpenSSL; raw ECDSA verification
requires python-cryptography, or `--der` when using the OpenSSL fallback.

The frontend depends on libdex. If its libraries live in a scratch prefix, put the environment
in this repository's gitignored `.xdp-env`; `dev-stack.sh`, `ui-smoke.sh`, `module-smoke.sh`
and `nss-smoke.sh` source it:

```sh
# .xdp-env
export LD_LIBRARY_PATH=/path/to/scratch/prefix/lib64
```

A valid `RUNPATH` may suffice. A prefix under `/tmp` can disappear at reboot; keep
`libdex-1.so.1` in a persistent scratch prefix if needed. The script checks frontend libraries
with `ldd`. `XDP_BUILD` selects the frontend build directory; `BACKEND` selects the backend
executable, and `XDP_ENV` selects the environment file.

### Run and expected output

```console
$ tools/dev-stack.sh -- --expect-no-certificate
```

Frontend output should include:

```
XDP: Found 'certificate' in configuration for org.freedesktop.impl.portal.experimental.Certificate1
XDP: Using certificate.portal for org.freedesktop.impl.portal.experimental.Certificate1 (interface specific config)
XDP: Providing portal org.freedesktop.portal.experimental.Certificate1
XDP: org.freedesktop.portal.Desktop acquired
```

Backend output for an empty discovery result includes:

```
** Message: request-received app_id=(none) identity=(none) purpose=create_session granted=yes
** Message: discovery-started app_id=(none) identity=unidentified purpose=client_auth granted=no
** Message: discovery-result tokens=0 candidates=0
** Message: no-matching-certificate tokens=0 candidates=0
```

The empty chooser says "Insert your security token" and disables Use. Cancel it; the client
reports signing capabilities and user cancellation:

```
GetCapabilities:
  max_grant_lifetime               3600
  mechanisms                       ['RSA_PKCS1_V1_5', 'RSA_PSS', 'ECDSA']
  operations                       ['sign']
  protected_authentication_path    True
  purposes                         ['client_auth', 'signing', 'email', 'ssh']

PASS no-certificate: AcquireCredential answered 1, no grant
```

The Python client on a private bus is unidentified; `app_id=(none)` and
`identity=unidentified` are expected. Capabilities do not require a present card. The frontend
filters the backend's mechanism list to its signing allowlist. Both capability fields describe
backend support, independent of inserted tokens and reader flags.

With no card, cancel the chooser and repeat browser enumeration within 10 seconds; the module
must return no objects without opening another chooser. Insert/remove a card while the chooser
is open; the purpose/filter is reapplied, and a disappearing selection disables Use.
`test-impl-dbus.c` compares forbidden/no-display outcomes and capabilities with SoftHSM and an
empty module list; `test-chooser.c` covers empty states and list replacement. Missing fixtures
or display skip the corresponding cases.

For manual calls, keep the stack running:

```console
$ tools/dev-stack.sh --keep --no-e2e
```

In another shell, set `DBUS_SESSION_BUS_ADDRESS` to the printed value and use
`tools/trigger-certificate.sh` (`version`, `introspect`, `capabilities`, `session`,
`acquire PATH`, `sign PATH`, `release PATH`, `monitor`, `all`). Its `sign` example sends
three bytes with `SHA256`, so it demonstrates validation failure; use the end-to-end client
for a signature that can verify.

## 2. Software token

SoftHSM tests verify cryptography and UI paths without establishing hardware behavior.
Fixture creation needs `libsofthsm2.so`, `softhsm2-util`, `certtool` (gnutls-utils),
`pkcs11-tool` (OpenSC) and OpenSSL. Module smoke tests also need `p11tool` (gnutls-utils).

```console
$ tools/softhsm-fixture.sh
$ meson test -C build broker-device --verbose
```

`broker-device` verifies RSA PKCS#1 v1.5 with SHA-256/SHA-384, RSA-PSS and ECDSA against
certificates read from the token. Its internal OAEP test decrypts ciphertext produced by
`openssl pkeyutl`. It also checks wrong-PIN reporting and discovery without login.

### Fixture directories

`tools/lib.sh` checks every fixture before use or recursive deletion. The resolved path must
be under `$TMPDIR`, contain no symlink component, have acceptable ancestor ownership and modes,
and have an accepted mode. Each ancestor beneath `$TMPDIR` must be owned by the user or root
and cannot be writable by others unless sticky. The marker `.xdg-desktop-portal-certificate-fixture`
must be a regular user-owned mode-0600 file naming the fixture. Existing unmarked directories
are refused. Fixtures are created exclusively with mode 0700 under `umask 077`; validation
accepts 0700 or 0500 without repairing modes.
Deletion uses the resolved path and `--one-file-system`.

These checks cover the dlopened module path in `$SOFTHSM_DIR`, UI `$LOGDIR` and stack `$DEVDIR`.
`$TMPDIR` is operator-chosen; containment protects against mistyped paths without authenticating
the operator. `tools-lib` tests the refusal cases. A valid fixture with a 0644 marker is refused;
change only that marker to mode 0600 or recreate the fixture with its owning script.

### UI smoke tests

`tools/ui-smoke.sh` uses GTK by default and works without gcr-4. Build with
`-Dgcr=enabled` to test `--pin-prompt=system`.

Create the fixture, then run the windows under Xvfb and xdotool:

```console
$ tools/ui-smoke.sh                                        # RSA
$ tools/ui-smoke.sh --key-algorithm EC                     # ECDSA, raw r||s
$ tools/ui-smoke.sh --key-algorithm EC --der               # ECDSA, DER
$ tools/ui-smoke.sh -- --key-algorithm RSA --regrant EC    # two sessions, two prompts
$ tools/ui-smoke.sh --pin-prompt=system                    # the shell's prompt instead
```

`--pin-prompt=system` starts `build/tests/certificate-test-prompter` on the private bus,
answering with `$PIN`. It needs gcr-4 and exercises the system-prompt implementation without
an operator shell or xdotool typing the PIN. The test prompter refuses to take an already-owned
name. Other UI runs drive the backend's GTK PIN window.

`dev-stack.sh` defaults private runs to GTK and refuses private `--pin-prompt=system`.
A private bus can activate `/usr/libexec/gcr-prompter` from system service directories, so
`auto` would depend on the machine. With gcr-4 on a live bus, `auto` selects an owned or
activatable system prompter. Prompt options survive script re-execution.

### Portal configuration

The scripts symlink installed `.portal` files and add this backend to a temporary portal
directory. `tools/lib.sh` resolves each interface across the machine's configuration chain
and flattens the effective choices into `portals.conf`, replacing the Certificate entry.
This preserves later-directory values such as `Screenshot=none`. `XDG_DESKTOP_PORTAL_DIR`
replaces all normal portal/configuration search directories, so the development directory
must include the desktop's other portals too. The `tools-lib` test checks this resolution.

Private runs disable the `Secret` backend because the private bus has no secret-service owner;
otherwise activation can delay frontend startup by about 25 seconds. Live runs preserve it.
To check the settings portal:

```console
$ tools/dev-stack.sh --keep --no-e2e
# Set the printed DBUS_SESSION_BUS_ADDRESS in another shell.
$ gdbus call --session --dest org.freedesktop.portal.Desktop \
      --object-path /org/freedesktop/portal/desktop \
      --method org.freedesktop.portal.Settings.ReadOne \
      org.freedesktop.appearance color-scheme
(<uint32 1>,)
```

Color-scheme values are `1` for prefer-dark, `2` for prefer-light and `0` for no preference.

### Theme and headless dependencies

Process hardening prevents the settings portal identifying the backend. The backend sets
`GDK_DEBUG=no-portals` and `ADW_DISABLE_PORTAL=1` before GTK initialization and reads
`org.gnome.desktop.interface color-scheme` through GSettings; see
[PIN handling](SECURITY.md#pin-handling). Test the dark setting and inspect verbose output:

```console
$ ADW_DEBUG_COLOR_SCHEME=prefer-dark tools/ui-smoke.sh
$ grep colour-scheme /tmp/xdp-certificate-ui-smoke.*/backend.log
... DEBUG: colour-scheme detail=dark
```

Without `ADW_DEBUG_COLOR_SCHEME`, the log reports the session setting.
Xvfb and xdotool can also be unpacked in a scratch directory:

```console
$ mkdir -p ~/scratch
$ (cd ~/scratch && dnf download --arch=x86_64 --resolve xorg-x11-server-Xvfb xdotool && for f in *.rpm; do rpm2cpio "$f" | cpio -idmu; done)
$ XVFB=~/scratch/usr/bin/Xvfb XDOTOOL=~/scratch/usr/bin/xdotool \
    LD_LIBRARY_PATH=~/scratch/usr/lib64 tools/ui-smoke.sh
```

The unpacked xdotool needs `libxdo.so.3` from that scratch library directory. A loader failure
can look like `ui-smoke: no window titled 'Use a Certificate'` because window-search stderr is
suppressed. Check `xdotool search --name .` directly when the backend logged `chooser-shown`.
SoftHSM can be unpacked similarly; set `SOFTHSM_MODULE` to its module.

### Cancellation and manual UI

For client cancellation without driving the windows:

```console
$ tools/ui-smoke.sh --no-drive -- --cancel-after 3000 --expect-cancelled
```

The client closes the acquisition Request after three seconds. Expect `chooser-cancelled`,
no grant and no later `Response`: the frontend unexports its Request before forwarding close.
For interactive windows on the current display:

```console
$ tools/dev-stack.sh --softhsm -- --purpose client_auth
```

Select a certificate and enter fixture PIN `123456`; the client verifies the signature.
Use the PIN only for this fixture. Scripts pass an explicit module and `--allow-software-tokens`;
the backend otherwise offers hardware tokens only. An explicit `--module` also permits software
tokens. `--list-tokens` explains skipped tokens. Remove the fixture with
`tools/softhsm-fixture.sh --clean`.

### 2.5 Client module through GnuTLS and OpenSC

Consumers talk PKCS#11 to `build/src/module/libpkcs11-portal-certificate.so`; the module
calls D-Bus. The harness supplies frontend, backend, SoftHSM, Xvfb and xdotool.

```console
$ ninja -C build
$ tools/softhsm-fixture.sh
$ tools/module-smoke.sh
$ tools/module-smoke.sh --phase 3        # just the handshake
$ tools/module-smoke.sh --phase 0        # just the "no chooser" proof
```

0. Token-only `p11tool --list-all-certs` and `pkcs11-tool --list-objects` must leave
   `grant-created` counts unchanged and return no objects. `portal_template_intent()` in
   `src/module/objects.c` and `/module/objects/credential-search` in `tests/test-module.c`
   define the intent gate. The recorded 2026-09-05 live run found server-chain lookups reaching
   this module before a client-certificate challenge; scope depends on GnuTLS configuration
   [[S19](SOURCES.md)]. Such lookups must not open a chooser.
1. `p11tool --provider ... --list-all` uses `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` to acquire
   during class enumeration. Certificate and both keys must share `CKA_ID` and the contract's
   object label. URIs come from `src/module/portal-token.h`; `URI_OBJECT=` removes `object=`
   to exercise the single-object import failure.
2. `pkcs11-tool --sign --mechanism SHA256-RSA-PKCS` signs; reading the certificate and
   `openssl dgst -sha256 -verify` must verify against the returned DER rather than fixture PEM.
3. `tests/gtls-client` constructs a certificate with `g_tls_certificate_new_from_pkcs11_uris()`
   and completes mutual TLS against a Python ssl server that requires and verifies the client.
   This is the constructor WebKitGTK reaches through glib-networking ([SPIKES.md](SPIKES.md) S3).

p11-kit reads an ephemeral `$XDG_CONFIG_HOME/pkcs11/modules` file with an absolute module path.
No installation is needed. The fixture's self-signed leaves lack `basicConstraints CA:TRUE`;
Python/OpenSSL accepts the peer leaf as a trust anchor where GnuTLS's server does not.
Expected output includes:

```
=== 0  a search that names no object must not ask for one ===
grants before=0 after=0
module-smoke: neither search acquired a credential
...
handshake completed
server said: PASS Portal Test User (RSA)
client certificate: {'organizationName': 'Example Org', 'commonName': 'Portal Test User (RSA)'}
protocol: TLSv1.3 cipher: TLS_AES_256_GCM_SHA384
module-smoke: PASS
```

`MODULE_LOG_CALLS=1` adds `log-calls: yes` to that configuration so p11-kit logs calls to
consumer stderr. It can diagnose a session that closes without searching, including a URI
that names no object.

Run the module through real consumers under sanitizers:

```console
$ meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false
$ ninja -C build-asan
$ LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0     MODULE_SO=$PWD/build-asan/src/module/libpkcs11-portal-certificate.so     GTLS_CLIENT=$PWD/build-asan/tests/gtls-client     tools/module-smoke.sh --phase "1 3"
```

Phase 2 cannot use this sanitizer setup: OpenSC's pkcs11-tool uses `RTLD_DEEPBIND`, which
the sanitizer runtime refuses.

### 2.55 WebKitGTK evidence

The web-auth backend's `tools/portal-stack.sh` supplies both portals, SoftHSM, a WebKitGTK view,
a temporary p11-kit configuration and a server requiring the fixture certificate, on a private
bus under Xvfb. Its frontend environment enables `Certificate1,WebAuthentication1` and routes
the impl interfaces to both backends. That script belongs to the sibling repository; this tree
contains only the certificate-side prerequisites, `ninja -C build` and
`tools/softhsm-fixture.sh`.

The 2026-09-05 run, following WebKitGTK runs on 2026-09-04/05, recorded:

```
  ok    3 p11-kit loaded the module here   xdg-desktop-portal-webauth:378854): pkcs11-portal-certificate-DEBUG
  ok    3 the module got a credential here ... grant acquired
  ok    3 the module ran in the network process (process:378930): ... grant acquired
  ok    4 the frontend identified the caller chooser-shown app_id=(none) identity=unidentified
  ok    5 the backend created a grant      grant-created
  ok    6 the PIN was accepted             login-ok
  ok    6 the signature was produced       operation-completed
  ok    7 the server saw the card's CN     client-cn=Portal Test User

module instances: 2
choosers granted: 2
PIN prompts:      1
signatures:       1
```

TLS 1.3 exercises `CKM_SHA256_RSA_PKCS_PSS`, module parameter mapping, portal `Sign` with
`mgf`/`salt_length` and backend PSS assembly. The pkcs11-tool phase covers v1.5 separately.
The UI process constructs a `GTlsCertificate`; the network process resolves the private-key
URI. Each module instance owns a D-Bus grant, producing two choosers about three seconds apart.
A third chooser is a regression to investigate. The 2026-09-05 live Entra run observed a third
prompt from server-chain verification before a challenge; phase 0 checks that search class.

Process-tree delegation cannot support Flatpak identity and can cross application boundaries.
Its code is archived on `experimental/certificate-webauthentication+delegation`;
[ADR 0011](decisions/0011-client-side-pkcs11-module.md) discusses app-info-scoped alternatives.
The module refuses exactly `xdg-desktop-portal` and `xdg-desktop-portal-certificate`, allowing
the consumer executable `xdg-desktop-portal-webauth`.

### 2.56 NSS headless tests

NSS consumers include Firefox, Thunderbird, LibreOffice and Evolution [[S54](SOURCES.md)].
`nss-smoke.sh` loads the shared object directly with `modutil -add -libfile`, matching Firefox's
Security Devices loader. It uses the same private stack as §2.5.

```console
$ ninja -C build
$ tools/softhsm-fixture.sh
$ tools/nss-smoke.sh
$ tools/nss-smoke.sh --phase 1        # just the private-key path
$ tools/nss-smoke.sh --phase 3        # just the handshake
$ tools/nss-smoke.sh --phase 4        # same-process expiry and reacquisition
```

Prerequisites are `nss-tools`: `certutil`, `modutil` and `tstclnt`. Phase 4 also needs NSS
development headers (`nss-devel` on Fedora); Meson builds `tests/nss-refresh-client` when
`pkg-config nss` is available. Reconfigure with `meson setup --reconfigure build` after adding
the headers. `NSS_REFRESH_CLIENT` can select a different build's helper. Fedora places `tstclnt` in
`/usr/lib64/nss/unsupported-tools`. Unpacked packages can be used with `NSS_BIN` pointing to
their `usr/bin`, or `TSTCLNT` naming that binary; download with `dnf download nss-tools`
and extract with `rpm2cpio`/`cpio` as above.

0. `modutil -list portal` names the token; whole-database `certutil -L` leaves grant counts unchanged.
1. `certutil -K -h "Portal Certificate"` finds a private key without enumeration opt-in.
   `CKA_CLASS=CKO_PRIVATE_KEY` establishes intent even with `CKA_TOKEN`. Output must not contain
   `Error opening input terminal for read`, which indicates the application's password callback.
2. `certutil -L -h "Portal Certificate"` returns no objects without enumeration opt-in, then
   acquires with `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1`. `u,u,u` means NSS matched a user
   certificate to the token's private key.
3. `tstclnt -n "Portal Certificate:Portal Certificate"` uses a `token:nickname` label search and
   needs no opt-in. It completes mutual TLS against the same Python server as §2.5.
4. `nss-refresh-client` initializes NSS once, resolves the certificate and key by nickname,
   signs and verifies a signature, then polls `PK11_IsPresent` until NSS advances the slot
   series after expiry. It retains the first certificate and key, resolves a replacement key
   with a different handle and signs and verifies again in the same process. The private stack
   and chooser driver stay running. Exactly two `grant-created` events are required.
   `tstclnt -Q` remains the TLS check in phase 3; the helper provides presence/cache assertions.

Phase 4 uses real grant expiry with `PKCS11_PORTAL_CERTIFICATE_REQUESTED_LIFETIME=20`, not a
simulated card event. The module forwards this optional environment setting as
`requested_lifetime`; valid values are 1–3600 seconds and invalid values leave the frontend's
default unchanged. The frontend may shorten the requested lifetime. The helper has a 45-second
refresh deadline after its first signature; the phase has a 180-second overall timeout.
Expect `first signature verified`, `NSS refreshed the token` and
`PASS: two verified signatures across expiry in one NSS process` in `nss-refresh-client.log`.
Failure to advance the slot series, replacement-handle reuse, either failed signature or an
unexpected grant count fails the phase. There is no module reload, NSS reinitialization or
explicit NSS cache flush between signatures.

Expected output:

```
=== 0  the token is visible, and listing the database asks for nothing ===
grants before=0 after=0
nss-smoke: the token is there and neither listing acquired a credential

=== 1  certutil -K: the private key, and NO password callback ===
< 0> rsa      6f5e40f180d8d48da9f587e6273bd8b87bb51327   Portal Certificate
grants before=0 after=1
nss-smoke: one chooser, one key, and no login was asked for

=== 2  certutil -L: the certificate list needs the enumeration opt-in ===
grants before=1 without=1 with=2
Portal Certificate:Portal Certificate                        u,u,u
nss-smoke: no chooser without the opt-in; with it, one user certificate

=== 3  tstclnt: a real TLS client-auth handshake, NSS end to end ===
client certificate: {'organizationName': 'Example Org', 'commonName': 'Portal Test User (RSA)'}
protocol: TLSv1.3 cipher: TLS_AES_256_GCM_SHA384
PASS Portal Test User (RSA)
nss-smoke: PASS
```

The tools receive `</dev/null` so terminal prompts cannot block. `modutil -force` does not
silence its p11-kit configuration prompt. `tstclnt -Q` exits on closed stdin; omitting it can
loop after a successful handshake. NSS uses plain `dlopen()`, so all phases can load the
sanitized module:

```console
$ meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false
$ ninja -C build-asan
$ LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=detect_leaks=0     MODULE_SO=$PWD/build-asan/src/module/libpkcs11-portal-certificate.so     NSS_REFRESH_CLIENT=$PWD/build-asan/tests/nss-refresh-client     tools/nss-smoke.sh --phase "1 2 3 4"
```

For consumers loaded through p11-kit, add this line to
`xdg-desktop-portal-certificate.module` to enable enumeration without setting a launcher environment:

```ini
x-init-reserved: enumerate=1
```

p11-kit passes the value to `C_Initialize` through `pReserved`. `enumerate=0` or omission
leaves enumeration off unless `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` is set. User module
files under `~/.config/pkcs11/modules/` can override the installed file. Direct NSS loading
uses the environment switch because it does not read these files. The `module-portal` tests
cover both direct initialization and forwarding from a p11-kit module file on a private bus.
They also cover reselection after logout, close-all and portal session closure, issued-ID
matching and cancellation across different templates; no card or display is required.
Invalidation tests cover `token_removed`, `expired`, `policy`, `backend_gone`, `error` and
local expiry: old sessions fail, the slot stays present and removable, one nonblocking event
is reported, issued-ID acquisition still works and old-generation handles remain refused.
Pending search, signing and decryption state cannot survive the transition.

### 2.6 Firefox

Confirmed on 2026-09-06 with Firefox, a throwaway profile, direct Security Devices loading and
a PIV card: portal chooser, Firefox picker, PIN prompt and successful site authentication.
No Protected Authentication alert appeared.

NSS authenticates non-friendly slots before `PK11_ListCertsInSlot()`. A manually loaded module
is not friendly. `CKF_LOGIN_REQUIRED` would invoke Firefox's protected-path callback, whose modal
`Alert()` waits for OK before the certificate search, even if `C_Login` has already returned.
The 2026-09-06 failure report recorded that alert, no frontend session/acquisition and no chooser;
[ADR 0011](decisions/0011-client-side-pkcs11-module.md) and [[S59](SOURCES.md)] explain it.
[The module login flags](ARCHITECTURE.md#client-side-pkcs11-module) avoid that alert.
`CKA_TOKEN=CK_FALSE` requests unsupported session objects;
[search intent](SECURITY.md#search-intent) covers persistent-token searches.

1. Build or install `libpkcs11-portal-certificate.so`. Start Firefox with
   `PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1`; its class-only certificate listing otherwise sees
   no objects. Private-key and token:nickname searches do not need the opt-in.
2. In Settings, Privacy & Security, Security Devices, Load, give the shared-object path.
   Direct loading does not read p11-kit configuration. On distribution builds using
   p11-kit-proxy instead, add `firefox` to the installed `enable-in:` list or a per-user override;
   enumeration can use `x-init-reserved: enumerate=1` in that file.
   See [the allowlist](decisions/0011-client-side-pkcs11-module.md#the-module-is-opt-in-by-name-and-the-shipped-file-is-the-allowlist).
   Do not combine `enable-in` and `disable-in`; p11-kit consults only the former when both exist.
3. Start the portal stack with a card or fixture, then visit a site requiring a client certificate.
4. Expect portal chooser at search, Firefox's own one-certificate picker, then backend PIN
   interaction at first `Sign`. A Protected Authentication alert indicates `CKF_LOGIN_REQUIRED`.

For single-prompt selection, set `security.default_personal_cert` to `Select Automatically`
in `about:config`. Firefox then uses the first candidate with a private key. The module exposes
only the certificate selected in the portal chooser, so Firefox's picker is skipped.
The Flatpak helper's `--auto-select` option sets this preference in its test profile.

To check removal/reinsertion in Firefox (including Flathub Firefox with §2.7), keep the same
browser and portal stack running:

1. Load this build's module and authenticate to a client-certificate site. Confirm
   `grant acquired`, object searches and a completed signature in the logs.
2. Remove the card and wait for the backend's detected removal and the module's
   `grant invalidated: token_removed` message before reinserting it. Removal between backend
   discovery polls can be missed.
3. Reinsert the same card and make the site request a fresh TLS client-certificate handshake
   (close the site's connections or use a different client-auth endpoint to avoid TLS resumption).
4. Expect a new portal chooser, a new grant, certificate/key searches and a successful signature
   within the next NSS presence poll, without restarting Firefox or waiting five minutes.
   Repeat the cycle and retain frontend, backend and module logs. A client-certificate error,
   new grant followed by only one search without signing, or stale-handle refusal after fresh
   selection is a failure.

Repeated enumeration and hardware-specific object changes after expiry still need live testing.
The recorded NSS `[CKA_ISSUER, CKA_SERIAL_NUMBER]` lookup returned no object even with a grant; certutil listing
survived and the Firefox path did not depend on it. That compatibility gap remains open.

### 2.7 Firefox Flatpak

Run 2026-09-07: pass. Firefox 155.0.1 from Flathub, `org.freedesktop.Platform//25.08`,
`--nosocket=pcsc --nodevice=all`, module in app data, real PIV card, GNOME 50/Wayland and
`--pin-prompt=system`. Recorded backend log:

```
15:20:31  request-received    app_id=org.mozilla.firefox identity=(none)     purpose=create_session granted=yes
15:20:31  discovery-started   app_id=org.mozilla.firefox identity=sandboxed  purpose=client_auth
15:20:31  discovery-result    tokens=1 candidates=4
15:20:31  chooser-shown       app_id=org.mozilla.firefox identity=sandboxed  purpose=client_auth
15:20:45  grant-created       app_id=org.mozilla.firefox identity=sandboxed  purpose=client_auth granted=yes
15:20:51  request-received    mechanism=RSA_PSS
15:20:51  pin-prompted        detail=on-screen
15:20:55  login-ok            detail=pin-accepted
15:20:56  operation-completed mechanism=RSA_PSS
15:21:13  grant-invalidated   detail=closed-by-portal
```

There was one portal chooser, Firefox's picker, one PIN and one signature accepted by the site.
The frontend derived `org.mozilla.firefox` and `sandboxed` from the caller. The sandbox reached
the card through module, D-Bus and backend. The installed Firefox permissions included
`sockets=pcsc` and `devices=all`; `flatpak info --show-permissions org.mozilla.firefox` shows
permissions for an installed version.

Checks on 2026-09-07 found the host module needed glibc 2.14, linked libraries available in that
runtime (GLib/GIO, GnuTLS, p11-kit and dependencies), and loaded inside the sandbox. Sandbox
gdbus saw the experimental interface with the branch frontend live; the restricted run lacked
`/run/pcscd`. Two discovery failures before the successful run reported `tokens=0` with the
card absent. Check `--list-tokens` and `opensc-tool -l` first in that case.

Start the live stack in one terminal:

```console
$ tools/dev-stack.sh --live --keep --no-e2e --pin-prompt=system
```

`--no-e2e` skips the script's own chooser, PIN and signature before the browser test.
In another terminal:

```console
$ flatpak install flathub org.mozilla.firefox      # once
$ tools/firefox-flatpak.sh --fresh --auto-select
```

The script copies the module to `~/.var/app/org.mozilla.firefox/data/`, creates a scratch profile,
checks sandbox pcsc absence and portal visibility, then launches with enumeration opt-in and
both direct-device permissions removed. `--fresh` resets the test profile; `--check` stops after
verification; `--keep-pcsc` is the installed-permissions control; `--url` opens a site;
`--module` selects another built module.

Once per profile, load the printed module path through Firefox's Security Devices dialog.
The `.module` allowlist is not involved in this direct loading. Visit a client-certificate site.
With `--auto-select`, expect the portal chooser followed by the portal PIN prompt, with no
Firefox certificate dialog. Correlate the backend's
`app_id=org.mozilla.firefox identity=sandboxed purpose=client_auth granted=yes` with
`CreateSession`/`AcquireCredential` in `$DEVDIR/frontend.log`. An alert, empty certificate list
or unidentified caller needs investigation. Compatibility with other runtime versions remains
unproven.

#### Single-prompt Firefox procedure

Close the test Firefox before changing its profile. After the initial module load, reuse it:

```sh
tools/firefox-flatpak.sh --auto-select --url https://mtls.example.org
```

Replace the URL with a site that requests your card's client certificate. `--auto-select`
writes `user_pref("security.default_personal_cert", "Select Automatically");` once in the test
profile's `user.js`. Runs without either selection option preserve the profile's setting.
To restore Firefox's picker, close the test Firefox and run:

```sh
tools/firefox-flatpak.sh --ask
```

`--ask` removes the preference from `user.js` and its saved value in `prefs.js`.
`--fresh` deletes the test profile, including its module registration.

Confirmed on 2026-10-16 with Flathub Firefox and a PIV card
([issue #13](https://github.com/sjtrotter/xdg-desktop-portal-certificate/issues/13)):
the portal chooser appeared, then the portal PIN prompt; Firefox showed no certificate dialog.
Private windows within the five-minute grant reused the selected certificate. Opening Firefox's
certificate manager opened the portal chooser before visiting any site; listing needed no PIN.
The first signature required the PIN.

On Fedora the Flatpak-exported `org.mozilla.firefox.desktop` can shadow the RPM launcher and
select an empty Flatpak profile. The host profile under `~/.config/mozilla/firefox` remains
separate. The script copies the RPM launcher to `~/.local/share/applications/` if no user
launcher exists. Removing the user Flatpak with `flatpak uninstall --user org.mozilla.firefox`
also removes that exported launcher.

### 2.8 Chrome Flatpak

Tested once on 2026-10-16 with a PIV card; results are at the end of this section. This procedure targets Flathub `com.google.Chrome` and requires the built
portal module, the live portal stack from §2.7, a card and host `nss-tools` for `modutil`.
Set `MODUTIL=/path/to/modutil` if it is not on `PATH`. Chrome has no module-loading UI;
the helper registers the module with `modutil -dbdir sql:<database-directory> -add`.

Install Chrome, start it once to create its profile, then quit it completely (background
processes can outlive the last window; `flatpak kill com.google.Chrome` stops them). The helper
refuses to run while Chrome is running:

```sh
flatpak install flathub com.google.Chrome
flatpak run com.google.Chrome
```

Chrome's Flatpak wrapper links the host's `/etc/opt/chrome/policies/managed/` files into the
sandbox. Install a policy for the site that requests your certificate; replace the example
pattern before running these commands:

```sh
sudo install -d -m 0755 /etc/opt/chrome/policies/managed
sudo tee /etc/opt/chrome/policies/managed/portal-certificate.json >/dev/null <<'POLICY'
{
  "AutoSelectCertificateForUrls": [
    "{\"pattern\":\"https://[*.]example.org\",\"filter\":{}}"
  ]
}
POLICY
sudo chmod 0644 /etc/opt/chrome/policies/managed/portal-certificate.json
```

`AutoSelectCertificateForUrls` takes an array of JSON strings. The empty filter accepts any
certificate offered for the matching site; the portal chooser determines which one this module
offers. The policy applies to every matching site in host Chrome and the Flatpak.

Keep the live stack running in another terminal, then launch the helper:

```sh
tools/chrome-flatpak.sh --site 'https://[*.]example.org' --url https://mtls.example.org
```

The helper copies the module to `~/.var/app/com.google.Chrome/data/`, finds `cert9.db` under
`~/.var/app/com.google.Chrome/`, and registers the copied library unless it is already listed.
`--site` prints policy JSON inside exact host installation commands; the helper never runs
`sudo`. A missing policy also prints commands, using `https://[*.]example.org` unless `--site`
was given. Chrome can still show its picker until the policy is installed and loaded.

Chrome M146 and later use `$HOME/.local/share/pki/nssdb`, while an existing `$HOME/.pki/nssdb`
still takes precedence. The helper discovers the persistent Flatpak database rather than
assuming either location. No database produces `start Chrome once to create its profile`;
multiple databases stop setup and print their paths. In the 2026-10-16 run Chrome used
`~/.var/app/com.google.Chrome/data/pki/nssdb` and loaded the copied library from there.

Open `chrome://policy`, reload policies and confirm `AutoSelectCertificateForUrls` has the
intended pattern and no errors. Visit the matching client-certificate site. Expect the portal
chooser and portal PIN prompt, with no Chrome picker, and a successful sign-in. Check the
backend log for `app_id=com.google.Chrome identity=sandboxed`, `grant-created`, `login-ok`
and `operation-completed`. A Chrome picker despite a valid matching policy, or no portal
chooser, needs investigation of the database and module path printed by the helper.

After closing Chrome, verify the setup without copying or registering anything:

```sh
tools/chrome-flatpak.sh --check
```

The helper passes `--env=PKCS11_PORTAL_CERTIFICATE_ENUMERATE=1` on each run, so the opt-in
does not persist. Default launches remove the pcsc socket and all device access with
`--nosocket=pcsc --nodevice=all`. If removing devices prevents Chrome's GPU startup, use:

```sh
tools/chrome-flatpak.sh --keep-devices --url https://mtls.example.org
```

`--keep-devices` keeps device access while removing the pcsc socket. `--keep-pcsc` retains both
installed permissions for comparison. `--module PATH` selects another built module.
The current manifest uses `org.freedesktop.Platform//25.08`, as in the Firefox module-loading
run.

Results 2026-10-16 (PIV card, default launch without the pcsc socket or devices):

- Without a matching policy, Chrome shows its own picker after the portal chooser.
- `chrome://policy` listed the policy as Platform, Machine, Mandatory, OK. The pattern must
  match the host that requests the client certificate. For the tested site that was a separate
  Microsoft certificate-login host, not the site's own domain. With that host in the pattern,
  the flow was portal chooser, portal PIN prompt, successful sign-in, with no Chrome picker.
- Within the grant lifetime, a second site and a private window reused the grant (no chooser,
  no PIN) but showed Chrome's picker, because their hosts were outside the pattern. After the
  grant expired, a new private window showed the chooser and PIN prompt again.
- `https://client.badssl.com/`: portal chooser only, then rejection; no Chrome picker and no
  PIN prompt, since the card's certificate does not match the server's CA list.
- Per-host patterns are workable only in managed deployments. A `"*"` pattern with an issuer
  filter, the equivalent of Firefox's "Select Automatically", is untested.

## 3. Real PIV card

Tiers 3.1–3.4 have a single-card result. Read this section before inserting a card: the live
stack replaces the session portal, and the optional wrong-PIN check spends a failed attempt.

### 3.0 Sequence

Run discovery, private-bus signing, private-bus cancellation, then live signing. Follow with
same-grant reuse only when a suitable client exists; retry checks require a healthy card you
can unblock. Stop at an unexpected result and retain the backend log. Successful PIN validation
can reset a retry counter; a wrong PIN consumes one.

### 3.1 Card discovery

```console
$ systemctl status pcscd.socket pcscd.service
$ pkcs11-tool --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-token-slots
$ ./build/src/xdg-desktop-portal-certificate --list-tokens
```

If p11-kit has no OpenSC configuration:

```console
$ ./build/src/xdg-desktop-portal-certificate \
      --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-tokens
```

A missing token in pkcs11-tool indicates a reader/card/pcscd problem before portal testing.
The backend prints token and certificate blocks: subject, issuer, expiry, key type/size,
mechanisms, purposes, PIV slot where known and a stable id. Display text is sanitized; pipe to
`cat -v` to inspect bytes. Serial output is `****` plus its last four characters; full serials
are not logged ([SECURITY.md](SECURITY.md)).

`hardware yes (CKF_HW_SLOT)` is expected for a reader; software slots are skipped without
`--allow-software-tokens` or explicit `--module`. A protected-path reader gets instructions
without a PIN entry; the typed wrong-PIN recipe below does not apply. Recent-failure warnings
mean skip §3.6. A final-attempt warning means stop and reset the counter. Expired certificates
remain offered and marked. Missing usable certificates can indicate key/ID, mechanism or
purpose restrictions; hidden keys are handled as [documented](IMPL-INTERFACE.md#discovery-before-login).

### 3.2 Private-bus signing

```console
$ tools/dev-stack.sh -- --purpose client_auth --reason "Testing the certificate portal"
```

The backend inherits the desktop display but uses a private bus and defaults to its GTK PIN
window. The chooser is titled "Use a Certificate". This Python caller is unidentified and must
be labelled accordingly. Purpose text describes proving identity to a server; `reason` appears
inside "The application says", outside trusted identity. Rows show certificate, validity, key,
token and reader; the window states scope and duration. Check the desktop color scheme.

Choose a certificate. At `Sign`, "Unlock Security Token" names caller, purpose, token and reader.
`may_prompt_later=true` describes this lazy login. Enter the PIN; expect a signature length,
`verified  signature checks against the returned certificate`, and `PASS`. A verification failure
can indicate the wrong key or encoding; retain logs.

### 3.3 Private-bus cancellation

```console
$ tools/dev-stack.sh -- --purpose client_auth --cancel-after 5000 --expect-cancelled
```

The client closes the Request after five seconds. Expect prompt closure, `chooser-cancelled`,
no grant and no later Response. Client-side cancellation prints
`PASS cancel: Close() delivered, no Response`. Escape or the window close button instead
produces `cancelled by the user` and exit 2.

### 3.4 Live bus and system PIN prompt

Proceed after 3.1–3.3 pass. This takes `org.freedesktop.portal.Desktop` from the installed
portal for the run:

```console
$ tools/dev-stack.sh --live -- --purpose client_auth
```

On GNOME, `auto` selects the shell-owned prompter. Its session-modal dialog is not parented
to the application; see [PIN transport](SECURITY.md#pin-entry-and-transport).
Press Return in an empty field: expect "Enter the PIN for this token.", no `pin-incorrect`
and no consumed attempt. If cancellation lands after submission, expect `cancelled`; successful
late login logs `login-ok detail=cancelled-after-login` and
`login-ok detail=abandoning-cancelled-login`.

A card can validate in tens of milliseconds, making post-submission cancellation impractical by
hand. `/pin-system/shell-cancel-after-the-pin-was-submitted` tests it with a scripted prompter.
GNOME's prompter is gnome-shell; killing it ends the session. Test disappearance with the private
prompter cases `prompter-vanishes-during-open`, `prompter-vanishes-during-password` and
`prompter-vanishes-during-confirm` in `tests/test-pin-system.c` instead.

Prompt selection appears as:

```
** Message: pin-prompt-selected detail=system
```

Compare with explicit GTK:

```console
$ tools/dev-stack.sh --live --pin-prompt=gtk -- --purpose client_auth
```

The chooser belongs to the backend in both runs.

### Observed on real hardware (2026-09-04)

Tiers 3.1–3.4 passed once against one PIV card, OpenSC, an SCR 331-class reader and GNOME 50
on Wayland. Discovery parsed every certificate; private signing/cancel behaved as described;
live system prompting passed, including empty-Return and chooser cancellation. The backend log
measured about 40 ms for PIN validation and 0.26 s for a signature. Disabling private-bus Secret
activation reduced startup from roughly 25 s to 2 s. These are measurements from one setup.

### 3.5 One PIN per grant

Unrun on hardware. Verify two sequential signatures and two concurrent signatures under the same
grant with `CKA_ALWAYS_AUTHENTICATE=FALSE`: one login prompt and successful results for all
live waiters. Keys with `CKA_ALWAYS_AUTHENTICATE=TRUE` require another PIN interaction for each
signature. No current command in `certificate-e2e.py` keeps a grant for a second signing
operation. Separate invocations create
separate connections/grants, and `--regrant` creates another session, so neither tests this
property. The broker and cancellation unit tests cover software-side sharing.

`/device/always-authenticate` generates a temporary token key in the SoftHSM fixture, verifies
two signatures and checks a context-specific login for each. The key is removed after the test.
`/pin-system/broker-context-login` checks two concurrent signatures with separate scripted PIN
prompts and asserts that each context login follows `C_SignInit`. It needs a private D-Bus but
no display or hardware.

### 3.6 Wrong PIN and final attempt

Optional and unrun on hardware. Use a healthy card that you can unblock; a typical PIV card
allows three failed attempts. This check intentionally spends one:

```console
$ tools/dev-stack.sh --live -- --purpose client_auth
```

Enter a wrong PIN, then the correct one. The prompt should offer a retry without failing the
request, refresh `CKF_USER_PIN_COUNT_LOW` and show recent-failure wording without an invented
count. If `CKF_USER_PIN_FINAL_TRY` appears, typed PIN entry must show and announce the warning
before input, both at open and after a wrong-PIN refresh; one Unlock submits. Cancel spends no
attempt. A PIN-pad reader instead requires one Continue before starting on the final try;
Cancel must leave the counter unchanged, and repeated Continue must not restart the reader.
Expect `pin-incorrect ... detail=retry-offered`. One prompt stops
after three refusals; a new application request is a separate prompt.

### 3.7 Removal and other hardware checks

Unrun. Remove during signing, between initialization and signing, between consent and first use,
and during PIN entry; expect a clean failure and invalidation when detected. Test same-card and
same-label different-card reinsertion. A detected removal must require reselection. Polling may
miss a quick removal/reinsertion; identity re-resolution and an open session's device-removal
errors provide additional checks. [SECURITY.md](SECURITY.md#card-removal-and-grants)
records the limit. Reader unplug, pcscd restart, multiple readers and a PIN-pad reader need
separate runs.

[PIN cancellation rules](SECURITY.md#login-retries-and-cancellation) apply during these checks,
including flag refresh after refusal and abandonment of late login success.

OAEP with non-SHA1 hashes or labels remains unproven against a compatible module; SoftHSM 2.x
refuses those parameters. No live-stack command can test this, because neither interface exposes
`Decrypt`. Internal decryption accepts only RSA-OAEP; PKCS#1 v1.5 is refused.

### 3.8 Restore the session and upgrade the backend

```console
$ busctl --user status org.freedesktop.portal.Desktop
```

After stack exit, `Exe=` should identify `/usr/libexec/xdg-desktop-portal`. If activation has not
occurred, request it:

```console
$ busctl --user introspect org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop >/dev/null
```

Check for remaining development processes:

```console
$ pgrep -af 'xdg-desktop-portal(-certificate)?' | grep -v /usr/libexec
```

No output is expected. Backend replacement requires the current owner to permit it:

| Option | Meaning |
|---|---|
| `--allow-replacement` | Permit a later process to take the name; absent from installed activation |
| `--replace` | Ask to replace a permitting owner |

D-Bus cannot authenticate the replacement. Upgrade by stopping the old backend and allowing
activation of the installed binary:

```console
$ pkill -f xdg-desktop-portal-certificate     # or systemctl --user stop, where it is a unit
# The next backend call activates the installed binary.
```

Development `dev-stack.sh --live` passes both flags so successive runs can replace each other.
Use restart/activation for installed instances.

## Reading logs

Backend events use the [logging fields and redaction rules](SECURITY.md#logging) in `src/redact.h`:

```
request-received      an impl method arrived
discovery-started     token enumeration began
discovery-result      how many tokens, how many candidates; inventory excluded
no-matching-certificate
chooser-shown         the consent window went up
consent-granted       the user picked one
chooser-cancelled     the user did not
grant-created         a grant a user answered a window for
pin-prompt-selected   detail=gtk | system; entry owner
pin-prompted          detail=on-screen | protected-path
pin-prompt-failed     detail=system-prompter[-unreachable]; prompter failure
pin-prompt-dismissed  detail=system-prompter; prompter dismissal
pin-prompt-round-completed-twice  gcr completed one round twice; the second was ignored
pin-incorrect         an attempt was spent
pin-locked            terminal
pin-timeout           a submitted C_Login did not return; the prompt came down
colour-scheme         detail=dark | light | forced | no-schema (--verbose only)
login-ok
operation-refused     a check said no; the mechanism name says which
operation-completed
grant-invalidated     detail says why
token-removed
```

`--verbose` enables diagnostic events for `xdg-desktop-portal-certificate` and
`pkcs11-portal-certificate`. Library debug output, including `Gcr`, stays disabled unless
requested through `G_MESSAGES_DEBUG`, which works with or without `--verbose`. For example,
`G_MESSAGES_DEBUG=Gdk` adds GDK output. Gcr debug output can contain secret-exchange payloads,
including the encrypted PIN transfer.

Sign operation logs include `session=<session_handle>`
and `operation=<operation_id>` for correlation with the frontend journal. An absent
`operation_id` appears as `(none)`. Both ids follow the [log field rules](SECURITY.md#logging).

## Troubleshooting

| Symptom | Check |
|---|---|
| Experimental Certificate interface absent | Frontend branch `experimental/integration`, configured impl backend and startup `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=Certificate1`; introspect the desktop path |
| No frontend Certificate routing log | `.portal` interface, `XDG_DESKTOP_PORTAL_DIR` and `portals.conf` |
| Backend disconnected without replying | Crash; hardening disables dumps. Use `--debug-allow-core` only for development debugging, using a disposable fixture |
| Wrong window theme | Compare `--verbose` `colour-scheme` with `gsettings get org.gnome.desktop.interface color-scheme`; inspect `follow_colour_scheme()` if they disagree |
| `--pin-prompt=system` requires gcr-4 | Rebuild with `-Dgcr=enabled`, or use `--pin-prompt=gtk` or `auto` |
| System prompt unavailable | Check the prompter on the backend's bus; failure is `no_display`, with `pin-prompt-failed detail=system-prompter-unreachable`. A private bus may activate a fallback, but has no shell |
| Software token skipped | Pass `--allow-software-tokens` or explicit `--module` |
| Missing fixture marker | Existing directory is refused; remove it manually only if disposable |
| Marker mode 644 | Set a valid fixture marker to 0600 or recreate with its script |
| Login timeout | Submitted attempt cannot be cancelled. Configure the backend's `--login-timeout` or `--login-timeout 0` for slow middleware; late success is abandoned |
| Every impl call gets `AccessDenied` | Caller must own `org.freedesktop.portal.Desktop` |
| Internal `interaction_required` | Interaction forbidden after successful enumeration; identical for no token, no match and match |
| Internal `no_display` | No usable display after successful enumeration; identical for no token, no match and match |
| Empty chooser | Insert a token; watch the filtered list update. Use stays disabled without a selection; Cancel answers `1` |
| Internal `device_error` | Middleware failure remains visible; serial-less tokens are refused after selection |
| `Sign` with `invalid_request` | Mechanism, parameter type or digest length; see [IMPL-INTERFACE.md](IMPL-INTERFACE.md) |
| Existing session gives `no_such_session` | Different `app_id` or increased identity level |
| Reused session path rejected | A live session occupies it; close first. Closed entries are replaceable |

The backend's `error` diagnostic is not forwarded by the frontend; the public response may carry
a different recognized `reason`.

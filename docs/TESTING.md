# Testing

Three tiers, in the order they become possible, and only the third needs a card. What each tier
can and cannot tell you is [tests/README.md](../tests/README.md); this file is the **commands**.

Everything here has been run on Fedora 44 except tier 3, which is the author's and has never been
run by anyone. **No real smart card has ever been read by this code.**

---

## 0. Build and run what needs nothing

```console
$ meson setup build -Dwarning_level=2 -Dwerror=false
$ ninja -C build
$ meson test -C build
```

Six suites:

| Suite | Needs | What it covers |
|---|---|---|
| `filter` | nothing | purpose and `certificate_filter` matching against fixture certificates |
| `mechanism` | nothing | the mechanism mapping, the digest-length rule, the PSS parameters and the `MGF1-<hash>` spelling, the OAEP parameters and `CK_RSA_PKCS_OAEP_PARAMS`, **that only `RSA_OAEP` may decrypt and only the three signing mechanisms may sign** |
| `redact` | nothing | the redactor, the display-text sanitiser, that a newline in an app id cannot forge a journal line |
| `broker-device` | a SoftHSM fixture, and `openssl(1)` for the OAEP half | `C_Login`, `C_Sign`, signature verification, and an **RSA-OAEP round trip** against a ciphertext `openssl pkeyutl` produced. **Skips itself** without one; see tier 2 |
| `broker-decrypt` | a SoftHSM fixture | the two properties that make `Decrypt` safe to offer: **one indistinguishable error** for every failure, and the **per-grant budget**. **Skips itself** without one |
| `impl-dbus` | nothing (it stands up its own `GTestDBus`) | the D-Bus boundary: a stranger calling every method including both `Close()`s, cross-`app_id` session use, session-path reuse, strict option validation, the results vardict's types |
| `cancellation` | a display for two of three, a SoftHSM fixture for the third | cancelling while `C_Login` is in flight, cancelling before the window is up, cancelling a signature |

### Under a sanitizer, which is where the cancellation tests earn their keep

Three of the defects the 2026 review found were use-after-frees on cancellation paths, and none of
them was reachable by a test that only checked return values. Run the whole suite again with
AddressSanitizer and UndefinedBehaviorSanitizer:

```console
$ meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false
$ meson test -C build-asan
```

**If every suite exits 127**, the sanitizer runtime is missing rather than the tests being broken:
`ldd build-asan/tests/test-mechanism` says `libasan.so.8 => not found`. It ships in `libasan` /
`libubsan`, which do not have to be installed system wide either — unpack them beside everything
else and point the loader at them, which wins over the binary's own `RUNPATH`:

```console
$ dnf download --arch=x86_64 libasan libubsan
$ mkdir -p ~/scratch/asan-rt && cd ~/scratch/asan-rt && for f in ../*.rpm; do rpm2cpio "$f" | cpio -idmu; done
$ LD_LIBRARY_PATH=~/scratch/asan-rt/usr/lib64 meson test -C build-asan
```

`tests/lsan.supp` suppresses the one-time allocations GTK, GnuTLS and p11-kit keep for the life of
the process. **Nothing under `src/` is suppressed**: a leak reported against this backend's own
code is a defect.

To check that the cancellation tests still fail when the bug is put back, make
`pin_prompt_finish()` answer immediately while a login is in flight and hand the worker the
prompt's own buffer instead of a copy — `/cancel/during-login` fails on the assertion that nothing
has been answered yet.

**`/cancel/during-login` opens a real PIN window** for a fraction of a second: it drives this
process's own prompt rather than needing `xdotool`. It skips itself when `gtk_init_check()` fails,
so a headless CI run reports it as skipped rather than failed. Run the suite under `Xvfb` if a
window appearing on your desktop is a problem.

```console
$ ./build/src/xdg-desktop-portal-certificate --help
$ ./build/src/xdg-desktop-portal-certificate --version
```

---

## 1. A private bus, with nothing in the reader

This proves the plumbing: that the frontend finds the `.portal` file, matches the impl interface,
exports the public one, activates this backend, and that a request with no card comes back as a
clean refusal rather than a hang.

### What it needs first

The frontend is a **local branch of xdg-desktop-portal**,
`experimental/certificate-webauthentication`, and it has a hard dependency on libdex which Fedora
does not install by default. If it was built against a scratch prefix, put the environment for it
in `.xdp-env` in this repository — the file is gitignored, and both `tools/dev-stack.sh` and
`tools/ui-smoke.sh` source it:

```sh
# .xdp-env
export LD_LIBRARY_PATH=/path/to/scratch/prefix/lib64
```

The frontend binary's `RUNPATH` already names the prefix it was built in, so it may work with no
`.xdp-env` at all — until that prefix is deleted. If the prefix was under `/tmp`, copy the one
library that is not packaged (`libdex-1.so.1`) somewhere that survives a reboot and point
`LD_LIBRARY_PATH` at it: `LD_LIBRARY_PATH` wins over `RUNPATH`. Rebuilding libdex from scratch is
`FreeRDP-plan/XDP-BRANCH.md` section 4.

`tools/dev-stack.sh` checks with `ldd` and says so if the frontend cannot resolve its libraries.

### The run

```console
$ tools/dev-stack.sh -- --expect-no-certificate
```

**What to look for in the output**, in order:

```
XDP: Found 'certificate' in configuration for org.freedesktop.impl.portal.experimental.Certificate
XDP: Using certificate.portal for org.freedesktop.impl.portal.experimental.Certificate (interface specific config)
XDP: Providing portal org.freedesktop.portal.experimental.Certificate
XDP: org.freedesktop.portal.Desktop acquired
```

then, from the backend:

```
** Message: request-received app_id=(none) identity=(none) purpose=create_session granted=yes
** Message: discovery-started app_id=(none) identity=unidentified purpose=client_auth granted=no
** Message: discovery-result tokens=0 candidates=0
** Message: no-matching-certificate tokens=0 candidates=0
```

and from the client (`operations` is `['sign', 'decrypt']`; `RSA_OAEP` is the only mechanism
`Decrypt` will take, and [IMPL-INTERFACE.md](IMPL-INTERFACE.md) says why):

```
GetCapabilities:
  max_grant_lifetime               3600
  mechanisms                       ['RSA_PKCS1_V1_5', 'RSA_PSS', 'RSA_OAEP', 'ECDSA']
  operations                       ['sign', 'decrypt']
  protected_authentication_path    False
  purposes                         ['client_auth', 'signing', 'email', 'ssh']
  selection_memory                 True

AcquireCredential answered 2 with no grant, as expected.
PASS (plumbing: the frontend reached the backend and the backend refused cleanly)
```

`app_id=(none)` and `identity=unidentified` are correct here: the client is a bare python script
on a private bus, so the frontend has nothing to identify it by, and the backend says so rather
than inventing a name. **That is the identity level doing its job.**

To poke it by hand instead, leave the stack up:

```console
$ tools/dev-stack.sh --keep --no-e2e
```

and use `tools/trigger-certificate.sh` or `gdbus` from another shell with the
`DBUS_SESSION_BUS_ADDRESS` it prints.

---

## 2. A software token, with nobody at the keyboard

A rehearsal. It proves the cryptography and the windows; it proves nothing about hardware.

```console
$ tools/softhsm-fixture.sh
$ meson test -C build broker-device --verbose
```

`broker-device` opens a session on the fixture token, logs in, signs with RSA PKCS#1 v1.5 over
SHA-256 and SHA-384, with RSA-PSS and with ECDSA, and **verifies each signature against the
certificate the token handed back** — not against the key the fixture script generated. It asserts
that **every** spelling of a decryption request is refused. It checks that a wrong PIN comes back as
`PIN_INCORRECT` and not as a generic failure, and that discovery sees both certificates without
logging in.

`tools/softhsm-fixture.sh` refuses to write into a directory it does not own or that is reached
through a symlink, and tightens the mode to 700 if it has to: what lives in that directory includes
the module path the backend `dlopen()`s.

Then the whole thing including the windows, in a headless X server:

```console
$ tools/ui-smoke.sh                                        # RSA
$ tools/ui-smoke.sh --key-algorithm EC                     # ECDSA, raw r||s
$ tools/ui-smoke.sh --key-algorithm EC --der               # ECDSA, DER
$ tools/ui-smoke.sh -- --decrypt --oaep-hash SHA1          # and the OAEP round trip
```

`--decrypt` asks for a grant that may decrypt, encrypts a short plaintext to the public key in the
certificate the portal returned — with python `cryptography`, or `openssl pkeyutl` if that is not
installed, because the ciphertext has to come from something that is not this backend — and checks
that `Decrypt` gives the plaintext back byte for byte. `--oaep-hash SHA1` is there because
**SoftHSM 2.x implements OAEP with SHA-1 and no label and refuses everything else** at
`C_DecryptInit`; against a card, drop it and use `--oaep-label` too.

It needs `Xvfb` and `xdotool`. Neither has to be installed system wide:

```console
$ dnf download --arch=x86_64 --resolve xorg-x11-server-Xvfb xdotool
$ mkdir -p ~/scratch && cd ~/scratch && for f in *.rpm; do rpm2cpio "$f" | cpio -idmu; done
$ XVFB=~/scratch/usr/bin/Xvfb XDOTOOL=~/scratch/usr/bin/xdotool \
    LD_LIBRARY_PATH=~/scratch/usr/lib64 tools/ui-smoke.sh
```

**`LD_LIBRARY_PATH` is not optional for an unpacked `xdotool`**: it needs `libxdo.so.3`, which came
out of the same rpm. The script searches for the window with `xdotool ... 2>/dev/null`, so a
loader failure there looks exactly like a window that never appeared — `ui-smoke: no window titled
'Use a Certificate'` while the backend log says `chooser-shown`. Run `xdotool search --name .`
by hand if you see that.

SoftHSM itself can be unpacked the same way and pointed at with `SOFTHSM_MODULE`.

And the cancellation path, where the point is that **nothing** touches the windows:

```console
$ tools/ui-smoke.sh --no-drive -- --cancel-after 3000 --expect-cancelled
```

The client calls `org.freedesktop.portal.Request.Close()` on the in-flight `AcquireCredential`
three seconds after making it. The backend log must show `chooser-cancelled` at that moment, and
**no `Response` signal follows the `Close()`** — the frontend unexports its own Request before
forwarding the Close, so the application, which asked for it, is not told again.

To see the windows on your own display instead of driving them:

```console
$ tools/dev-stack.sh --softhsm -- --purpose client_auth
```

The chooser appears, you pick a certificate, the PIN prompt appears, the PIN is `123456`, and the
client verifies the signature. **The fixture PIN is a test PIN in a scratch directory. Do not
reuse it.**

Clean up with `tools/softhsm-fixture.sh --clean`.

---

## 3. A real PIV card. This is the run that has never happened.

**Read this section before inserting the card.** One of these steps deliberately spends a PIN
attempt and one of them replaces the system portal.

### 3.1 Does the system see the card at all

Insert the card, then:

```console
$ systemctl --user status pcscd.socket ; systemctl status pcscd
$ pkcs11-tool --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-token-slots
$ pkcs11-tool --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-objects
```

If `--list-token-slots` shows no token, nothing below will work and the problem is pcscd, the
reader or the card, not this backend.

### 3.2 Does this backend see it

```console
$ ./build/src/xdg-desktop-portal-certificate --list-tokens
```

and, if p11-kit is not configured for OpenSC on this machine:

```console
$ ./build/src/xdg-desktop-portal-certificate \
      --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-tokens
```

Expect one token block per card, then one entry per usable certificate: subject, issuer, expiry,
key type and size, the mechanisms the token advertises for it, the purposes it fits, the PIV slot
where that could be determined, and a stable id. **The serial is printed as `****` plus its last
four characters** and the full one is never logged; that is deliberate, and
[SECURITY.md](SECURITY.md) says why.

Things worth checking here, because they are the things that go wrong:

- a certificate you expected is **missing**: it has no private key with a matching `CKA_ID`, its
  key is a type this backend has no mechanism for, or its EKU rules it out of every purpose.
- a certificate is listed as **EXPIRED**: that is correct behaviour. Expired certificates are
  offered and marked, never hidden.
- `PIN entry: on the reader (protected path)`: your reader has a PIN pad, and the PIN prompt will
  be an instruction window with no editable field.
- `PIN state: final attempt before locking`: **stop**. Do not run 3.4 until the counter is reset.

### 3.3 The private-bus run, with the card in

```console
$ tools/dev-stack.sh -- --purpose client_auth --reason "Testing the certificate portal"
```

Windows will appear on your real display even though the bus is private, because the backend
inherits `WAYLAND_DISPLAY` from your session.

**What to expect, in order:**

1. **The chooser**, titled *Use a Certificate*. At the top, the application name and its identity
   level — for this client, "This application could not be identified", in warning styling, which
   is correct. Then "wants to use a certificate on your security token to prove who you are to a
   server." Then the `reason` you passed, quoted, inside a frame labelled *The application says* —
   it must never appear above, in the name position. Then a list of certificates, each with
   subject, issuer, validity, key type, token label and reader. Then what the grant allows and for
   how long. Then Cancel and Use Certificate.
2. Escape, or the close button, cancels; the client prints `AcquireCredential was cancelled by the
   user` and exits 2. Try that first.
3. Run it again, pick a certificate, press Use Certificate.
4. **The PIN prompt**, titled *Unlock Security Token*, naming the application, the purpose, the
   token and the reader. It appears **at Sign time, not at grant time** — that is the lazy login,
   and it is why `may_prompt_later` is `true` in the output above it.
5. Type the PIN. The client prints the signature length and then
   `verified  the signature checks out against the certificate the portal returned`, and `PASS`.

If it prints `FAIL: the signature did not verify`, that is the interesting failure and worth
keeping the logs for: it means the wrong key signed, or the digest was wrapped wrongly.

### 3.4 The things only a card can answer

Each of these is a separate run. **The wrong-PIN one spends a PIN attempt.**

Before starting, three things that changed in the November 2026 fix pass and that this section
depends on:

- **Cancelling during the PIN prompt no longer frees what `C_Login` is reading.** The window
  disappears at once, the answer is given when the worker returns, and the buffer the card is
  reading is a private copy the worker owns. `tests/test-cancellation.c` is the regression test and
  it runs under ASan. The card operation itself is still not cancellable — PKCS#11 has no way to
  withdraw a `C_Login` — so **an attempt that has been submitted is spent whatever you do with the
  window**.
- **The PIN flags are re-read after every refusal**, so `CKF_USER_PIN_FINAL_TRY` appearing mid-run
  is shown. Once it is set the window demands a **second, explicit Unlock** before spending the
  attempt, and one window offers at most three attempts.
- **`Decrypt` takes `RSA_OAEP` and nothing else.** PKCS#1 v1.5 decryption is refused by name, so
  there is no path that could expose the key to a padding oracle. What a card can tell you that
  SoftHSM cannot: whether OAEP works with a hash other than SHA-1, and whether it accepts a label.
  SoftHSM 2.x refuses both at `C_DecryptInit`, so those two paths have never run against a module.
  `tools/certificate-e2e.py --decrypt` drives the round trip end to end.

```console
# cancel from the application's side while the chooser is up: the window must
# vanish and no grant may be issued
$ tools/dev-stack.sh -- --purpose client_auth --cancel-after 5000 --expect-cancelled

# wrong PIN, then the right one: the window must say the PIN was not accepted
# and let you try again, WITHOUT the request failing
$ tools/dev-stack.sh -- --purpose client_auth

# a second signature on the same grant: NO second PIN prompt, because the
# session stays logged in for the grant's lifetime
$ tools/dev-stack.sh --keep -- --purpose client_auth
# ...then run tools/certificate-e2e.py again from another shell on the same bus

# pull the card out between the chooser and the PIN prompt
# pull the card out while the PIN prompt is up
# pull the card out after the grant, before signing
#   -> expect GrantInvalidated with reason token_removed, and a clean error

# two Sign calls on one logged-out grant: exactly ONE PIN window must appear,
# and both calls must be answered
$ tools/dev-stack.sh --keep -- --purpose client_auth
# ...then two tools/certificate-e2e.py runs at once from another shell
```

The one that matters most and is easiest to get wrong: **reinsert the same card, then insert a
different card with the same label into the same reader.** A grant must not survive either, because
this backend re-resolves the token by manufacturer, model, serial and label together and refuses a
different one.

### 3.5 On the real session bus

Only when everything above works. This **takes `org.freedesktop.portal.Desktop` away from the
system portal** for as long as it runs.

```console
$ tools/dev-stack.sh --live -- --purpose client_auth
```

Afterwards, check the system portal came back:

```console
$ busctl --user status org.freedesktop.portal.Desktop
```

The `Exe=` line should read `/usr/libexec/xdg-desktop-portal` again, not your build directory. It
returns by D-Bus activation the next time anything asks for the name; if nothing has asked yet,
`busctl --user introspect org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop >/dev/null`
is enough to provoke it. To be certain nothing of the development stack is left:

```console
$ pgrep -af 'xdg-desktop-portal(-certificate)?' | grep -v /usr/libexec
```

should print nothing.

---

## Reading the logs

The backend logs **decisions, not data**. Every line is a stable reason code plus fields that
`src/redact.h` permits:

```
request-received      an impl method arrived
discovery-started     token enumeration began
discovery-result      how many tokens, how many candidates -- never which
no-matching-certificate
chooser-shown         the consent window went up
consent-granted       the user picked one
chooser-cancelled     the user did not
grant-created
pin-prompted          detail=on-screen | protected-path
pin-incorrect         an attempt was spent
pin-locked            terminal
login-ok
operation-refused     a check said no; the mechanism name says which
operation-completed
grant-invalidated     detail says why
token-removed
```

There is deliberately no PIN, no certificate subject, no PKCS#11 URI, no signature and no card
serial in any of them, and there is no logging entry point that takes a format string, so there is
no way to add one by accident. `--verbose` adds breadcrumbs; it does not add data.

**Answering "what used my card, and when" needs both journals.** The decision — which application,
at which identity level, for which purpose — is xdg-desktop-portal's; the card event is this
backend's. That is a consequence of the split, and the session handle is what joins them.

## If something goes wrong

| Symptom | Where to look |
|---|---|
| `org.freedesktop.portal.experimental.Certificate is not exported` | the frontend was started without `XDG_DESKTOP_PORTAL_ENABLE_EXPERIMENTAL=certificate`, or it is not the branch |
| the frontend logs nothing about `certificate` | no `.portal` file matched: check `XDG_DESKTOP_PORTAL_DIR` and `portals.conf` |
| `Backend call failed: ... disconnected from message bus without replying` | **this backend crashed** — and there will be no core dump, because `main()` sets `PR_SET_DUMPABLE(0)` and `RLIMIT_CORE 0` so that a crash between typing a PIN and wiping it cannot write one to disk. Re-run it with `--debug-allow-core` to get a dump and to be able to attach `gdb`; never put that flag in an installed service file |
| `Gdk-WARNING: Failed to read portal settings ... Unable to open /proc/<pid>/root` | expected, and the same hardening: a non-dumpable process's `/proc` entries are root-owned, so the settings portal cannot identify this one and GDK falls back to GSettings. It is the mechanism that blocks a same-uid `ptrace` attach |
| every method returns `AccessDenied` | the sender does not own `org.freedesktop.portal.Desktop`. That is the peer check, and it is working |
| `AcquireCredential` answers 2 with `no_token` | no token is present |
| `AcquireCredential` answers 2 with `no_matching_certificate` | a token is present but nothing on it fits the purpose and filter. `--list-tokens` says which purposes each certificate fits |
| `Sign` answers 2 with `invalid_request` | the mechanism, the `hash` parameter or the digest length did not validate. See [IMPL-INTERFACE.md](IMPL-INTERFACE.md) |
| `Decrypt` answers 2 with `invalid_request` | the mechanism was not `RSA_OAEP`, or its `hash`/`mgf1_hash`/`label` did not validate, or the ciphertext was not exactly one modulus long. See [IMPL-INTERFACE.md](IMPL-INTERFACE.md) |
| `Decrypt` answers 2 and says only "the decryption failed" | by design: every failure of a well-formed request is reported in the same words so that it cannot be used as an oracle. The reason is in the backend's journal |
| `Decrypt` answers 2 and mentions a new grant | the grant has spent its 32 decryptions. Acquire again |
| `AcquireCredential` answers 2 with `no_such_session` and the session obviously exists | the call named a different `app_id` than `CreateSession` did, or a higher `app_identity_level` than the session has already been used at |
| a second `CreateSession` on the same path answers 2 | there is a live session there. Close it first; a **closed** one is replaced |

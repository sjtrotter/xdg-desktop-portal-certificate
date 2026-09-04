# Testing

Three tiers, in the order they become possible, and only the third needs a card. What each tier
can and cannot tell you is [tests/README.md](../tests/README.md); this file is the **commands**.

Everything here has been run on Fedora 44. Tier 3 is the author's; tiers 3.1 through 3.4 have now
been run once, against one real PIV card and one reader (see the note under §3.4), but the rest of
tier 3 and every other card and reader combination remain unrun.

---

## 0. Build and run what needs nothing

```console
$ meson setup build -Dwarning_level=2 -Dwerror=false
$ ninja -C build
$ meson test -C build
```

Ten suites:

| Suite | Needs | What it covers |
|---|---|---|
| `filter` | nothing | purpose and `certificate_filter` matching against fixture certificates |
| `mechanism` | nothing | the mechanism mapping, the digest-length rule, the PSS parameters and the `MGF1-<hash>` spelling **including a mismatched hash and a wrong-typed one**, the OAEP parameters and `CK_RSA_PKCS_OAEP_PARAMS`, **that only `RSA_OAEP` may decrypt and only the three signing mechanisms may sign**, and that a present-but-mistyped `signature_encoding`, `mgf` or `mgf1_hash` is an error rather than a default |
| `redact` | nothing | the redactor, the display-text sanitiser, that a newline in an app id cannot forge a journal line |
| `chooser` | nothing | the consent window's display helpers: that a desktop file's `Name=` or a card's token label cannot add a line, an ANSI escape or a direction override to the window, that both are capped, and that "expired" is a **word** |
| `broker-device` | a SoftHSM fixture, and `openssl(1)` for the OAEP half | `C_Login`, `C_Sign`, signature verification, an **RSA-OAEP round trip** against a ciphertext `openssl pkeyutl` produced, and that opening the device for a **different** candidate throws away the previous grant's login and key handle. **Skips itself** without one; see tier 2 |
| `broker-decrypt` | a SoftHSM fixture | the two properties that make `Decrypt` safe to offer: **one indistinguishable error** for every failure, and the **per-grant budget**. **Skips itself** without one |
| `broker-regrant` | a SoftHSM fixture with both an RSA and an EC key | a second `AcquireCredential` on a live session, end to end: the signature after the re-grant **verifies against the new certificate**, and the operation in between is refused rather than signed with the old grant's key. **Skips itself** without one |
| `tools-lib` | nothing | the two helpers in `tools/lib.sh` that decide something dangerous: that the generated `portals.conf` is the **effective** per-interface resolution of the machine's whole configuration chain rather than a copy of the first file (a user `Screenshot=none` survives an `/etc` file that names a backend for it), that our `Certificate` line replaces any existing one, that a private run switches the `Secret` backend off and a `--live` one does not, and that the fixture checks refuse a forged marker, a symlinked path, an ancestor that is not ours, a mode that is not 0700, and a directory this project did not make |
| `pin-system` | nothing (it stands up its own `GTestDBus`, and gcr's own system prompter or a hand-written hostile one on it) | the OTHER PIN prompt, end to end and with nobody typing: that `--pin-prompt=auto` picks the system prompter when the name is on the bus, that the application, purpose, token and reader reach the prompt, that no "remember" choice is ever offered, that a wrong PIN comes back as a **warning on the prompt that is already up** rather than a second prompt, that an **empty answer never reaches `C_Login`**, the three-attempt cap, cancel from the prompter, `Request.Close()` closing it, a **Cancel in the shell after the PIN was submitted** answering `cancelled` and abandoning the login that succeeds anyway, the prompter **vanishing** during the open, during a password round and during a confirmation round, a **close racing a transport error** (gcr completing one round twice), the `FINAL_TRY` second confirmation **and that refusing it leaves the card unasked — on a protected authentication path too**, the token flags reaching the warning without a number, the login timeout, and a protected-authentication-path token asking for nothing. Built only when the build found gcr-4 |
| `impl-dbus` | nothing (it stands up its own `GTestDBus`) | the D-Bus boundary: a stranger calling every method including both `Close()`s, cross-`app_id` session use, session-path reuse, strict option validation, the results vardict's types, a frontend **replaced while its call is already in the backend's queue**, and the frontend vanishing while a call is in flight |
| `cancellation` | a display for four of six, a SoftHSM fixture for two | cancelling while `C_Login` is in flight, cancelling before the window is up, cancelling **while the device call is in progress**, a cancelled login that succeeded anyway being logged out again (and a normal one not being), and one of two callers sharing a PIN window cancelling **on its own** |

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
the process. **Nothing under `src/` is suppressed, and nothing broad enough to cover it either**: it
used to contain `leak:libglib-2.0`, `leak:libgio-2.0` and `leak:libgobject-2.0`, and because LSan
matches a suppression against *any* frame of the allocation stack, those hid almost every leak this
backend can have. A leak reported against this backend's own code is a defect.

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

### The build without gcr

`--pin-prompt` exists only when the build found gcr-4, and so does the `pin-system` suite. Both
halves are checked by configuring without it:

```console
$ meson setup build-nogcr -Dgcr=disabled && ninja -C build-nogcr
$ ./build-nogcr/src/xdg-desktop-portal-certificate --help | grep pin-prompt   # nothing
$ meson test -C build-nogcr                                                   # ten suites
```

An option that names a prompt the binary cannot draw would be an option that fails at the worst
possible moment, so it is absent rather than refused.

---

## 1. A private bus, with nothing in the reader

This proves the plumbing: that the frontend finds the `.portal` file, matches the impl interface,
exports the public one, activates this backend, and that a request with no card comes back as a
clean refusal rather than a hang.

The stack runs against a throwaway `XDG_DESKTOP_PORTAL_DIR` that is a **copy of the machine's**: a
symlink to every `.portal` installed here, this repository's `certificate.portal`, and the machine's
effective `portals.conf` with one line added. The directory is printed at the top of the run. §2
says why it is the whole set rather than just ours.

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

PASS no-certificate: AcquireCredential answered 2, no grant
```

That is the plumbing check: the frontend routed to this backend, the backend answered, and the
answer was a clean refusal rather than a hang or a crash.

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

`tools/softhsm-fixture.sh` refuses to write into — or delete — any directory unless all five of
these hold: no component of the path is a symlink (the path is compared with its own resolved real
path), it is under `$TMPDIR` by real path, every ancestor from `$TMPDIR` down is owned by you or by
root and is not writable by others unless it is sticky, it carries this project's marker
(`.xdg-desktop-portal-certificate-fixture`) as a **regular file you own at mode 0600** whose
contents name the fixture, and the directory itself is mode 0700. What lives in that directory
includes the module path the backend `dlopen()`s, and the script deletes it recursively; an
ownership check alone is one a mistyped `SOFTHSM_DIR` pointing at `$HOME` passes.

A directory that already exists without a valid marker is **refused rather than emptied**, and the
message names the manual way out. Modes are no longer repaired: fixtures are created exclusively
(`mktemp -d`, or a plain `mkdir` under `umask 077` for the one whose name has to be predictable) so
they are 0700 from their first instant, and one that is not was open at some point. The delete runs
on the resolved path with `--one-file-system`.

`$TMPDIR` itself is the operator's choice and is not otherwise validated: containment under it
guards against a typo, not against the person running the script. The same rules cover
`tools/ui-smoke.sh`'s `$LOGDIR` and `tools/dev-stack.sh`'s `$DEVDIR`; it is all in `tools/lib.sh`,
and the `tools-lib` suite in tier 1 asserts each refusal.

**A fixture made before these checks existed has a 0644 marker and will be refused.** Either
`chmod 600` the marker or re-create the fixture with the script that owns it.

Then the whole thing including the windows, in a headless X server:

```console
$ tools/ui-smoke.sh                                        # RSA
$ tools/ui-smoke.sh --key-algorithm EC                     # ECDSA, raw r||s
$ tools/ui-smoke.sh --key-algorithm EC --der               # ECDSA, DER
$ tools/ui-smoke.sh -- --decrypt --oaep-hash SHA1          # and the OAEP round trip
$ tools/ui-smoke.sh -- --key-algorithm RSA --regrant EC    # two grants, two prompts
$ tools/ui-smoke.sh --pin-prompt=system                    # the shell's prompt instead
```

**`--pin-prompt=system` is the only way to exercise the system-prompt path against the real stack**,
and it does it without a shell: the script starts `build/tests/certificate-test-prompter`, which
owns `org.gnome.keyring.SystemPrompter` **on the private bus** and answers with `$PIN`. Nothing is
typed, `xdotool` is not used for the PIN at all, and a signature coming back is the proof. It
refuses to run if anything already owns that name on the bus it was pointed at, because a test
fixture must never stand between a user and a password request. It needs a build with gcr-4.

`tools/dev-stack.sh` **refuses** `--pin-prompt=system` outside `--live`, and **defaults a private
run to `gtk`** rather than leaving it at the backend's `auto`. Both are the same fact: `auto` asks
the bus whether `org.gnome.keyring.SystemPrompter` has an owner *or is activatable*, and
`dbus-run-session` reads the same service directories the session bus does — so on any machine with
gnome-keyring installed, `org.gnome.keyring.SystemPrompter.service` activates
`/usr/libexec/gcr-prompter` on the private bus too. **"No shell" is not "no prompter"**, and a
private run left at `auto` was not testing the window it looked like it was testing. `--pin-prompt`
is forwarded through both of the script's re-executions, so `--live --pin-prompt=gtk` really is
`gtk`. On the real session bus with no `--pin-prompt`, `auto` picks the shell's prompter.

The portal directory these scripts build is a **reconstruction of the machine's**: a symlink to
every `.portal` file installed here, plus this repository's, plus the machine's configuration
chain **flattened into one `portals.conf`**, with the `Certificate` line replaced by ours.
`XDG_DESKTOP_PORTAL_DIR` makes the frontend ignore every other portal directory *and* every other
`portals.conf`, so a directory holding only `certificate.portal` used to leave the stack with no
settings portal — which is why the windows came up light on a dark desktop — and used to take every
other portal on the session down for the duration of a `--live` run.

**Flattened, not copied.** The frontend does not stop at the first configuration file it finds: it
loads one per directory in the chain and then resolves *each interface* against the whole list, so
copying the first file loses whatever a later one said — a partial `~/.config` file hiding
`/etc`'s `Screenshot=none`, for instance, and handing the development stack a backend the session
had switched off. `tools/lib.sh` replays that resolution per interface, `none` included, and the
`tools-lib` suite asserts it.

**On a private bus the `Secret` backend is switched off**, because nothing there owns
`org.freedesktop.secrets` and the frontend's start-up otherwise waits out the full D-Bus activation
timeout — about 25 seconds of "Failed to create secret proxy: … Timeout was reached" before
`Desktop acquired`. A `--live` run keeps the machine's own value.

To check the settings portal is really there:

```console
$ tools/dev-stack.sh --keep --no-e2e
# ...then, from another shell, with the DBUS_SESSION_BUS_ADDRESS it printed:
$ gdbus call --session --dest org.freedesktop.portal.Desktop \
      --object-path /org/freedesktop/portal/desktop \
      --method org.freedesktop.portal.Settings.ReadOne \
      org.freedesktop.appearance color-scheme
(<uint32 1>,)
```

`1` is `prefer-dark`, `2` is `prefer-light`, `0` is "no preference".

### The theme, which is a security-relevant detail dressed as a cosmetic one

A trusted dialog that does not look like the rest of the desktop is a trusted dialog that is harder
to tell from an untrusted one. `PR_SET_DUMPABLE(0)` stops the settings portal identifying this
process, so the backend reads `org.gnome.desktop.interface color-scheme` from GSettings itself;
[SECURITY.md](SECURITY.md#pin-handling) records why that rather than dropping the hardening.
`--verbose` prints the answer:

```console
$ ADW_DEBUG_COLOR_SCHEME=prefer-dark tools/ui-smoke.sh
$ grep colour-scheme /tmp/xdp-certificate-ui-smoke.*/backend.log
... DEBUG: colour-scheme detail=dark
```

With `ADW_DEBUG_COLOR_SCHEME` unset the same line reports what the session is actually set to, which
is the thing that used to be wrong.

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

**The fixture token is software**, and this backend offers only hardware tokens by default — a
window headed "security token" that offers keys out of a home directory says something untrue about
where the key is. Naming a module with `--module` is already the deliberate act that lifts the
default, which is what `tools/` does; it passes `--allow-software-tokens` as well so that the intent
is visible in the command line rather than implied. `--list-tokens` names any token it skipped and
why.

The chooser appears, you pick a certificate, the PIN prompt appears, the PIN is `123456`, and the
client verifies the signature. **The fixture PIN is a test PIN in a scratch directory. Do not
reuse it.**

Clean up with `tools/softhsm-fixture.sh --clean`.

---
## 3. A real PIV card. Tiers 3.1–3.4 have been run, once.

**Read this whole section before inserting the card.** One step deliberately spends a PIN attempt
and one step replaces the system portal. Nothing above this line touches hardware, and nothing
below it has been run against more than one card in one reader — see the note under §3.4.

### 3.0 The shortest sequence that would change that

Six steps, in this order, and the first four are cheap. Everything after step 3 assumes the one
before it passed.

| | Step | What it settles | Spends an attempt |
|---|---|---|---|
| 1 | `--list-tokens` | the card is visible, the certificates parse, the PIN counter is healthy | no |
| 2 | private bus, happy path | chooser → PIN window → `C_Sign` → the signature verifies | no |
| 3 | private bus, cancel | the window goes away and no grant is issued | no |
| 4 | live, happy path | the **system prompter** draws the PIN request, on the real session bus | no |
| 5 | live, a second signature on one grant | one PIN for the grant, not one per operation | no |
| 6 | wrong PIN, **optional** | the retry wording and the flags, from a real counter | **yes** |

The exact commands are 3.1 to 3.6. **Stop at the first one that does not do what it says**, and keep
the backend log: every one of them has a distinctive failure and they are the interesting ones.

### 3.1 Does anything see the card

```console
$ systemctl --user status pcscd.socket ; systemctl status pcscd
$ pkcs11-tool --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-token-slots
$ ./build/src/xdg-desktop-portal-certificate --list-tokens
```

and, if p11-kit is not configured for OpenSC on this machine:

```console
$ ./build/src/xdg-desktop-portal-certificate \
      --module /usr/lib64/pkcs11/opensc-pkcs11.so --list-tokens
```

If `pkcs11-tool --list-token-slots` shows no token, nothing below will work and the problem is
pcscd, the reader or the card, not this backend.

Expect one token block per card, then one entry per usable certificate: subject, issuer, expiry, key
type and size, the mechanisms the token advertises, the purposes it fits, the PIV slot where that
could be determined, and a stable id. Every card-supplied string goes through the same sanitiser the
chooser uses, so a card carrying ANSI escapes or a right-to-left override cannot rewrite this
output; `| cat -v` if you want the bytes rather than the reading. **The serial is printed as `****`
plus its last four characters** and the full one is never logged — [SECURITY.md](SECURITY.md) says
why.

Four lines to read carefully:

- `hardware      yes (CKF_HW_SLOT)` — expected for a card in a reader. **`no`** means this backend
  will not offer it without `--allow-software-tokens` or `--module`, and a `SKIPPED` line says so.
- `PIN entry: on the reader (protected path)` — your reader has a PIN pad, and the prompt will be an
  instruction with no editable field. 3.6 does not apply.
- `PIN state: recent failed attempts` — the counter is already down. Do not run 3.6.
- `PIN state: final attempt before locking` — **stop.** Reset the counter before anything else.

A certificate you expected but do not see has no private key with a matching `CKA_ID`, has a key
type this backend has no mechanism for, or is ruled out of every purpose by its EKU. One listed as
`EXPIRED` is correct behaviour: expired certificates are offered and marked, never hidden.

### 3.2 The private-bus happy path

```console
$ tools/dev-stack.sh -- --purpose client_auth --reason "Testing the certificate portal"
```

Windows appear on your real display even though the bus is private, because the backend inherits
`WAYLAND_DISPLAY` from your session. On a private bus there is no shell to own
`org.gnome.keyring.SystemPrompter`, so this run uses **this backend's own PIN window** — which is
the one to look at first, because it is the one this repository draws.

**In order:**

1. **The chooser**, titled *Use a Certificate*. At the top the application name and its identity
   level — for this client, "This application could not be identified", in warning styling, which is
   correct. Then "wants to use a certificate on your security token to prove who you are to a
   server." Then the `reason` you passed, quoted, inside a frame labelled *The application says* — it
   must never appear above, in the name position. Then the certificates, each with subject, issuer,
   validity, key type, token label and reader. Then what the grant allows and for how long. Then
   Cancel and Use Certificate. **It should be the same colour as the rest of your desktop**; if it is
   not, `--verbose` prints `colour-scheme detail=dark` or `detail=light` and §2 says what that means.
2. Pick a certificate, press Use Certificate.
3. **The PIN prompt**, titled *Unlock Security Token*, naming the application, the purpose, the token
   and the reader. It appears **at Sign time, not at grant time** — that is the lazy login, and it is
   why `may_prompt_later` was `true` in the output above it.
4. Type the PIN. The client prints the signature length, then
   `verified  signature checks against the returned certificate`, then `PASS`.

`FAIL: the signature did not verify` is the interesting failure and worth keeping the logs for: the
wrong key signed, or the digest was wrapped wrongly.

### 3.3 The private-bus cancel

```console
$ tools/dev-stack.sh -- --purpose client_auth --cancel-after 5000 --expect-cancelled
```

The chooser goes up and the client closes the request five seconds later. The window must vanish at
that moment, the backend log must show `chooser-cancelled`, no grant may be issued, and **no
`Response` follows the `Close()`**. Pressing Escape or the close button by hand must do the same
thing from the other direction: the client prints `cancelled by the user` and exits 2. When the
client asked, it prints `PASS cancel: Close() delivered, no Response` — upstream's `Request`
unexports the frontend object before forwarding `Close()` to the backend, so there is no second
answer for the application that asked.

### 3.4 On the real session bus, with the shell's PIN prompt

Only when 3.1 to 3.3 have all passed. This **takes `org.freedesktop.portal.Desktop` away from the
system portal** for as long as it runs.

```console
$ tools/dev-stack.sh --live -- --purpose client_auth
```

On a GNOME session `--pin-prompt` defaults to `auto` and `org.gnome.keyring.SystemPrompter` is owned
by gnome-shell, so **the PIN request is drawn by the shell**, not by this backend: a shell-styled
dialog rather than a window of ours, and it will **not** be parented to the requesting application.
Both of those are expected and [SECURITY.md](SECURITY.md#where-the-field-is-drawn-and-what-that-moves)
says what that moves and what it does not.

**Two things to try in the shell's dialog by hand.** Press Return on an empty field: the prompt
must come back with "Enter the PIN for this token." and the attempt counter must not move
(`--verbose` shows no `pin-incorrect`, and 3.1 will still say the counter is healthy). Press Cancel
*after* the PIN has gone in, while the card is thinking: the answer must be `cancelled`, and if the
login succeeded anyway the log must show `login-ok detail=cancelled-after-login` followed by
`login-ok detail=abandoning-cancelled-login`. **That second one is not reliably testable by hand**:
a PIV card typically verifies a submitted PIN in tens of milliseconds, well inside human reaction
time, so there is usually no window to land the Cancel after submission and before the answer comes
back — it is only observable by hand against a slow reader or card. Otherwise it is covered by the
headless `/pin-system/shell-cancel-after-the-pin-was-submitted` case in `tests/test-pin-system.c`,
which drives the same path with a scripted prompter instead.

On GNOME, `org.gnome.keyring.SystemPrompter` **is gnome-shell itself**, not a separate
`gcr-prompter` process — killing it would end the session the prompt is running in, not exercise a
crash path. The prompter vanishing mid-interaction is therefore **not testable by hand on GNOME**;
it is covered instead by the vanish cases in `tests/test-pin-system.c`
(`prompter-vanishes-during-open`, `prompter-vanishes-during-password`,
`prompter-vanishes-during-confirm`), which run against a hand-written hostile prompter that can
drop off the bus on command.

The backend log says which prompt was used:

```
** Message: pin-prompt-selected detail=system
```

To compare the two by eye, run it again with the other one. `--pin-prompt` is forwarded through
the script's `--live` re-execution, so this really is the in-process window and not `auto` again:

```console
$ tools/dev-stack.sh --live --pin-prompt=gtk -- --purpose client_auth
```

The chooser is this backend's window in both cases. Only the PIN request moves.

### Observed on real hardware (2026-09-04)

Tiers 3.1 through 3.4 have passed, once, against one PIV card in one reader (OpenSC, an SCR 331
class reader, GNOME 50 under Wayland): `--list-tokens` parsed every certificate on the card (3.1),
the private-bus happy path and cancel both went as described (3.2, 3.3), and the live run with the
shell's own prompter passed including the empty-Return re-prompt and a chooser cancel (3.4).
Timings, from the backend's own log: the card verifies a submitted PIN in about 40 ms, a signature
comes back in about 0.26 s, and moving the `Secret` backend off (§2) took private-bus startup from
roughly 25 s to about 2 s. **One card, one reader** — this is not yet a claim about PIV hardware in
general.

### 3.5 One PIN per grant

```console
$ tools/dev-stack.sh --live --keep -- --purpose client_auth
# ...then, from another shell on the same bus, run tools/certificate-e2e.py again
```

The second signature must go through with **no second PIN request**: the session stays logged in for
the grant's lifetime. Two `certificate-e2e.py` runs started at once must produce **exactly one** PIN
request and both must be answered.

### 3.6 The wrong-PIN run — OPTIONAL, and it spends an attempt

**Skip this unless 3.1 said the counter is healthy, and never run it on a card you cannot unblock.**
A PIV card typically allows three attempts before it locks, and this deliberately spends one.

```console
$ tools/dev-stack.sh --live -- --purpose client_auth
```

Type a wrong PIN, then the right one. What must happen:

- the prompt says the PIN was not accepted and lets you try again, **without the request failing**;
- the warning is re-read from the token, so `CKF_USER_PIN_COUNT_LOW` appearing shows up as
  "There have been recent failed attempts on this token";
- if `CKF_USER_PIN_FINAL_TRY` appears, the prompt demands a **second, explicit** confirmation before
  spending the attempt — and refusing it must leave the counter alone;
- the backend log shows `pin-incorrect ... detail=retry-offered`, and never a number of attempts,
  because PKCS#11 has no portable way to ask for one.

Three refusals in one prompt is where it stops asking; the application can ask again, which is a new
decision rather than a habit.

### 3.7 The things only a card can answer, when there is time

None of these is on the critical path, and each is a separate run.

```console
# pull the card out between the chooser and the PIN prompt
# pull the card out while the PIN prompt is up
# pull the card out after the grant, before signing
#   -> expect GrantInvalidated with reason token_removed, and a clean error

# reinsert the SAME card, then insert a DIFFERENT card with the SAME label into
# the same reader: a grant must not survive either, because the token is
# re-resolved by manufacturer, model, serial and label together

# OAEP with a hash other than SHA-1, and with a label: SoftHSM 2.x refuses both
# at C_DecryptInit, so neither path has ever run against a module
$ tools/dev-stack.sh --live -- --purpose client_auth --decrypt --oaep-label test
```

Three things changed in the November 2026 fix pass that this section depends on:

- **Cancelling during the PIN prompt does not free what `C_Login` is reading.** The prompt
  disappears at once, the answer is given when the worker returns, and the buffer the card is
  reading is a private copy the worker owns. The card operation itself is still not cancellable —
  PKCS#11 has no way to withdraw a `C_Login` — so **an attempt that has been submitted is spent
  whatever you do with the prompt.** The same is true of `--login-timeout`, which gives up on the
  interaction after 60 seconds and abandons the login if it lands afterwards.
- **The PIN flags are re-read after every refusal**, so `CKF_USER_PIN_FINAL_TRY` appearing mid-run
  is shown.
- **`Decrypt` takes `RSA_OAEP` and nothing else.** PKCS#1 v1.5 decryption is refused by name, so
  there is no path that could expose the key to a padding oracle.

### 3.8 Putting the session back

```console
$ busctl --user status org.freedesktop.portal.Desktop
```

The `Exe=` line should read `/usr/libexec/xdg-desktop-portal` again, not your build directory. It
returns by D-Bus activation the next time anything asks for the name; if nothing has,
`busctl --user introspect org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop >/dev/null`
provokes it. Then:

```console
$ pgrep -af 'xdg-desktop-portal(-certificate)?' | grep -v /usr/libexec
```

should print nothing.

**There is no in-place upgrade of this backend, and `--replace` on its own is not one.**
`G_BUS_NAME_OWNER_FLAGS_REPLACE` only succeeds if the current owner asked to be replaceable, and the
D-Bus-activated instance deliberately does not: `ALLOW_REPLACEMENT` is not "let the package manager
replace me", it is "let whoever asks next replace me", and what would be taken over is the thing
that asks for a PIN. The two halves are separate flags:

| | |
|---|---|
| `--allow-replacement` | this instance may be replaced later. Not the default, and **not in the installed `.service` file** |
| `--replace` | this instance asks to replace the current owner — which works only if that owner was started with `--allow-replacement` |

So moving to a new build means **stopping the old process and letting D-Bus activation start the new
one**:

```console
$ pkill -f xdg-desktop-portal-certificate     # or systemctl --user stop, where it is a unit
# ...the next AcquireCredential activates the new binary
```

`tools/dev-stack.sh --live` starts its backend with `--replace --allow-replacement` so that
re-running it takes the name off the instance the previous run left behind. That is a development
loop, not a deployment recipe.

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
pin-prompt-selected   detail=gtk | system -- which process drew the PIN field
pin-prompted          detail=on-screen | protected-path
pin-prompt-failed     detail=system-prompter[-unreachable] -- the shell's prompt did not answer
pin-prompt-dismissed  detail=system-prompter -- the shell took the prompt away
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
| `Gdk-WARNING: Failed to read portal settings ... Unable to open /proc/<pid>/root` | expected, and the same hardening: a non-dumpable process's `/proc` entries are root-owned, so the settings portal cannot identify this one. It is the mechanism that blocks a same-uid `ptrace` attach. The colour scheme is **not** lost with it: `src/main.c` reads `org.gnome.desktop.interface color-scheme` from GSettings and feeds libadwaita directly, because measuring showed the fallbacks did not recover it |
| the chooser or the PIN window is the wrong colour | `--verbose` prints `colour-scheme detail=dark` / `detail=light`. If it disagrees with `gsettings get org.gnome.desktop.interface color-scheme`, the GSettings path in `follow_colour_scheme()` is what to look at; if it agrees, the theme is right and something else is wrong |
| `--pin-prompt` is not in `--help` | this build has no gcr-4. `meson configure build \| grep gcr`; the option does not exist rather than failing later |
| `--pin-prompt=system` and nothing appears | `org.gnome.keyring.SystemPrompter` is not on the bus the backend is using. On a private bus there is no shell; the backend answers `no_display` and says `pin-prompt-failed detail=system-prompter-unreachable` rather than silently drawing its own window |
| `--list-tokens` says `SKIPPED  not a hardware token` | the token's slot does not set `CKF_HW_SLOT`. That is the default policy, not a failure: pass `--allow-software-tokens`, or name the module with `--module` |
| a tools script says a directory `has no .xdg-desktop-portal-certificate-fixture` | it was not created by this project, and the scripts delete these directories recursively. Remove it by hand if it really is disposable |
| a tools script says a marker `is mode 644, not 600` | the fixture predates the tightened checks. `chmod 600` the marker, or re-create the fixture with the script that owns it |
| a `Sign` fails with "The token did not answer the login in time" | `--login-timeout` (60 s) ran out. The attempt is still spent — PKCS#11 cannot withdraw a `C_Login` — and a login that lands afterwards is logged out again. Raise it, or pass `--login-timeout 0`, if the middleware is legitimately that slow |
| every method returns `AccessDenied` | the sender does not own `org.freedesktop.portal.Desktop`. That is the peer check, and it is working |
| `AcquireCredential` answers 2 with `no_token` | no token is present |
| `AcquireCredential` answers 2 with `no_matching_certificate` | a token is present but nothing on it fits the purpose and filter. `--list-tokens` says which purposes each certificate fits |
| `Sign` answers 2 with `invalid_request` | the mechanism, the `hash` parameter or the digest length did not validate. See [IMPL-INTERFACE.md](IMPL-INTERFACE.md) |
| `Decrypt` answers 2 with `invalid_request` | the mechanism was not `RSA_OAEP`, or its `hash`/`mgf1_hash`/`label` did not validate, or the ciphertext was not exactly one modulus long. See [IMPL-INTERFACE.md](IMPL-INTERFACE.md) |
| `Decrypt` answers 2 and says only "the decryption failed" | by design: every failure of a well-formed request is reported in the same words so that it cannot be used as an oracle. The reason is in the backend's journal |
| `Decrypt` answers 2 and mentions a new grant | the grant has spent its 32 decryptions. Acquire again |
| `AcquireCredential` answers 2 with `no_such_session` and the session obviously exists | the call named a different `app_id` than `CreateSession` did, or a higher `app_identity_level` than the session has already been used at |
| a second `CreateSession` on the same path answers 2 | there is a live session there. Close it first; a **closed** one is replaced |

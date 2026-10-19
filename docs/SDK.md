# Certificate core SDK

`meson setup build-sdk -Dservice=false` builds the core without looking for
GTK, libadwaita or gcr, regardless of `auto_features` or the `gcr` option (including
`--auto-features=enabled -Dgcr=enabled`). The `service` boolean defaults to `true`.
The default build also builds the GTK service and client module;
gcr remains optional (`-Dgcr=disabled` keeps the GTK service). `meson install -C build-sdk` installs:

- `libxdp-certificate-core.so.0` and its linker symlink;
- `xdp-certificate-core-0.pc` (project version, private GLib/GIO, p11-kit and GnuTLS dependencies);
- `abi.h`, `core.h`, `ui.h`, `secret.h` and `dispatch-glib.h` beneath
  `include/xdp-certificate-core-0/xdp-certificate/`.

The earlier `-Dauto_features=disabled` shortcut still selects the SDK alone;
use `-Dservice=false` to choose it explicitly.

Use `<xdp-certificate/core.h>` and `<xdp-certificate/ui.h>` with
`pkg-config --cflags --libs xdp-certificate-core-0`. These headers require only C11
or C++17. The separate, optional `<xdp-certificate/dispatch-glib.h>` requires
`pkg-config --cflags glib-2.0`; it exposes `GMainContext`. No toolkit is required.
Only installed declarations are the desktop SDK contract; `adapter.h`, `session.h`
and other build-tree headers are private compatibility interfaces for this service.
The `XDP_CERTIFICATE_CORE_0` symbol version contains exactly the exported functions
declared in the installed headers. `XDP_CERTIFICATE_CORE_PRIVATE_0` is internal to
the in-tree service and has no stability promise. The service and library must ship
from the same build; external consumers must use only the public node.

Create one `XccContext` with a complete `XccUiV1` table. Specs, strings and input bytes
are copied before API calls return. Contexts, sessions, requests and candidate snapshots
have explicit ref/unref functions; close sessions before releasing their last application
reference. Each request completes exactly once. Results and views are borrowed only during
the callback; copy display strings or retain candidates to keep them. A writable `XccSecret`
is exclusively owned by the UI; submission consumes it, including stale replies. Never
copy PINs into toolkit models, queued signal arguments or logs. Draw external strings as
plain text, retain the identity assurance supplied by the frontend, and honour window
parenting and one-use activation tokens. Desktop adapters still own D-Bus authorization,
request/session exports and frontend-owner generation changes.

`XccDispatch.post` must be thread safe: always enqueue, including calls from its receiver
thread, in FIFO order onto one desktop/UI thread. It must never invoke inline or drop a
closure. UI callbacks, completions and invalidations run there. Call the public API from
that thread; the core coordinates workers privately. Replies may be submitted inside UI
callbacks and are queued back to the coordinator. Acknowledge PIN presentation with
`xcc_pin_ready`; honour hide immediately and close once per shown interaction. Pair
`xcc_context_hold_ui` / `xcc_context_release_ui` around asynchronous provider callbacks
that may survive close, acquiring the hold while the UI callback is active. Keep the
receiver and UI state alive until shutdown completion; keep dispatching while
`xcc_context_shutdown_async` drains workers and UI holds. After completion, release all
remaining handles. The library must stay loaded for the life of the process: its static
GObject types, including `XccSession`, retain registered metadata and function pointers
even after all handles are released. Shutdown completion means resources are drained;
it does not permit unloading the core DSO. The library links with `-Wl,-z,nodelete`
so `dlclose()` cannot unmap it. Unresponsive middleware can prevent completion.
Embedding also requires explicit process hardening before collecting PINs (`PR_SET_DUMPABLE(0)`, `RLIMIT_CORE=0`) and resolving
crash-handler integration; see [SECURITY.md](SECURITY.md).

Every public struct starts with `uint32_t struct_size, abi_version`; initialize inputs
(including nested principals and byte spans) with their size and `XCC_ABI_VERSION`, the
single core ABI constant. Error outputs receive these fields from the core. Check sizes
and versions before reading views. Use `xcc_chooser_view_candidate` and
`xcc_acquire_spec_issuer` for producer-stride arrays; invalid sizes or overflowing offsets
return NULL. Producers remain responsible for valid backing allocations. Extensions to
pointer-passed structs append fields and retain the original minimum accepted size;
consumers gate appended fields on `struct_size`. Embedded/value-returned structs and the
fixed error output keep their layout for this SONAME. Incompatible changes require both a new SONAME and a new pkg-config
API name, including during experimentation. The Certificate1 wire version is independent.

`xcc_candidate_info()` returns borrowed metadata valid while the candidate is retained.
`subject`, `issuer`, `token` and `reader` are sanitized display strings. The appended
`token_label`, `token_manufacturer`, `token_model` and `token_reader` fields carry the
original token label, manufacturer, model and reader name used by the reference
adapter's `token_display` dictionary. They are empty strings, never NULL, when absent;
no serial number is exposed. These strings are external input: render them as plain
text and use the sanitized fields for chooser presentation. Before reading the four
fields, check `info->struct_size >= offsetof(XccCandidateInfo, token_reader) +
sizeof(const char*)` (and the ABI version). Older producers supply only the original
prefix. `protected_path` still supplies `protected_authentication_path` on the wire.
This append-only extension keeps the SONAME, ABI version and exported symbol list.

`meson test -C build --suite sdk` covers staged C/C++ consumers, all installed headers,
ABI prefixes, complete public/private export lists and their symbol versions, `NODELETE`,
a separate `-Dservice=false --auto-features=enabled` configuration and stride bounds.
The new consumers use an explicit empty module list, so they need no SoftHSM fixture.
Existing token suites retain their missing-fixture skips and private static link seams.
`sdk-headers` also freezes the original `XccCandidateInfo` offsets and the appended
metadata order in C and C++. `sdk-token-metadata` checks original and absent metadata,
and compares all four fields with discovered SoftHSM token values when a fixture is
available (`SOFTHSM_FIXTURE_DIR`, optionally `SOFTHSM_MODULE`, or the usual
`/tmp/xdp-certificate-softhsm` fixture from `tools/softhsm-fixture.sh`).

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

Each session accepts one successful acquisition. On an open session, `xcc_acquire_async`
completes with `XCC_ERROR_INVALID_REQUEST` if a grant exists or another acquisition
is pending. A failed or cancelled first acquisition can be retried after completion on
the same open session. If cancellation suppresses a committed grant's result, the
core releases that grant before delivering the cancellation. The grant cannot be
used before successful completion delivery; Sign returns `XCC_ERROR_INVALID_REQUEST`
while that delivery is pending. Cancellation after successful delivery retains the grant.
Create a new session to select another credential or obtain a new grant after expiry.
The credential, permissions and expiry remain fixed for the granted session.

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

Desktops should build user-visible wording from structured view fields and their
own translation catalogs. The SDK's English strings are a compatibility fallback
for producers whose `struct_size` lacks the corresponding structured fields.
Do not parse or compare English sentences to discover state. Continue to render
external certificate, token, reader, caller and reason text literally as plain text.

`XccChooserCandidateView` appends, in order, `int64_t not_before, not_after`
(Unix seconds), `uint32_t validity` (`XccValidity`), `const char *key_type`,
`uint32_t key_size`, and `uint32_t display_flags`. Nonpositive timestamps are
unknown. The core decides `VALID`, `EXPIRED`, `NOT_YET_VALID` or `UNKNOWN` using
the same wall-clock sample as the existing `expiry`, `detail` and `invalid`
fields. Expired and not-yet-valid checks retain their existing precedence;
otherwise either missing date produces `UNKNOWN`. Desktops must use this state,
not recompute validity with a second clock. Format dates in the user's locale
and key details from the algorithm identifier and bit count (`key_type` is NULL
when unknown; `unsupported` is an algorithm identifier for unsupported keys).
The original `expiry` and `detail` fields keep their previous content.

Gate each appended field with `struct_size >= offsetof(Type, field) +
sizeof(view->field)` and check the ABI version. For example, the complete key
metadata is available through `key_size`; validity is independently available
through `validity`. The `XCC_CHOOSER_CANDIDATE_VIEW_V1_SIZE`,
`XCC_CHOOSER_VIEW_V1_SIZE` and `XCC_PIN_VIEW_V1_SIZE` constants retain the original
minimum sizes, including alignment padding. Do not require the new `sizeof`
when accepting older views. The chooser stride walker accepts original, partial
and larger producer layouts; always use it instead of indexing the array.
Dispatched snapshots own the appended key string as well as the original text.
Each extension starts on an eight-byte boundary using `XCC_ALIGNAS(8)` (C11
`_Alignas` / C++ `alignas`), including the token metadata in `XccCandidateInfo`.
V1 minimum sizes round the last original field's end to the original struct's
alignment, independently of that extension boundary. On ARM EABI the original
chooser occupies 96 bytes; `generic_purpose` starts at 96, beyond its tail
padding. On i386 the original chooser remains 92 bytes and the extension starts
at 96. Original field offsets on both ABIs and x86_64 are preserved.

The remaining public UI views have been audited for SDK-owned English:

| View / English fields | Structured source for desktop translations |
| --- | --- |
| `XccChooserView.caller_name` unidentified-app fallback | Appended `display_flags`, `XCC_DISPLAY_CALLER_FALLBACK`; actual caller names remain external text. |
| `identity_detail` | Existing `identity_level`. |
| `purpose_text`, `purpose_detail` | Existing `purpose` plus appended `bool generic_purpose`, which selects generic module disclosure without changing permissions. |
| `operation_scope` | Existing `may_sign`, `may_decrypt`. |
| `duration` | Existing `lifetime_seconds`. |
| `later_prompt` | Invariant disclosure that the first key use may prompt for a PIN; desktops translate this fixed contract. |
| `reason_label` | Invariant label introducing application-supplied, untrusted reason text; desktops translate the label. `untrusted_reason` itself is external text. |
| `XccPinView.purpose_display` | Appended `uint32_t purpose` (`XccPurpose`) and `bool generic_purpose`; generic ignores `purpose`. The core resolves the private legacy purpose strings before publishing these fields. |
| `XccPinView.status` | Appended `uint32_t status_code` (`XccPinStatus`): `NONE`, `INCORRECT`, `REQUIRED`, `TOO_LONG`, `MEMORY_UNAVAILABLE`. `NONE` preserves input on busy-only updates; other codes request fresh input. The English `status` and its NULL convention are retained. |
| `XccPinView.token_label` unnamed-token fallback | Appended `uint32_t display_flags`, `XCC_DISPLAY_TOKEN_FALLBACK`. `reader` and `caller_display` are external display text with NULL for absence, not English policy sentences. |
| `XccWarning.message` | Existing `code` (`XCC_WARNING_FINAL_TRY`); no extension needed. |

The chooser candidate's `display_flags` also distinguishes the SDK's unnamed
certificate, issuer and token placeholders using `XCC_DISPLAY_SUBJECT_FALLBACK`,
`XCC_DISPLAY_ISSUER_FALLBACK` and `XCC_DISPLAY_TOKEN_FALLBACK`. Translate only
flagged placeholders; an external label that happens to match English must stay
literal. These flags and the chooser/PIN extensions are append-only and leave
the SONAME, ABI version and exported symbol list unchanged. All other view
fields are IDs, state, external display data or opaque window/activation data.

`meson test -C build --suite sdk` covers staged C/C++ consumers, all installed headers,
ABI prefixes, complete public/private export lists and their symbol versions, `NODELETE`,
a separate `-Dservice=false --auto-features=enabled` configuration and stride bounds.
The new consumers use an explicit empty module list, so they need no SoftHSM fixture.
Existing token suites retain their missing-fixture skips and private static link seams.
`sdk-headers` also freezes the original `XccCandidateInfo` and UI-view offsets,
original UI minimum sizes, and appended metadata order in C and C++.
The header checks also compile with `-m32` and `-m32 -malign-double` when the
compiler and standard headers support them. Static ILP32 models cover both
four- and eight-byte `uint64_t` alignment even on hosts without multilib support;
the test output explicitly reports unavailable compiler modes.
`sdk-stride` includes an original chooser-row array; chooser-policy checks all
four validity states, key metadata and placeholder flags, and core-api checks
the dispatched metadata snapshot. `sdk-token-metadata` checks original and absent metadata,
and compares all four fields with discovered SoftHSM token values when a fixture is
available (`SOFTHSM_FIXTURE_DIR`, optionally `SOFTHSM_MODULE`, or the usual
`/tmp/xdp-certificate-softhsm` fixture from `tools/softhsm-fixture.sh`).

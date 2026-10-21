# Dedicated desktop receiver

`samlab-viewer --stdio-v1` is a separate Windows console process. It reuses the
ordinary `DEFAULT_CONN` RustDesk desktop protocol and the company's existing
rendezvous/relay. It does not require a new receiver protocol on installed hosts.
It is not a terminal, management command runner, web server or external console.

Failure and prompt dialogs remain terminal denials with no retry. The exact
ordinary Session notice `success` / `Successful` / `Connected, waiting for image...`
with an empty link is informational: ignore it only after encrypted peer checks
passed and no error exists, so it cannot abort a valid session before its first
image. Arbitrary success dialogs still fail closed. The real Session forwarding
path is regression-tested, not just the viewer's peer callback in isolation.
Public failure reasons
are fixed categories: password_required/password_rejected, two_factor_required,
session_authentication_required/login_rejected, remote_offline/remote_id_unknown,
server_key_mismatch/server_key_rejected, connection_peer_reset/connection_timeout,
rendezvous_connection_failed/relay_connection_failed/direct_connection_failed,
connection_security_failed, remote_display_unavailable,
encrypted_connection_required, or the unchanged connection_unavailable fallback.
Raw dialog type/title/text/link, server addresses, peer IDs and credentials are
never emitted. A category reports the protocol failure, not hardware identity
or evidence that a remote device is safe to restart or reenroll.

The trusted PC9 worker verifies the product path and hash, then writes one JSONL
start record to redirected stdin. Never use a shell or pass credentials in argv.

## Windows initial permission contract

The initial-permission local product was built from Rust source commit
`fb387b50eca5353ae8e0434580dce4909c81540a`. Its workflow/documentation-only
follow-up added regression checks without rebuilding it. Runtime changes such
as bounded fresh-frame requests require a new source-pinned product.
The existing Windows x64 jobs in `flutter-build.yml` (pull requests) and
`samlab-windows.yml` (manual company builds) run the exact
`headless_viewer::tests::` and `viewer_policy::tests::` filters: currently 17 and
10 tests, respectively. Generated bridge files, vcpkg dependencies and Rust caches
are already prepared at that point. These release-profile tests explicitly use
Rust 1.99.0 and run before the existing application build; no other platform or
application build toolchain is changed. Either test failure fails the job.

The viewer previously waited for an explicit keyboard permission message before
emitting `peer`. Windows hosts only send initial **false**; default permission
therefore produced valid direct frames but no peer record, and the broker rightly
discarded those frames. Ordinary Flutter and legacy clients initialize
`Session.server_keyboard_enabled=true`; the dedicated viewer now uses that same
internal protocol state, while its public Handler remains unknown and denied.

Ordering is established by `server/connection.rs`: `Connection::start` awaits
`on_open`, sends initial keyboard denial (and other denied permissions), then
enters its sole receive/authorization loop. Successful LoginResponse/PeerInfo is
sent later in that loop by `send_logon_response_and_keep_alive`. Permission and
login messages both write directly to the same encrypted stream, not separate
delivery queues. `server.rs` establishes its key before `Connection::start`;
`hbb_common::tcp` encrypts/decrypts sequential framed messages with consecutive
nonces. An omitted encrypted denial cannot silently become a successfully
decoded later PeerInfo. Subsequent permission changes use the same stream.

After successful PeerInfo validation, the existing Session passes its **current**
keyboard snapshot through a default-no-op callback implemented only by the
viewer. The viewer accepts it only for a validated encrypted peer without an
error. A previously explicit permission (including false) takes precedence and
cannot be replaced by the initial snapshot. Later false immediately updates both
Session and Handler, revokes public control and releases held keys/buttons.
Public control and input still require the user's request, validated peer,
established permission, no error, and an actual delivered first frame; frame
sequence/age/epoch gates remain separate and mandatory. Read-only requests stay
read-only even when the host's protocol permission is true.

Regression tests exercise the real Session PeerInfo forwarding path with initial
unknown, default allow, initial/later explicit denial, unauthenticated or malformed
peer data, and read-only/before-first-frame gates. This contract is not hardware
identity verification and does not change installed hosts or general clients.

## Fresh frames on a static desktop

The ordinary protocol sends changed video, so a static screen can otherwise leave
the last delivered frame older than the mandatory two-second input window. The
viewer requests an actual recapture through `Session::refresh_video(current_display)`
only for an authenticated encrypted peer without an error, when no actual output
frame arrived for 750 ms. Requests are at least one second apart and capped at
900 per process. The existing 30-second first-frame deadline, 1..900-second total
duration, explicit close and no-reconnect contracts remain unchanged.

The existing method selects `RefreshVideoDisplay` on supporting peers and the
legacy `RefreshVideo` fallback on older peers. The host authorizes the message,
sets the current display's `OPTION_REFRESH` and restarts that capture/encoder
loop, producing real new frames. Only new `on_rgba` observations advance JPEG
sequence; a refresh request never rewrites cached JPEGs, last-frame times or
input evidence. No freshness window is widened. Existing viewers of the same host
display may also observe this capture/encoder restart, which is why requests are
strictly bounded and display-specific where the existing protocol supports it.

Regression tests cover authentication/error gates, the exact stale threshold and
minimum interval, total request cap, unchanged frame evidence without a new
delivery, and actual modern/legacy refresh messages through the Session sender.
The record is strict and has exactly these fields:

```
viewerVersion: 1
sessionId: UUID
deviceId: UUID
addressId: 6..16 decimal digits
password: nonempty private string, at most 256 bytes
connection_token: optional private string, at most 4096 bytes
controlRequested: boolean
maxSeconds: integer 1..900
```

No passwords are read interactively or loaded from peer history. An absent/blank
password is rejected, and a mismatched local company server/key configuration is
blocked without changing it. Session peer configuration is memory-only. The
local client identity must already exist: the viewer never generates or replaces
the PC9 RustDesk identity. Missing identity is `viewer_local_identity_required`.
Its login uses the read-only identity getter instead of `Config::get_id()`.
Initial stdin byte buffers are overwritten, and credentials are not serialized, logged,
recorded or written to disk. The existing client keeps authentication data in
the bounded child process memory until that process exits; this is not a claim
that every internal Rust String allocation is securely erased.

Subsequent JSONL records have `type: input`, `viewerVersion: 1` (may be omitted),
`sessionId`, positive increasing `sequence`, `frameEpoch`, `frameSequence`, and
`events` (1..32). Each event has one of these strict shapes:

* `{kind: pointer, action: move|down|up|wheel, x, y, button?, deltaX?, deltaY?}`.
  Coordinates are integers in the latest frame. Down/up require left/middle/right;
  move has no button/deltas. Wheel has no button, each delta is -120..120 and at
  least one is nonzero. Positive browser deltas are down/right; the receiver
  reverses them for the RustDesk wheel convention. Display origin is added for
  positional input, including negative virtual desktop origins.
* `{kind: key, action: down|up, key: DOM-code}`. Letters, digits, F1..F12,
  arrows/navigation, common modifiers and punctuation are allowed. RustDesk's
  special control actions (lock screen/CtrlAltDel), arbitrary virtual keys and
  commands are not accepted. Modifier state comes only from this session's keys,
  not the PC9 keyboard or saved user remapping. Text composition should use text.
* `{kind: text, text}`: 1..1024 UTF-8 bytes, no control characters except LF/TAB.
  The normal RustDesk string input path is used. On the supported Windows peer it
  becomes Unicode SendInput, not clipboard synchronization.
* `{kind: release-all}`: releases only keys/buttons held by this receiver. A
  standalone release-all still needs the exact session and increasing sequence
  but bypasses epoch/frame-age/keyboard-permission checks, including before any
  frame. A mixed event list gets no such exemption.

Input requires requested and protocol-established keyboard permission, encrypted peer login,
a matching current display epoch and an actually delivered frame no older than
two seconds. At most 256 events/second, 32 queued input records and 32768 bytes per
stdin line. Invalid/stale/foreign-session input closes without executing that
input; the broker may replace a rejected input with same-sequence release-all.
`{type: close, viewerVersion:1, sessionId}` closes the session. No retries occur.

Stdout contains only JSONL public records, all with viewerVersion/sessionId/type:

* `peer`: addressId, deviceId (caller binding), encrypted:true,
  hardwareIdentityVerified:false, platform:Windows, version, keyboard:boolean.
  Version is the actual nonempty numeric major.minor.patch from PeerInfo;
  malformed/missing versions are blocked, never synthesized. Keyboard authority
  comes from an explicit permission message or the authenticated Windows initial
  permission snapshot described below; the latter is not an observed true message.
  Authenticated address and
  encrypted login are not hardware identity verification.
* `permissions`: keyboard and controlAvailable (requested AND actual permission
  AND authenticated encrypted peer AND an actually delivered frame). No success
  is inferred from connecting, a local default, or a success notice.
* `frame`: sequence, frameEpoch, displayId, width, height, jpegBase64. Maximum
  4096x2160, 512KiB JPEG, five frames/second, one replaceable latest frame. JPEG
  quality falls from 75 to 45 to 20 to meet the cap; oversize/invalid image closes.
  libyuv ARGB/BGRA, ABGR/RGBA, RGB and aligned rows are explicitly converted.
* `state`: connecting/viewing phase, fixed reason, controlAvailable. Viewing is
  emitted only after writing the first actual JPEG frame.
* `error` / `closed`: fixed reason; closed also has phase:closed and
  controlAvailable:false. Raw remote errors, names, logs and inputs are absent.

The process alone forces CPU pixel output, null GPU adapter and no automatic
recording, clipboard/file contexts, audio/file/printer/command message handling,
initial resolution change or automatic privacy/virtual-display toggles. Regular
Flutter/service invocations leave the viewer flag false and keep their behavior.
The receiver uses no file output or auto reconnect. EOF, close, permission loss,
geometry change and normal expiry release held keys/buttons. A separate watchdog
also releases/closes on blocked stdout (five seconds) or bounded process expiry;
transport loss can only attempt release, and ordinary server disconnect cleanup
remains necessary. First-frame wait is at most 30 seconds, first stdin 10 seconds,
session at most 900 seconds plus bounded cleanup. The worker must keep revocation
and browser liveness checks, never leave a stale browser authorized until max time.

The upstream Flutter web workflow is disabled and its referenced flutter/web
sources are absent. This receiver plus the authenticated application relay is
the selected path. Broker/API/browser implementation and approved real-host
first-frame/control proof are separate requirements. Synthetic tests and a built
receiver do not prove an installed device supports actual unattended control.

Focused verification:

```
cargo check --locked --offline --features flutter,hwcodec,vram --lib --bin samlab-viewer
cargo test --locked --offline --features flutter,hwcodec,vram --lib viewer -- --test-threads=1
cargo build --locked --offline --release --features flutter,hwcodec,vram --bin samlab-viewer
```

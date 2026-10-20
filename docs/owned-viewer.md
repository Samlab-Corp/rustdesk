# Dedicated desktop receiver

`samlab-viewer --stdio-v1` is a separate Windows console process. It reuses the
ordinary `DEFAULT_CONN` RustDesk desktop protocol and the company's existing
rendezvous/relay. It does not require a new receiver protocol on installed hosts.
It is not a terminal, management command runner, web server or external console.

The trusted PC9 worker verifies the product path and hash, then writes one JSONL
start record to redirected stdin. Never use a shell or pass credentials in argv.
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

Input requires requested and measured keyboard permission, encrypted peer login,
a matching current display epoch and an actually delivered frame no older than
two seconds. At most 256 events/second, 32 queued input records and 32768 bytes per
stdin line. Invalid/stale/foreign-session input closes without executing that
input; the broker may replace a rejected input with same-sequence release-all.
`{type: close, viewerVersion:1, sessionId}` closes the session. No retries occur.

Stdout contains only JSONL public records, all with viewerVersion/sessionId/type:

* `peer`: addressId, deviceId (caller binding), encrypted:true,
  hardwareIdentityVerified:false, platform:Windows, version, keyboard:boolean.
  Version is the actual nonempty numeric major.minor.patch from PeerInfo;
  malformed/missing versions are blocked, never synthesized. The record waits
  for an actual keyboard permission message (including an observed false).
  Authenticated address and
  encrypted login are not hardware identity verification.
* `permissions`: keyboard and controlAvailable (requested AND actual permission
  AND authenticated encrypted peer). No success is inferred from connecting.
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

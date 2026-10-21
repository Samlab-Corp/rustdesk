# Project instructions

Owned-viewer connection diagnostics expose fixed failure categories only. Never emit raw dialog/error text or retry a failed dialog; preserve server/key/authentication gates.
Windows initial keyboard authority uses the authenticated ordered-protocol snapshot in `docs/owned-viewer.md`; never describe it as an observed true message, override explicit denial, or authorize before the first actual frame.
Static-screen freshness uses only bounded authenticated `refresh_video` requests from `docs/owned-viewer.md`; never refresh timestamps/sequences of cached frames or widen the input freshness window.

Follow [AGENTS.md](AGENTS.md) for source, build, and verification rules.

Browser desktop viewing follows [docs/owned-viewer.md](docs/owned-viewer.md): separate fixed PC9 receiver, stdin-only credentials, bounded CPU JPEG, exact session/frame/permission gates and held-key release. Preserve installed ordinary-protocol hosts and never equate source/build proof with real viewing or hardware identity.

Headless terminal automation follows [docs/headless-terminal.md](docs/headless-terminal.md): reuse existing authentication and permissions, stdin-only secrets, finite limits, and verified per-command completion. No GUI input or automatic retry of uncertain commands.

Kiosk approvals follow [docs/kiosk-control-stdin.md](docs/kiosk-control-stdin.md): fixed current-user non-PTY worker, capability before sensitive payload, pinned ProgramFiles wrapper and no approval/token in command text or EncodedCommand. Probe is not hardware identity or absence-of-active-delivery evidence; unknown outcomes remain uncertain.

Company sources are `Samlab-Corp/rustdesk` and `Samlab-Corp/hbb_common`, with the common library pinned to an available company commit. Validated development changes use `release/next`; Windows test builds use `samlab-windows.yml`.

LetMeUp remote access starts at `https://kiosk.letmeup.co.kr` and ClassUp remote access starts at `https://ops.classup.io`. A separate console opening, source recovery, or a successful build does not establish a real unattended device connection. Preserve existing recovery access until approved pilot devices pass connection and reconnection checks.

* Company-approved SYSTEM commands use `docs/native-management.md`: fresh password plus a fixed Guardian/API execute-once grant, never a general interactive SYSTEM terminal. A running SYSTEM service and an audit use record do not prove command completion. Keep the new management feature disabled until the approved isolated pilot verifies execution and reconnection.

Guardian reenrollment follows [docs/guardian-reenrollment.md](docs/guardian-reenrollment.md): separate purpose-bound SYSTEM RPC, actual capability before grant, protected pinned Guardian, one durable provider CAS, and public receipts only. An uncertain delivery is never retried; existing installation/manual password semantics remain unchanged.

Refresh recovery must admit only an actual encoded key frame from the owned one-slot queue; delta frames never clear discard state. See docs/owned-viewer.md.

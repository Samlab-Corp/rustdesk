# Project instructions

Follow [AGENTS.md](AGENTS.md) for source, build, and verification rules.

Company sources are `Samlab-Corp/rustdesk` and `Samlab-Corp/hbb_common`, with the common library pinned to an available company commit. Validated development changes use `release/next`; Windows test builds use `samlab-windows.yml`.

LetMeUp remote access starts at `https://kiosk.letmeup.co.kr` and ClassUp remote access starts at `https://ops.classup.io`. A separate console opening, source recovery, or a successful build does not establish a real unattended device connection. Preserve existing recovery access until approved pilot devices pass connection and reconnection checks.

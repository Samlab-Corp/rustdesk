# Authenticated Windows terminal CLI

`samlab-terminal` is a console binary using the existing RustDesk `TERMINAL`
connection, login, encryption, terminal permission and current-user token path.
It does not start Flutter/Sciter, enable terminal permissions, change passwords,
open a listening port, or introduce another remote-execution protocol.

Build with the company's existing Windows native dependencies:

    cargo build --release --bin samlab-terminal --features flutter,hwcodec,vram

Arguments contain only an explicit numeric RustDesk target and optional limits:

    samlab-terminal --target <numeric-id> --force-relay --timeout-seconds 60 --max-output-bytes 1048576

Send one JSON object through the child's redirected standard input, then close
that pipe. Fields are `password`, `command` (PowerShell), and optional
`connection_token`. Obtain existing credentials from the approved secret store
in the invoking program's memory. Never put the JSON in command arguments,
environment variables, shell history, temporary files, or logs. The maximum
request size is 64 KiB. The command is limited to 32 KiB, the deadline to 300
seconds and captured terminal output to 4 MiB.

The adapter uses an ephemeral peer configuration, disables normal client logs,
and returns only one JSON result on standard output. The result includes
`status`, a fixed `reason`, captured command `output`, and `remoteExitCode`.
Terminal output is a combined PTY stream, so stdout and stderr from the remote
command cannot be separated. Launcher echo, shell banners and control sequences
are removed before capturing the command output. The random per-command
completion marker and terminal id must match; connection acceptance, timeout or
a closed shell without that marker never means command success.

Local exit codes: 0 = confirmed remote exit 0; 10 = confirmed nonzero remote
exit (see JSON); 1 = connection/protocol/output failure or unconfirmed command;
2 = invalid input; 124 = finite timeout. A timed-out command may have already
run. The client closes its nonpersistent terminal/session and does not retry;
operators must inspect state before repeating a mutation.

The CLI never automatically accepts an authentication prompt, insecure
connection, two-factor challenge, Windows session selector or OS-account login.
It uses the current logged-in remote user and does not request administrator
login. Missing permission or an absent active user is a failure to resolve
through the normal administrative workflow, not a reason to bypass it.

## Verification

Framing checks can run without native dependency compilation:

    rustc --edition 2021 --test src/headless_terminal_policy.rs -o <OS-temp-test-executable>

The ignored `headless_terminal::tests::existing_local_service_hostname` test is
opt-in. Set only the non-secret executable path in `SAMLAB_TERMINAL_EXE` and
the explicit local numeric id in `SAMLAB_LOCAL_TERMINAL_ID`. The test reads the
existing local service id and temporary password through normal read-only IPC,
requires exact id equality, and sends only `hostname` via stdin. It never sets
credentials or terminal permissions. This is local-service evidence, separate
from a customer device connection or unattended reconnection.

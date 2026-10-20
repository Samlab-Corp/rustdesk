# Fixed kiosk control over private stdin

This protocol is separate from the interactive terminal and from SYSTEM management.
It requires the existing encrypted RustDesk session, terminal permission and a
fresh password validation. It does not enable a permission or change enrollment.
Never put approval material in the legacy `command` / `-EncodedCommand` path.

## Client contract

Use `samlab-terminal --target ADDRESS --kiosk-control-probe` before obtaining a
short-lived app approval. Then use `--kiosk-control` with a new delivery UUID.
`--force-relay`, `--timeout-seconds 1..300` (default 60), and
`--max-output-bytes 1..32768` (default 32768) retain their existing meanings.
These two modes accept only redirected JSON stdin:

```json
{
  "password": "<runtime input only>",
  "delivery_id": "11111111-1111-4111-8111-111111111111",
  "operation_id": "22222222-2222-4222-8222-222222222222",
  "expected_device_id": "<Guardian-verified device identity>",
  "wrapper_sha256": "<lowercase sha256 of the approved installed wrapper>",
  "payload": {
    "commandVersion": 1,
    "deliveryId": "11111111-1111-4111-8111-111111111111",
    "operationId": "22222222-2222-4222-8222-222222222222",
    "action": "status"
  }
}
```

Optional `connection_token` is also stdin-only. Probe forbids `payload`. Unknown
fields, arbitrary commands, script paths and executable overrides are rejected.
UUIDs are lowercase version 4. Payload is at most 32768 bytes. The three fixed
actions match the app's `kiosk-command-transport.ts` contract:

* `prepare` adds `assignment` with environment, positive safe-integer merchantId,
  deviceId, outer/inner location and number 1..99.
* `apply` adds `approval` containing approvalToken and the exact ES256 challenge
  metadata. Credentials are never part of the command text, argv or output.
* `status` has no extra fields. Use a new deliveryId and the same operationId to
  read an uncertain operation; never repeat apply to recover a lost response.

Probe returns `status: "capable"`, controlVersion 1,
action `letmeup-kiosk-control-v1`, nonPty/currentUser true, wrapperSha256 and
expectedDeviceId, with empty output and null remoteExitCode. The expected device
identity is caller scope binding, **not an independent hardware measurement**.
The caller must verify Guardian hardware identity, exact assignment and the
prepare receipt's P256 public key before obtaining an approval.

Execute returns status/reason/output/remoteExitCode. Only `completed` with an
explicit exit code and a validated public app receipt establishes a returned
command result. It does not itself mean that the app receipt is verified: inspect
`ok`, `verified`, assignment and observed state. Raw stdout/stderr and remote
error strings never pass through. Public keyId is SHA256 in base64url (43 chars),
not hexadecimal; publicKey is the app's SPKI DER base64url.

## Transport and current-user worker

The terminal login has a new, additive protocol discriminator. The client sends
no `OpenTerminal`, `TerminalData`, script or payload before a matching versioned
capability/challenge. Old peers fail with capability_required before any approval
is transmitted. A capability is fresh for 20 seconds, binds address, scope, wrapper
hash and delivery, and can consume one exact payload SHA256 only. Wrong input
spends the capability too. Replayed delivery IDs are rejected by a bounded,
non-evicting process-local set. No automatic reconnect/retry is performed.

On Windows, only the active interactive user is accepted; SYSTEM/service tokens,
prelogin, supplied OS credentials and administrator substitution are rejected.
The fixed install is resolved from KnownFolder ProgramFiles:

* `LET ME UP - Study Cafe V2\LET ME UP - Study Cafe V2.exe`
* `LET ME UP - Study Cafe V2\resources\kiosk-control.ps1`

All ancestors and files reject reparse points, untrusted ownership/write ACLs;
held read-share-only handles prevent replacement. Wrapper SHA256 and single-link
identity are checked before capability and again in the user helper. Missing app
or wrapper is explicitly unavailable; this transport does not bootstrap an app.

Windows does not support handle inheritance across sessions. A SYSTEM server
therefore launches the same RustDesk binary as the selected user with **no handle
inheritance**, passing only a random pipe UUID and service PID. A first-instance,
local-only duplex named pipe admits SYSTEM and that user only. The service checks
the actual connecting helper PID against its held child handle before writing the
frame. The helper holds/verifies the actual server PID, SYSTEM token, liveness and
same executable path before reading. A failed check closes without execution.
See [Microsoft's process-creation contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera).

The helper independently checks payload hash, schema and install identity. It
creates a non-PTY PowerShell child **inside its own user session**, with an explicit
three-handle inheritance list and anonymous stdin/stdout/stderr. Only fixed paths
appear in argv; user environment is built from the user token with fixed system
PATH/module path and no NODE_OPTIONS/ELECTRON_RUN_AS_NODE. No execution-policy
override is used. The helper initializes neither logs nor crash dump handling.
Output is combined-size bounded; stderr is discarded. A job guard kills an
abandoned wrapper, while the intended GUI child may survive the wrapper.
Named-pipe I/O has a deadline and cancelled operations are drained before buffer
release. Helper loss, timeout, output overflow or invalid receipts are uncertain.

## Evidence limits and rollout

The RustDesk delivery set is not a durable execution ledger. The app's durable
operation state prevents a second apply after uncertain execution. Probe does
not observe the app or prove absence of active deliveries; it must never be used
to assert `noActiveDelivery: true` or to finalize an unexecuted operation. Unknown
remote state remains uncertain until genuine readback establishes the outcome.

Source/type checks, local pipe fixtures and product hashes are separate from a
real cross-session device run. Upgrade both endpoints and verify the approved
isolated device before enabling the workflow. Preserve existing remote recovery
access. No production or device rollout is implied by this change.

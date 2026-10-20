//! Service-to-current-user bridge. No inherited cross-session handles or PTY.
//! Both endpoints verify the actual peer PID before any sensitive frame is read.
use super::kiosk_control::{self, Handle, Outcome};
use crate::{kiosk_control_payload, kiosk_control_policy as policy};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    time::{Duration, Instant},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
            HLOCAL, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation,
            InitializeSecurityDescriptor, SetSecurityDescriptorDacl, TokenUser,
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::*,
        System::{
            Pipes::*,
            SystemInformation::GetSystemDirectoryW,
            Threading::*,
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        },
    },
};
const BAD: &str = "kiosk_control_execution_unconfirmed";
const MAX_FRAME: usize = 262144;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    version: u32,
    delivery_id: String,
    operation_id: String,
    expected_device_id: String,
    wrapper_sha256: String,
    payload_sha256: String,
    timeout_seconds: u32,
    output_limit_bytes: u32,
    payload: Vec<u8>,
}
impl Drop for Frame {
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}
impl Frame {
    fn request(&self) -> policy::Request {
        policy::Request {
            version: self.version,
            delivery_id: self.delivery_id.clone(),
            operation_id: self.operation_id.clone(),
            expected_device_id: self.expected_device_id.clone(),
            wrapper_sha256: self.wrapper_sha256.clone(),
            payload_sha256: self.payload_sha256.clone(),
            timeout_seconds: self.timeout_seconds,
            output_limit_bytes: self.output_limit_bytes,
            probe_only: false,
        }
    }
}
fn validated(frame: &Frame) -> Result<(policy::Request, String), &'static str> {
    let request = frame.request();
    if !request.valid()
        || frame.payload.len() > policy::MAX_PAYLOAD
        || hex::encode(sha2::Sha256::digest(&frame.payload)) != request.payload_sha256
    {
        return Err(BAD);
    }
    let action = kiosk_control_payload::validate(&frame.payload, &request)?;
    Ok((request, action))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    exit: Option<i32>,
    receipt: Vec<u8>,
}
struct Child {
    process: Handle,
    _thread: Handle,
}
impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            let _ = TerminateProcess(self.process.0, 1);
            let _ = WaitForSingleObject(self.process.0, 1000);
        }
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn name(id: &str) -> String {
    format!(r"\\.\pipe\samlab_kiosk_control_{}", id)
}
fn remaining(deadline: Instant) -> Result<u32, &'static str> {
    let ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis();
    if ms == 0 {
        Err(BAD)
    } else {
        Ok(ms.min(u32::MAX as u128) as u32)
    }
}

// Every overlapped operation is cancelled and drained before its buffers/event
// leave scope. No detached thread retains the secret frame after a timeout.
fn finish(
    pipe: HANDLE,
    ov: &mut OVERLAPPED,
    pending: bool,
    deadline: Instant,
) -> Result<u32, &'static str> {
    let mut count = 0;
    if pending {
        let wait = remaining(deadline)
            .ok()
            .map(|ms| unsafe { WaitForSingleObject(ov.hEvent, ms) });
        if wait != Some(WAIT_OBJECT_0) {
            unsafe {
                let _ = CancelIoEx(pipe, Some(ov));
                let _ = GetOverlappedResult(pipe, ov, &mut count, true);
            }
            return Err(BAD);
        }
    }
    unsafe { GetOverlappedResult(pipe, ov, &mut count, false) }.map_err(|_| BAD)?;
    Ok(count)
}
fn event() -> Result<(Handle, OVERLAPPED), &'static str> {
    let h = Handle(unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(|_| BAD)?);
    let mut ov = OVERLAPPED::default();
    ov.hEvent = h.0;
    Ok((h, ov))
}
fn connect(pipe: HANDLE, deadline: Instant) -> Result<(), &'static str> {
    let (_event, mut ov) = event()?;
    match unsafe { ConnectNamedPipe(pipe, Some(&mut ov)) } {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(()),
        Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
            finish(pipe, &mut ov, true, deadline).map(|_| ())
        }
        _ => Err(BAD),
    }
}
fn transfer(
    pipe: HANDLE,
    buf: &mut [u8],
    writing: bool,
    deadline: Instant,
) -> Result<(), &'static str> {
    let mut offset = 0;
    while offset < buf.len() {
        remaining(deadline)?;
        let (_event, mut ov) = event()?;
        let result = if writing {
            unsafe { WriteFile(pipe, Some(&buf[offset..]), None, Some(&mut ov)) }
        } else {
            unsafe { ReadFile(pipe, Some(&mut buf[offset..]), None, Some(&mut ov)) }
        };
        let pending = match result {
            Ok(()) => false,
            Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => true,
            _ => return Err(BAD),
        };
        let n = finish(pipe, &mut ov, pending, deadline)? as usize;
        if n == 0 || n > buf.len() - offset {
            return Err(BAD);
        }
        offset += n;
    }
    Ok(())
}
fn server_pipe(id: &str, token: HANDLE) -> Result<Handle, &'static str> {
    let sid =
        super::get_user_sid_from_token(super::UserToken::new(token.0 as usize)).map_err(|_| BAD)?;
    let acl = super::create_restricted_dacl(&sid).map_err(|_| BAD)?;
    struct Acl(*mut std::ffi::c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
    let _acl = Acl(acl);
    let mut descriptor = [0u64; 8];
    let sd = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast());
    unsafe { InitializeSecurityDescriptor(sd, 1) }.map_err(|_| BAD)?;
    unsafe { SetSecurityDescriptorDacl(sd, true, Some(acl.cast()), false) }.map_err(|_| BAD)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let path = wide(&name(id));
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(path.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(
                PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_OVERLAPPED.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0,
            ),
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            20000,
            Some(&sa),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        Err(BAD)
    } else {
        Ok(Handle(pipe))
    }
}
fn launch(token: HANDLE, id: &str) -> Result<Child, &'static str> {
    let executable = std::env::current_exe().map_err(|_| BAD)?;
    let text = executable.to_str().ok_or(BAD)?;
    if text.contains('"') {
        return Err(BAD);
    }
    let application: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut command = wide(&format!(
        "\"{}\" --kiosk-control-helper {} {}",
        text,
        id,
        unsafe { GetCurrentProcessId() }
    ));
    let mut system = vec![0u16; 32768];
    let size = unsafe { GetSystemDirectoryW(Some(&mut system)) } as usize;
    if size == 0 || size >= system.len() {
        return Err(BAD);
    }
    let root = std::path::PathBuf::from(String::from_utf16(&system[..size]).map_err(|_| BAD)?);
    let env = kiosk_control::environment(token, &root)?;
    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessAsUserW(
            Some(token),
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(env.as_ptr().cast()),
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    }
    .map_err(|_| BAD)?;
    Ok(Child {
        process: Handle(pi.hProcess),
        _thread: Handle(pi.hThread),
    })
}
pub fn execute(
    token: Handle,
    install: crate::native_management_guardian::FixedKiosk,
    mut payload: Vec<u8>,
    request: policy::Request,
) -> Outcome {
    let result = (|| {
        let frame = Frame {
            version: request.version,
            delivery_id: request.delivery_id.clone(),
            operation_id: request.operation_id.clone(),
            expected_device_id: request.expected_device_id.clone(),
            wrapper_sha256: request.wrapper_sha256.clone(),
            payload_sha256: request.payload_sha256.clone(),
            timeout_seconds: request.timeout_seconds,
            output_limit_bytes: request.output_limit_bytes,
            payload: std::mem::take(&mut payload),
        };
        let mut bytes = serde_json::to_vec(&frame).map_err(|_| BAD)?;
        // Keep the pinned installation and process handles until the result is read.
        let _install = install;
        let id = uuid::Uuid::new_v4().to_string();
        let pipe = server_pipe(&id, token.0)?;
        let child = launch(token.0, &id)?;
        let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds as u64 + 20);
        connect(pipe.0, deadline)?;
        let mut pid = 0;
        unsafe { GetNamedPipeClientProcessId(pipe.0, &mut pid) }.map_err(|_| BAD)?;
        if pid != unsafe { GetProcessId(child.process.0) } || pid == 0 {
            return Err(BAD);
        }
        if bytes.len() > MAX_FRAME {
            return Err(BAD);
        }
        let mut length = (bytes.len() as u32).to_le_bytes();
        transfer(pipe.0, &mut length, true, deadline)?;
        let sent = transfer(pipe.0, &mut bytes, true, deadline);
        bytes.fill(0);
        sent?;
        transfer(pipe.0, &mut length, false, deadline)?;
        let size = u32::from_le_bytes(length) as usize;
        if size == 0 || size > MAX_FRAME {
            return Err(BAD);
        }
        let mut reply = vec![0; size];
        transfer(pipe.0, &mut reply, false, deadline)?;
        let reply: Reply = serde_json::from_slice(&reply).map_err(|_| BAD)?;
        if reply.receipt.len() > request.output_limit_bytes as usize {
            return Err(BAD);
        }
        let action = kiosk_control_payload::validate(&frame.payload, &request)?;
        let receipt = kiosk_control_payload::receipt(&reply.receipt, &request, &action)?;
        Ok((reply.exit, receipt))
    })();
    payload.fill(0);
    match result {
        Ok((exit, receipt)) => Outcome {
            exit,
            receipt,
            reason: "",
        },
        Err(reason) => Outcome {
            exit: None,
            receipt: vec![],
            reason,
        },
    }
}
fn system_parent(pid: u32) -> Result<Handle, &'static str> {
    let parent = Handle(
        unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .map_err(|_| BAD)?,
    );
    if unsafe { WaitForSingleObject(parent.0, 0) }.0 != 258 {
        return Err(BAD);
    }
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(parent.0, TOKEN_QUERY, &mut token) }.map_err(|_| BAD)?;
    let token = Handle(token);
    let mut needed = 0;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
    if needed == 0 || needed > 65536 {
        return Err(BAD);
    }
    let mut buf = vec![0u64; (needed as usize + 7) / 8];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(|_| BAD)?;
    let user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) }.map_err(|_| BAD)?;
    let sid_value = unsafe { sid.to_string() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid.0.cast())));
    }
    if sid_value.map_err(|_| BAD)? != "S-1-5-18" {
        return Err(BAD);
    }
    let mut path = vec![0u16; 32768];
    let mut size = path.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            parent.0,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut size,
        )
    }
    .map_err(|_| BAD)?;
    let expected = std::env::current_exe()
        .map_err(|_| BAD)?
        .to_string_lossy()
        .into_owned();
    let actual = String::from_utf16(&path[..size as usize]).map_err(|_| BAD)?;
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(BAD);
    }
    Ok(parent)
}
// Invoked only in the actual interactive user's session. No secret argv or files.
pub fn run(args: &[String]) -> Result<(), &'static str> {
    if args.len() != 2 || !policy::uuid4(&args[0]) {
        return Err(BAD);
    }
    let pid = args[1].parse::<u32>().map_err(|_| BAD)?;
    let _parent = system_parent(pid)?;
    let token = kiosk_control::user_token(None)?;
    let path = wide(&name(&args[0]));
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0),
            None,
        )
    }
    .map_err(|_| BAD)?;
    let mut file = unsafe { std::fs::File::from_raw_handle(handle.0) };
    let mut server = 0;
    unsafe { GetNamedPipeServerProcessId(HANDLE(file.as_raw_handle()), &mut server) }
        .map_err(|_| BAD)?;
    if server != pid {
        return Err(BAD);
    }
    let mut length = [0; 4];
    file.read_exact(&mut length).map_err(|_| BAD)?;
    let size = u32::from_le_bytes(length) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(BAD);
    }
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes).map_err(|_| BAD)?;
    let decoded = serde_json::from_slice::<Frame>(&bytes);
    bytes.fill(0);
    let mut frame = decoded.map_err(|_| BAD)?;
    let (request, action) = validated(&frame)?;
    let install = crate::native_management_guardian::pin_kiosk(&request.wrapper_sha256)?;
    let outcome = kiosk_control::execute_direct(
        token,
        install,
        std::mem::take(&mut frame.payload),
        request.timeout_seconds,
        request.output_limit_bytes,
    );
    let receipt = kiosk_control_payload::receipt(&outcome.receipt, &request, &action)?;
    let reply = serde_json::to_vec(&Reply {
        exit: outcome.exit,
        receipt,
    })
    .map_err(|_| BAD)?;
    if reply.len() > MAX_FRAME {
        return Err(BAD);
    }
    file.write_all(&(reply.len() as u32).to_le_bytes())
        .map_err(|_| BAD)?;
    file.write_all(&reply).map_err(|_| BAD)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_pipe_round_trip_and_actual_peer_pid() {
        // Local pipe fixture only: no remote connection, app or script execution.
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.unwrap();
        let token = Handle(token);
        let id = uuid::Uuid::new_v4().to_string();
        let pipe = server_pipe(&id, token.0).unwrap();
        let path = name(&id);
        let child = std::thread::spawn(move || {
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(wide(&path).as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0),
                    None,
                )
            }
            .unwrap();
            let mut file = unsafe { std::fs::File::from_raw_handle(handle.0) };
            let mut input = [0; 4];
            file.read_exact(&mut input).unwrap();
            assert_eq!(&input, b"PING");
            file.write_all(b"PONG").unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        connect(pipe.0, deadline).unwrap();
        let mut actual = 0;
        unsafe { GetNamedPipeClientProcessId(pipe.0, &mut actual) }.unwrap();
        assert_eq!(actual, unsafe { GetCurrentProcessId() });
        let mut ping=*b"PING";
        transfer(pipe.0, &mut ping, true, deadline).unwrap();
        let mut reply = [0; 4];
        transfer(pipe.0, &mut reply, false, deadline).unwrap();
        assert_eq!(&reply, b"PONG");
        child.join().unwrap();
    }
    #[test]
    fn unconnected_pipe_deadline_cancels_and_drains_overlapped_io() {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.unwrap();
        let token = Handle(token);
        let pipe = server_pipe(&uuid::Uuid::new_v4().to_string(), token.0).unwrap();
        let now = Instant::now();
        assert!(connect(pipe.0, now + Duration::from_millis(25)).is_err());
        assert!(now.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn helper_independently_rejects_tampered_scope_and_hash() {
        let delivery = "11111111-1111-4111-8111-111111111111";
        let operation = "22222222-2222-4222-8222-222222222222";
        let payload=serde_json::to_vec(&serde_json::json!({"commandVersion":1,"deliveryId":delivery,"operationId":operation,"action":"status"})).unwrap();
        let mut frame = Frame {
            version: 1,
            delivery_id: delivery.into(),
            operation_id: operation.into(),
            expected_device_id: "fixture".into(),
            wrapper_sha256: "a".repeat(64),
            payload_sha256: hex::encode(sha2::Sha256::digest(&payload)),
            timeout_seconds: 60,
            output_limit_bytes: 32768,
            payload,
        };
        assert!(validated(&frame).is_ok());
        frame.operation_id = delivery.into();
        assert!(validated(&frame).is_err());
        frame.operation_id = operation.into();
        frame.payload.push(b' ');
        assert!(validated(&frame).is_err());
        let mut value = serde_json::to_value(&frame).unwrap();
        value["command"] = serde_json::json!("fixture-only");
        assert!(serde_json::from_value::<Frame>(value).is_err());
    }
}

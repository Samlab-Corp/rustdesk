//! Current-user fixed wrapper, anonymous stdin/stdout, no console and no PTY.
use std::{
    fs::File,
    io::{Read, Write},
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, DuplicateHandle, LocalFree, SetHandleInformation, DUPLICATE_SAME_ACCESS,
            HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HLOCAL, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenSessionId, TokenUser,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
            },
            Pipes::CreatePipe,
            SystemInformation::GetSystemDirectoryW,
            Threading::*,
        },
    },
};
const UNREADY: &str = "kiosk_control_not_ready";
pub struct Handle(pub HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
fn duplicate(token: HANDLE) -> Result<Handle, &'static str> {
    let mut out = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            token,
            GetCurrentProcess(),
            &mut out,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(|_| UNREADY)?;
    Ok(Handle(out))
}
pub fn user_token(token: Option<super::UserToken>) -> Result<Handle, &'static str> {
    let token = if let Some(token) = token {
        duplicate(HANDLE(token.as_raw() as _))?
    } else {
        let mut out = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut out) }
            .map_err(|_| UNREADY)?;
        Handle(out)
    };
    let mut session = 0u32;
    let mut needed = 0;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenSessionId,
            Some((&mut session as *mut u32).cast()),
            4,
            &mut needed,
        )
    }
    .map_err(|_| UNREADY)?;
    if session == 0 {
        return Err("kiosk_control_current_user_required");
    }
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
    if needed == 0 || needed > 65536 {
        return Err(UNREADY);
    }
    let mut buffer = vec![0u64; (needed as usize + 7) / 8];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(|_| UNREADY)?;
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(|_| UNREADY)?;
    let sid = unsafe { text.to_string() }.map_err(|_| UNREADY);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    if matches!(sid?.as_str(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20") {
        return Err("kiosk_control_current_user_required");
    }
    Ok(token)
}
fn pipe() -> Result<(Handle, Handle), &'static str> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    unsafe { CreatePipe(&mut read, &mut write, Some(&sa), 0) }.map_err(|_| UNREADY)?;
    Ok((Handle(read), Handle(write)))
}
struct Attributes {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _bytes: Vec<usize>,
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}
fn attributes(handles: &[HANDLE]) -> Result<Attributes, &'static str> {
    let mut size = 0;
    let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
    if size == 0 || size > 65536 {
        return Err(UNREADY);
    }
    let mut bytes =
        vec![0usize; (size + std::mem::size_of::<usize>() - 1) / std::mem::size_of::<usize>()];
    let list = LPPROC_THREAD_ATTRIBUTE_LIST(bytes.as_mut_ptr().cast());
    unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut size) }
        .map_err(|_| UNREADY)?;
    let value = Attributes {
        list,
        _bytes: bytes,
    };
    unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(handles.as_ptr().cast()),
            std::mem::size_of_val(handles),
            None,
            None,
        )
    }
    .map_err(|_| UNREADY)?;
    Ok(value)
}
pub(super) fn environment(
    token: HANDLE,
    system: &std::path::Path,
) -> Result<Vec<u16>, &'static str> {
    let mut raw = std::ptr::null_mut();
    unsafe { CreateEnvironmentBlock(&mut raw, Some(token), false) }.map_err(|_| UNREADY)?;
    let result = (|| {
        let mut values = std::collections::BTreeMap::<String, String>::new();
        let p = raw.cast::<u16>();
        let mut offset = 0;
        while offset < 131072 {
            let mut end = offset;
            while end < 131072 && unsafe { *p.add(end) } != 0 {
                end += 1;
            }
            if end >= 131072 {
                return Err(UNREADY);
            }
            if end == offset {
                break;
            }
            let item = String::from_utf16(unsafe {
                std::slice::from_raw_parts(p.add(offset), end - offset)
            })
            .map_err(|_| UNREADY)?;
            if let Some((key, value)) = item.split_once('=') {
                let key = key.to_ascii_uppercase();
                // Retain only Windows profile/path values needed by the fixed
                // app. Runtime, proxy, module and script-policy injection vars
                // from a user's registry must not alter this control worker.
                if matches!(
                    key.as_str(),
                    "APPDATA"
                        | "LOCALAPPDATA"
                        | "USERPROFILE"
                        | "USERNAME"
                        | "USERDOMAIN"
                        | "USERDOMAIN_ROAMINGPROFILE"
                        | "HOMEDRIVE"
                        | "HOMEPATH"
                        | "TEMP"
                        | "TMP"
                        | "SYSTEMROOT"
                        | "WINDIR"
                        | "COMSPEC"
                        | "PROGRAMDATA"
                        | "PUBLIC"
                        | "PROGRAMFILES"
                        | "PROGRAMFILES(X86)"
                        | "PROGRAMW6432"
                        | "COMMONPROGRAMFILES"
                        | "COMMONPROGRAMFILES(X86)"
                        | "COMMONPROGRAMW6432"
                        | "COMPUTERNAME"
                        | "OS"
                        | "PROCESSOR_ARCHITECTURE"
                        | "PROCESSOR_ARCHITEW6432"
                        | "NUMBER_OF_PROCESSORS"
                ) {
                    values.insert(key, value.into());
                }
            }
            offset = end + 1;
        }
        if offset >= 131072 {
            return Err(UNREADY);
        }
        values.insert("PATH".into(), system.to_string_lossy().into_owned());
        values.insert(
            "PSMODULEPATH".into(),
            system
                .join(r"WindowsPowerShell\v1.0\Modules")
                .to_string_lossy()
                .into_owned(),
        );
        values.remove("NODE_OPTIONS");
        values.remove("ELECTRON_RUN_AS_NODE");
        let mut result = Vec::new();
        for (k, v) in values {
            result.extend(format!("{k}={v}").encode_utf16());
            result.push(0);
        }
        result.push(0);
        Ok(result)
    })();
    unsafe {
        let _ = DestroyEnvironmentBlock(raw);
    }
    result
}
struct Child {
    process: Handle,
    thread: Handle,
    finished: bool,
    _job: Handle,
}
impl Drop for Child {
    fn drop(&mut self) {
        if !self.finished {
            unsafe {
                let _ = TerminateProcess(self.process.0, 1);
                let _ = WaitForSingleObject(self.process.0, 1000);
            }
        }
    }
}
pub struct Outcome {
    pub exit: Option<i32>,
    pub receipt: Vec<u8>,
    pub reason: &'static str,
}
pub fn execute(
    token: Handle,
    as_user: bool,
    install: crate::native_management_guardian::FixedKiosk,
    payload: Vec<u8>,
    request: crate::kiosk_control_policy::Request,
) -> Outcome {
    if as_user {
        return super::kiosk_bridge::execute(token, install, payload, request);
    }
    execute_direct(
        token,
        install,
        payload,
        request.timeout_seconds,
        request.output_limit_bytes,
    )
}
pub(super) fn execute_direct(
    token: Handle,
    install: crate::native_management_guardian::FixedKiosk,
    mut payload: Vec<u8>,
    timeout: u32,
    cap: u32,
) -> Outcome {
    let result = run(&token, &install, &mut payload, timeout, cap);
    payload.fill(0);
    match result {
        Ok((exit, receipt)) => Outcome {
            exit: Some(exit),
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
fn run(
    token: &Handle,
    install: &crate::native_management_guardian::FixedKiosk,
    payload: &mut Vec<u8>,
    timeout: u32,
    cap: u32,
) -> Result<(i32, Vec<u8>), &'static str> {
    let mut system = vec![0u16; 32768];
    let size = unsafe { GetSystemDirectoryW(Some(&mut system)) } as usize;
    if size == 0 || size >= system.len() {
        return Err(UNREADY);
    }
    let system =
        std::path::PathBuf::from(String::from_utf16(&system[..size]).map_err(|_| UNREADY)?);
    let powershell = system.join(r"WindowsPowerShell\v1.0\powershell.exe");
    let application: Vec<u16> = powershell
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if [
        powershell.as_path(),
        install.wrapper.as_path(),
        install.executable.as_path(),
    ]
    .iter()
    .any(|p| p.to_string_lossy().contains('"'))
    {
        return Err(UNREADY);
    }
    // Only fixed installation paths enter argv. Payload is exclusively stdin.
    // No ExecutionPolicy override: a machine script policy failure stays closed.
    let line = format!(
        "\"{}\" -NoLogo -NoProfile -NonInteractive -File \"{}\" -Executable \"{}\"",
        powershell.display(),
        install.wrapper.display(),
        install.executable.display()
    );
    let mut command: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
    let (input_read, input_write) = pipe()?;
    let (output_read, output_write) = pipe()?;
    let (error_read, error_write) = pipe()?;
    for handle in [input_write.0, output_read.0, error_read.0] {
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
            .map_err(|_| UNREADY)?;
    }
    let inherited = [input_read.0, output_write.0, error_write.0];
    let attrs = attributes(&inherited)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input_read.0;
    startup.StartupInfo.hStdOutput = output_write.0;
    startup.StartupInfo.hStdError = error_write.0;
    startup.lpAttributeList = attrs.list;
    let env = environment(token.0, &system)?;
    let mut information = PROCESS_INFORMATION::default();
    let flags = CREATE_NO_WINDOW
        | CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT;
    let job = Handle(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(|_| UNREADY)?);
    let created = unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            true,
            flags,
            Some(env.as_ptr().cast()),
            PCWSTR::null(),
            &startup.StartupInfo,
            &mut information,
        )
    };
    created.map_err(|_| UNREADY)?;
    let mut child = Child {
        process: Handle(information.hProcess),
        thread: Handle(information.hThread),
        finished: false,
        _job: job,
    };
    // The fixed app is meant to survive this wrapper. Its children deliberately
    // break away; only the wrapper worker is killed when its helper disappears.
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    unsafe {
        SetInformationJobObject(
            child._job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    }
    .map_err(|_| UNREADY)?;
    unsafe { AssignProcessToJobObject(child._job.0, child.process.0) }.map_err(|_| UNREADY)?;
    drop(input_read);
    drop(output_write);
    drop(error_write);
    if unsafe { ResumeThread(child.thread.0) } == u32::MAX {
        return Err(UNREADY);
    }
    let deadline = Instant::now() + Duration::from_secs(timeout as u64);
    let (written_tx, written_rx) = mpsc::sync_channel(1);
    let mut data = std::mem::take(payload);
    std::thread::spawn(move || {
        let mut file = unsafe { File::from_raw_handle(input_write.0 .0) };
        std::mem::forget(input_write);
        let result = file.write_all(&data);
        data.fill(0);
        drop(file);
        let _ = written_tx.send(result.is_ok());
    });
    let used = Arc::new(AtomicUsize::new(0));
    let overflow = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel(2);
    for (handle, keep) in [(output_read, true), (error_read, false)] {
        let used = used.clone();
        let overflow = overflow.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut file = unsafe { File::from_raw_handle(handle.0 .0) };
            std::mem::forget(handle);
            let mut result = Vec::new();
            let mut buf = [0u8; 4096];
            let mut ok = true;
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let start = used.fetch_add(n, Ordering::AcqRel);
                        if start.saturating_add(n) > cap as usize {
                            overflow.store(true, Ordering::Release);
                            ok = false;
                            break;
                        }
                        if keep {
                            result.extend_from_slice(&buf[..n]);
                        }
                        buf[..n].fill(0);
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            let _ = tx.send((keep, ok, result));
        });
    }
    drop(tx);
    loop {
        if overflow.load(Ordering::Acquire) {
            return Err("kiosk_control_output_unconfirmed");
        }
        if Instant::now() >= deadline {
            return Err("kiosk_control_timeout_unconfirmed");
        }
        match unsafe { WaitForSingleObject(child.process.0, 20) } {
            WAIT_OBJECT_0 => break,
            value if value.0 == 258 => {}
            _ => return Err("kiosk_control_execution_unconfirmed"),
        }
    }
    let mut exit = 0;
    unsafe { GetExitCodeProcess(child.process.0, &mut exit) }
        .map_err(|_| "kiosk_control_execution_unconfirmed")?;
    child.finished = true;
    if written_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()
        != Some(true)
    {
        return Err("kiosk_control_execution_unconfirmed");
    }
    let mut stdout = Vec::new();
    for _ in 0..2 {
        let (keep, ok, bytes) = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "kiosk_control_execution_unconfirmed")?;
        if !ok {
            return Err("kiosk_control_output_unconfirmed");
        }
        if keep {
            stdout = bytes;
        }
    }
    // No raw stderr is ever returned. The fixed wrapper validates and emits a receipt.
    Ok((exit as i32, stdout))
}

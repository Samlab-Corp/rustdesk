//! Fixed SYSTEM --server child of the live SCM service, rechecked around secret IPC.
use crate::ipc::{ConnClient, ConnectionTmpl};
use std::{
    fs::{self, File, OpenOptions},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::PathBuf,
};
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Pipes::GetNamedPipeServerProcessId,
            Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
        },
        UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT},
    },
};
use windows_service::{
    service::{ServiceAccess, ServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
const UNTRUSTED: &str = "reenrollment_identity_untrusted";
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{FILETIME, UNICODE_STRING, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};
fn created(process: &Process) -> Result<u64, &'static str> {
    if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT {
        return Err(UNTRUSTED);
    }
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) }
        .map_err(|_| UNTRUSTED)?;
    let value = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    if value == 0 {
        return Err(UNTRUSTED);
    }
    Ok(value)
}
fn parent_pid(pid: u32) -> Result<u32, &'static str> {
    let snapshot =
        Process(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|_| UNTRUSTED)?);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe { Process32FirstW(snapshot.0, &mut entry) }.map_err(|_| UNTRUSTED)?;
    loop {
        if entry.th32ProcessID == pid {
            return Ok(entry.th32ParentProcessID);
        }
        if unsafe { Process32NextW(snapshot.0, &mut entry) }.is_err() {
            return Err(UNTRUSTED);
        }
    }
}
fn command_line(process: &Process) -> Result<String, &'static str> {
    let mut needed = 0;
    let _ = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed < std::mem::size_of::<UNICODE_STRING>() as u32 || needed > 65536 {
        return Err(UNTRUSTED);
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let bytes = buffer.len() * std::mem::size_of::<usize>();
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            buffer.as_mut_ptr().cast(),
            bytes as u32,
            &mut needed,
        )
    };
    if status.0 < 0 {
        return Err(UNTRUSTED);
    }
    let value = unsafe { &*buffer.as_ptr().cast::<UNICODE_STRING>() };
    let start = value.Buffer.0 as usize;
    let base = buffer.as_ptr() as usize;
    let len = value.Length as usize;
    if len == 0
        || len % 2 != 0
        || value.Length > value.MaximumLength
        || start % 2 != 0
        || start < base
        || start.checked_add(len).is_none_or(|end| end > base + bytes)
    {
        return Err(UNTRUSTED);
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value.Buffer.0, len / 2) })
        .map_err(|_| UNTRUSTED)
}

fn lineage(
    child: u32,
    parent: u32,
    scm: u32,
    actual_parent: u32,
    child_at: u64,
    parent_at: u64,
) -> bool {
    child > 0
        && parent > 0
        && child != parent
        && parent == scm
        && actual_parent == parent
        && parent_at > 0
        && child_at >= parent_at
}
pub(crate) struct Pin {
    child: Process,
    parent: Process,
    child_pid: u32,
    parent_pid: u32,
    child_at: u64,
    parent_at: u64,
    expected: PathBuf,
    _file: File,
}
impl Pin {
    pub(crate) fn open(stream: &ConnectionTmpl<ConnClient>) -> Result<Self, &'static str> {
        let mut child_pid = 0;
        unsafe {
            GetNamedPipeServerProcessId(
                HANDLE(stream.inner.get_ref().as_raw_handle()),
                &mut child_pid,
            )
        }
        .map_err(|_| UNTRUSTED)?;
        let root = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }
            .map_err(|_| UNTRUSTED)?;
        let value = unsafe { root.to_string() };
        unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(root.0.cast())) };
        let expected = fs::canonicalize(
            PathBuf::from(value.map_err(|_| UNTRUSTED)?)
                .join("RustDesk")
                .join("RustDesk.exe"),
        )
        .map_err(|_| UNTRUSTED)?;
        if fs::canonicalize(std::env::current_exe().map_err(|_| UNTRUSTED)?)
            .map_err(|_| UNTRUSTED)?
            != expected
        {
            return Err(UNTRUSTED);
        }
        let parent_pid = Self::service(&expected)?;
        let open = |pid| {
            unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    false,
                    pid,
                )
            }
            .map(Process)
            .map_err(|_| UNTRUSTED)
        };
        let child = open(child_pid)?;
        let parent = open(parent_pid)?;
        let child_at = created(&child)?;
        let parent_at = created(&parent)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&expected)
            .map_err(|_| UNTRUSTED)?;
        let pin = Self {
            child,
            parent,
            child_pid,
            parent_pid,
            child_at,
            parent_at,
            expected,
            _file: file,
        };
        pin.check(stream)?;
        Ok(pin)
    }
    fn service(expected: &std::path::Path) -> Result<u32, &'static str> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| UNTRUSTED)?;
        let service = manager
            .open_service(
                "RustDesk",
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|_| UNTRUSTED)?;
        let status = service.query_status().map_err(|_| UNTRUSTED)?;
        let config = service.query_config().map_err(|_| UNTRUSTED)?;
        let command = config.executable_path.to_str().ok_or(UNTRUSTED)?;
        let account = config
            .account_name
            .as_ref()
            .ok_or(UNTRUSTED)?
            .to_string_lossy();
        if status.current_state != ServiceState::Running
            || !command_matches(command, expected, "--service")
            || !(account.eq_ignore_ascii_case("LocalSystem")
                || account.eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM"))
        {
            return Err(UNTRUSTED);
        }
        status.process_id.filter(|p| *p > 0).ok_or(UNTRUSTED)
    }
    pub(crate) fn check(&self, stream: &ConnectionTmpl<ConnClient>) -> Result<(), &'static str> {
        let mut pid = 0;
        unsafe {
            GetNamedPipeServerProcessId(HANDLE(stream.inner.get_ref().as_raw_handle()), &mut pid)
        }
        .map_err(|_| UNTRUSTED)?;
        if pid != self.child_pid
            || created(&self.child)? != self.child_at
            || created(&self.parent)? != self.parent_at
            || !lineage(
                pid,
                self.parent_pid,
                Self::service(&self.expected)?,
                parent_pid(pid)?,
                self.child_at,
                self.parent_at,
            )
        {
            return Err(UNTRUSTED);
        }
        for (process, pid, role) in [
            (&self.child, self.child_pid, "--server"),
            (&self.parent, self.parent_pid, "--service"),
        ] {
            if !crate::platform::is_process_running_as_system(pid).unwrap_or(false)
                || !command_matches(&command_line(process)?, &self.expected, role)
            {
                return Err(UNTRUSTED);
            }
            let mut image = vec![0u16; 32768];
            let mut len = image.len() as u32;
            unsafe {
                windows::Win32::System::Threading::QueryFullProcessImageNameW(
                    process.0,
                    windows::Win32::System::Threading::PROCESS_NAME_WIN32,
                    PWSTR(image.as_mut_ptr()),
                    &mut len,
                )
            }
            .map_err(|_| UNTRUSTED)?;
            let image = String::from_utf16(&image[..len as usize]).map_err(|_| UNTRUSTED)?;
            if fs::canonicalize(image).map_err(|_| UNTRUSTED)? != self.expected {
                return Err(UNTRUSTED);
            }
        }
        if Self::service(&self.expected)? != self.parent_pid
            || created(&self.child)? != self.child_at
            || created(&self.parent)? != self.parent_at
        {
            return Err(UNTRUSTED);
        }
        Ok(())
    }
}
fn command_matches(command: &str, path: &std::path::Path, role: &str) -> bool {
    command_path(command, role)
        .and_then(|p| fs::canonicalize(p).ok())
        .map_or(false, |p| p == path)
}
fn command_path<'a>(command: &'a str, role: &str) -> Option<&'a str> {
    command
        .strip_prefix('"')?
        .strip_suffix(&format!("\" {role}"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_child_and_creation_fences_reject_scm_replacement_and_pid_reuse() {
        assert!(lineage(20, 10, 10, 10, 200, 100));
        for args in [
            (20, 10, 11, 10, 200, 100),
            (20, 10, 10, 9, 200, 100),
            (20, 10, 10, 10, 99, 100),
            (10, 10, 10, 10, 200, 100),
            (20, 10, 10, 10, 200, 0),
        ] {
            assert!(!lineage(args.0, args.1, args.2, args.3, args.4, args.5));
        }
    }
    #[test]
    fn fixed_commands_do_not_accept_extra_arguments() {
        assert_eq!(
            command_path(
                "\"C:\\Program Files\\RustDesk\\RustDesk.exe\" --server",
                "--server"
            ),
            Some("C:\\Program Files\\RustDesk\\RustDesk.exe")
        );
        for c in ["x --server", "\"x\" --server --service", "\"x\" --service"] {
            assert!(command_path(c, "--server").is_none());
        }
    }
    #[test]
    fn held_current_process_measurements_are_read_only() {
        let process = Process(
            unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    false,
                    std::process::id(),
                )
            }
            .unwrap(),
        );
        assert!(created(&process).unwrap() > 0);
        assert!(parent_pid(std::process::id()).unwrap() > 0);
        assert!(!command_line(&process).unwrap().is_empty());
    }
}

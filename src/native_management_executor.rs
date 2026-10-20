//! One noninteractive child in a kill-on-close Windows job. No user-token lookup.
//! Call only after the connection's exact command grant has been consumed.
use std::io::{Read, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant};

pub struct Outcome {
    pub reason: &'static str,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub executor_is_system: bool,
}
fn failure(reason: &'static str, system: bool) -> Outcome {
    Outcome {
        reason,
        exit_code: None,
        stdout: vec![],
        stderr: vec![],
        executor_is_system: system,
    }
}
// One shared budget for both pipes. Continue draining only until the controller
// kills the job; never wait for unbounded attacker output to fit in memory.
fn capture(
    mut reader: impl Read,
    used: Arc<AtomicUsize>,
    overflow: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    cap: usize,
) -> Vec<u8> {
    let mut result = Vec::new();
    let mut bytes = [0u8; 4096];
    loop {
        match reader.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => {
                let start = used.fetch_add(n, Ordering::AcqRel);
                let take = cap.saturating_sub(start).min(n);
                result.extend_from_slice(&bytes[..take]);
                if take != n {
                    overflow.store(true, Ordering::Release);
                    break;
                }
            }
            Err(_) => {
                failed.store(true, Ordering::Release);
                break;
            }
        }
    }
    result
}

#[cfg(windows)]
pub fn execute(command: &str, timeout: u32, cap: u32) -> Outcome {
    use hbb_common::base64::Engine;
    use std::os::windows::{io::AsRawHandle, process::CommandExt};
    use std::process::{Command, Stdio};
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{CloseHandle, HANDLE},
            System::{
                JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW,
                    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
                    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
                    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                },
                SystemInformation::GetSystemDirectoryW,
            },
        },
    };
    if command.is_empty()
        || command.len() > 16384
        || !(1..=300).contains(&timeout)
        || !(1..=1048576).contains(&cap)
    {
        return failure("management_invalid_request", false);
    }
    // Real process SID, independent of session number, installation, elevation,
    // the client flags and the existence of a running SYSTEM service.
    if !crate::platform::is_process_running_as_system(std::process::id()).unwrap_or(false) {
        return failure("management_system_required", false);
    }
    let mut system_dir = vec![0u16; 32768];
    let size = unsafe { GetSystemDirectoryW(Some(&mut system_dir)) } as usize;
    if size == 0 || size >= system_dir.len() {
        return failure("management_not_ready", true);
    }
    let root = match String::from_utf16(&system_dir[..size]) {
        Ok(v) => std::path::PathBuf::from(v),
        Err(_) => return failure("management_not_ready", true),
    };
    let executable = root
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    struct Job(HANDLE);
    impl Drop for Job {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
    let job = match unsafe { CreateJobObjectW(None, PCWSTR::null()) } {
        Ok(h) => Job(h),
        Err(_) => return failure("management_not_ready", true),
    };
    fn reaped(child: &mut std::process::Child) -> bool {
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Err(_) => return false,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        false
    }
    fn stopped(job: HANDLE, child: &mut std::process::Child) -> bool {
        if unsafe { TerminateJobObject(job, 1) }.is_err() {
            return false;
        }
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            if unsafe {
                QueryInformationJobObject(
                    Some(job),
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&accounting) as u32,
                    None,
                )
            }
            .is_err()
            {
                return false;
            }
            if accounting.ActiveProcesses == 0 {
                return reaped(child);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    }
    .is_err()
    {
        return failure("management_not_ready", true);
    }
    // No command or grant in process arguments. Empty environment prevents
    // inherited user PSModulePath/profile hooks; the executable path is fixed.
    let mut child = match Command::new(&executable)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"])
        .env_clear()
        .env("SystemRoot", root.parent().unwrap_or(&root))
        .env("PATH", &root)
        .current_dir(&root)
        .creation_flags(0x08000000)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(v) => v,
        Err(_) => return failure("management_not_ready", true),
    };
    // Before the first command byte: assignment failure can never run input.
    if unsafe { AssignProcessToJobObject(job.0, HANDLE(child.as_raw_handle())) }.is_err() {
        let _ = child.kill();
        let _ = reaped(&mut child);
        return failure("management_not_ready", true);
    }
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = stopped(job.0, &mut child);
        return failure("management_not_ready", true);
    };
    let used = Arc::new(AtomicUsize::new(0));
    let overflow = Arc::new(AtomicBool::new(false));
    let read_failed = Arc::new(AtomicBool::new(false));
    let (out_tx, out_rx) = mpsc::sync_channel(1);
    let (err_tx, err_rx) = mpsc::sync_channel(1);
    let u = used.clone();
    let o = overflow.clone();
    let f = read_failed.clone();
    std::thread::spawn(move || {
        let _ = out_tx.send(capture(stdout, u, o, f, cap as usize));
    });
    let u = used.clone();
    let o = overflow.clone();
    let f = read_failed.clone();
    std::thread::spawn(move || {
        let _ = err_tx.send(capture(stderr, u, o, f, cap as usize));
    });
    // The finite controller also covers a child refusing to read its stdin.
    // ASCII transport avoids PowerShell's ambient stdin codepage changing the
    // exact UTF-8 command whose hash was authorized. Encoding is memory only.
    let encoded = hbb_common::base64::engine::general_purpose::STANDARD.encode(command.as_bytes());
    let input=format!("[Console]::OutputEncoding=New-Object Text.UTF8Encoding $false;$ErrorActionPreference='Stop';$global:LASTEXITCODE=0;try{{& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))));if(-not $?){{exit 1}};exit $global:LASTEXITCODE}}catch{{exit 1}}\n").into_bytes();
    let (input_tx, input_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut pipe = stdin;
        let result = pipe.write_all(&input).and_then(|_| pipe.write_all(b"\n"));
        let _ = input_tx.send(result.is_ok());
    });
    let deadline = Instant::now() + Duration::from_secs(timeout as u64);
    let mut reason = "";
    let mut exit_code = None;
    loop {
        if overflow.load(Ordering::Acquire) {
            reason = "management_output_limit";
            break;
        }
        if read_failed.load(Ordering::Acquire) {
            reason = "management_output_unconfirmed";
            break;
        }
        if Instant::now() >= deadline {
            reason = "management_timeout_unconfirmed";
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                reason = "management_timeout_unconfirmed";
                break;
            }
        }
    }
    // Terminate descendants even when the root exits successfully. The result
    // describes this one command, never a detached background management shell.
    if !stopped(job.0, &mut child) {
        reason = "management_cleanup_unconfirmed";
        exit_code = None;
    }
    drop(job); // Kill-on-close remains the fallback; never block on Child::wait.
    let stdout = out_rx.recv_timeout(Duration::from_secs(1));
    let stderr = err_rx.recv_timeout(Duration::from_secs(1));
    if reason.is_empty()
        && (input_rx.recv_timeout(Duration::from_secs(1)) != Ok(true)
            || stdout.is_err()
            || stderr.is_err()
            || exit_code.is_none())
    {
        reason = "management_timeout_unconfirmed";
        exit_code = None;
    }
    if overflow.load(Ordering::Acquire) {
        reason = "management_output_limit";
        exit_code = None;
    }
    if read_failed.load(Ordering::Acquire) {
        reason = "management_output_unconfirmed";
        exit_code = None;
    }
    if !reason.is_empty() {
        exit_code = None;
    }
    Outcome {
        reason,
        exit_code,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
        executor_is_system: true,
    }
}
#[cfg(not(windows))]
pub fn execute(_: &str, _: u32, _: u32) -> Outcome {
    failure("management_system_required", false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdout_and_stderr_share_one_budget() {
        let used = Arc::new(AtomicUsize::new(0));
        let overflow = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        assert_eq!(
            capture(
                &b"abcd"[..],
                used.clone(),
                overflow.clone(),
                failed.clone(),
                6
            ),
            b"abcd"
        );
        assert_eq!(
            capture(&b"efgh"[..], used, overflow.clone(), failed, 6),
            b"ef"
        );
        assert!(overflow.load(Ordering::Acquire));
    }
    #[test]
    fn exact_output_limit_does_not_claim_overflow() {
        let used = Arc::new(AtomicUsize::new(0));
        let overflow = Arc::new(AtomicBool::new(false));
        assert_eq!(
            capture(
                &b"abcd"[..],
                used,
                overflow.clone(),
                Arc::new(AtomicBool::new(false)),
                4
            ),
            b"abcd"
        );
        assert!(!overflow.load(Ordering::Acquire));
    }
}

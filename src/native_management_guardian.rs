//! Authenticated, fixed local Guardian endpoint. Never send a grant before
//! validating the real pipe server, SCM identity and protected executable.
use crate::native_management_policy::{Gate, VerifiedGrant};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Approval {
    protocol_version: u32,
    ok: bool,
    management_version: u32,
    authorized: bool,
    authorization_source: String,
    environment: String,
    operation_id: String,
    command_hash: String,
    challenge: String,
    merchant_id: u64,
    kiosk_option_id: u64,
    device_id: String,
    enrollment_id: String,
    address_id: String,
    actor_id: u64,
    expires_at: u64,
}
fn approval(bytes: &[u8], gate: &Gate) -> Result<VerifiedGrant, &'static str> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Denial {
        protocol_version: u32,
        ok: bool,
        reason: String,
    }
    if let Ok(denial) = serde_json::from_slice::<Denial>(bytes) {
        if denial.protocol_version == 1 && !denial.ok {
            return Err(
                crate::native_management_policy::fixed_reason(&denial.reason)
                    .unwrap_or("management_verification_unavailable"),
            );
        }
        return Err("management_protocol_rejected");
    }
    let value: Approval =
        serde_json::from_slice(bytes).map_err(|_| "management_verification_unavailable")?;
    if value.protocol_version != 1
        || !value.ok
        || value.management_version != 1
        || !value.authorized
        || value.authorization_source != "fixed-api-online"
        || value.environment != "development"
        || value.merchant_id == 0
        || value.kiosk_option_id == 0
        || value.device_id.is_empty()
        || value.device_id.len() > 50
        || !crate::native_management_policy::uuid4(&value.enrollment_id)
        || value.actor_id == 0
        || value.operation_id != gate.request().operation_id
        || value.command_hash != gate.request().command_hash
        || value.challenge != gate.nonce()
        || value.address_id != gate.address_id()
    {
        return Err("management_approval_denied");
    }
    Ok(VerifiedGrant {
        environment: value.environment,
        operation_id: value.operation_id,
        command_hash: value.command_hash,
        challenge: value.challenge,
        address_id: value.address_id,
        actor_id: value.actor_id,
        expires_at: value.expires_at,
    })
}
#[cfg(windows)]
mod local {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Component, Path, PathBuf, Prefix},
        time::{Duration, Instant},
    };
    use windows::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL},
            Security::{
                Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT},
                GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            },
            Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION},
            System::{
                Com::CoTaskMemFree,
                Pipes::{
                    GetNamedPipeServerProcessId, SetNamedPipeHandleState, PIPE_NOWAIT,
                    PIPE_READMODE_MESSAGE,
                },
                Threading::{
                    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                },
            },
            UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT},
        },
    };
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    const UNTRUSTED: &str = "management_identity_untrusted";
    struct Process(HANDLE);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
    struct Identity {
        _process: Process,
        _files: Vec<File>,
    }
    fn handle(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle())
    }
    fn sid(sid: PSID) -> Result<String, &'static str> {
        if sid.0.is_null() {
            return Err(UNTRUSTED);
        }
        let mut p = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid, &mut p) }.map_err(|_| UNTRUSTED)?;
        let s = unsafe { p.to_string() }.map_err(|_| UNTRUSTED);
        let _ = unsafe { LocalFree(Some(HLOCAL(p.0.cast()))) };
        s
    }
    fn trusted(sid: &str) -> bool {
        matches!(
            sid,
            "S-1-5-18"
                | "S-1-5-32-544"
                | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        )
    }
    fn audit(file: &File, leaf: bool) -> Result<(), &'static str> {
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            GetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                Some(&mut sd),
            )
        }
        .ok()
        .map_err(|_| UNTRUSTED)?;
        struct Security(PSECURITY_DESCRIPTOR);
        impl Drop for Security {
            fn drop(&mut self) {
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
            }
        }
        let _security = Security(sd);
        if !trusted(&sid(owner)?) || dacl.is_null() {
            return Err(UNTRUSTED);
        }
        // Ancestor creation rights do not allow replacing this pinned child.
        // Deletion, DAC/owner writes and leaf file creation/writes do.
        let mask = 0x000D0040u32 | if leaf { 0x00000116 } else { 0 };
        for index in 0..unsafe { (*dacl).AceCount } as u32 {
            let mut ace = std::ptr::null_mut();
            unsafe { GetAce(dacl, index, &mut ace) }.map_err(|_| UNTRUSTED)?;
            if ace.is_null() {
                return Err(UNTRUSTED);
            }
            let head = unsafe { &*(ace as *const ACE_HEADER) };
            if head.AceFlags & 0x08 != 0 {
                continue;
            } // INHERIT_ONLY does not grant this object.
            if head.AceType == 0 {
                if (head.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                    return Err(UNTRUSTED);
                }
                let allow = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                if allow.Mask & (mask | 0x50000000) != 0
                    && !trusted(&sid(PSID(
                        (&allow.SidStart as *const u32).cast_mut().cast(),
                    ))?)
                {
                    return Err(UNTRUSTED);
                }
            } else if !matches!(head.AceType, 1 | 2 | 3) {
                return Err(UNTRUSTED);
            }
        }
        Ok(())
    }
    fn open(path: &Path, dir: bool) -> Result<File, &'static str> {
        let f = OpenOptions::new()
            .access_mode(0x20080)
            .share_mode(1)
            .custom_flags(0x00200000 | if dir { 0x02000000 } else { 0 })
            .open(path)
            .map_err(|_| UNTRUSTED)?;
        let m = f.metadata().map_err(|_| UNTRUSTED)?;
        if m.file_attributes() & 0x400 != 0 || m.is_dir() != dir {
            return Err(UNTRUSTED);
        }
        Ok(f)
    }
    fn file_id(file: &File) -> Result<(u32, u32, u32), &'static str> {
        let mut i = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle(file), &mut i) }.map_err(|_| UNTRUSTED)?;
        Ok((i.dwVolumeSerialNumber, i.nFileIndexHigh, i.nFileIndexLow))
    }
    fn fixed_path() -> Result<PathBuf, &'static str> {
        let p = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }
            .map_err(|_| UNTRUSTED)?;
        let s = unsafe { p.to_string() }.map_err(|_| UNTRUSTED);
        unsafe { CoTaskMemFree(Some(p.0.cast())) };
        Ok(PathBuf::from(s?)
            .join("Samlab")
            .join("Guardian")
            .join("samlab-guardian.exe"))
    }
    pub(crate) struct FixedKiosk {
        pub wrapper: PathBuf,
        pub executable: PathBuf,
        _files: Vec<File>,
    }
    pub(crate) fn pin_kiosk(expected_hash: &str) -> Result<FixedKiosk, &'static str> {
        use sha2::{Digest, Sha256};
        let value = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }.map_err(|_|UNTRUSTED)?;
        let folder = unsafe { value.to_string() }.map_err(|_|UNTRUSTED);
        unsafe { CoTaskMemFree(Some(value.0.cast())); }
        let root = PathBuf::from(folder?).join("LET ME UP - Study Cafe V2");
        let wrapper = root.join("resources").join("kiosk-control.ps1");
        let executable = root.join("LET ME UP - Study Cafe V2.exe");
        let mut files = Vec::new();
        let mut path = PathBuf::new();
        for component in wrapper.parent().ok_or(UNTRUSTED)?.components() {
            path.push(component);
            if matches!(component,Component::Prefix(_)){continue;}
            let file=open(&path,true)?;
            audit(&file,path==root || path==root.join("resources"))?;
            files.push(file);
        }
        let app=open(&executable,false)?;audit(&app,true)?;files.push(app);
        let mut script=OpenOptions::new().read(true).access_mode(0x80020000).share_mode(1).custom_flags(0x00200000).open(&wrapper).map_err(|_|UNTRUSTED)?;
        let md=script.metadata().map_err(|_|UNTRUSTED)?;
        if !md.is_file() || md.file_attributes()&0x400!=0 || md.len()>65536{return Err(UNTRUSTED);}
        audit(&script,true)?;
        let mut information=BY_HANDLE_FILE_INFORMATION::default();
        unsafe{GetFileInformationByHandle(handle(&script),&mut information)}.map_err(|_|UNTRUSTED)?;
        if information.nNumberOfLinks!=1{return Err(UNTRUSTED);}
        let mut bytes=Vec::new();Read::by_ref(&mut script).take(65537).read_to_end(&mut bytes).map_err(|_|UNTRUSTED)?;
        if bytes.len()>65536 || hex::encode(Sha256::digest(&bytes))!=expected_hash{return Err("kiosk_control_wrapper_mismatch");}
        files.push(script);
        Ok(FixedKiosk{wrapper,executable,_files:files})
    }
    fn lexical(a: &Path, b: &Path) -> bool {
        let valid = |p: &Path| {
            p.is_absolute()
                && matches!(p.components().next(),Some(Component::Prefix(x)) if matches!(x.kind(),Prefix::Disk(_)))
                && !p
                    .to_string_lossy()
                    .split(['\\', '/'])
                    .any(|x| matches!(x, "." | ".."))
        };
        valid(a)
            && valid(b)
            && a.components().count() == b.components().count()
            && a.components().zip(b.components()).all(|(x, y)| {
                x.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&y.as_os_str().to_string_lossy())
            })
    }
    fn verify(file: &File) -> Result<Identity, &'static str> {
        let mut pid = 0;
        unsafe { GetNamedPipeServerProcessId(handle(file), &mut pid) }.map_err(|_| UNTRUSTED)?;
        let scm = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| UNTRUSTED)?;
        let svc = scm
            .open_service(
                "SamlabGuardian",
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            )
            .map_err(|_| UNTRUSTED)?;
        let status = svc.query_status().map_err(|_| UNTRUSTED)?;
        let config = svc.query_config().map_err(|_| UNTRUSTED)?;
        if status.current_state != ServiceState::Running
            || status.process_id != Some(pid)
            || !config.account_name.as_ref().is_some_and(|x| {
                x.to_string_lossy().eq_ignore_ascii_case("LocalSystem")
                    || x.to_string_lossy()
                        .eq_ignore_ascii_case("NT AUTHORITY\\SYSTEM")
            })
            || !crate::platform::is_process_running_as_system(pid).unwrap_or(false)
        {
            return Err(UNTRUSTED);
        }
        let expected = fixed_path()?;
        let cmd = config.executable_path.to_str().ok_or(UNTRUSTED)?;
        let service_path = cmd
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix("\" service"))
            .ok_or(UNTRUSTED)?;
        if !lexical(Path::new(service_path), &expected) {
            return Err(UNTRUSTED);
        }
        let process = Process(
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
                .map_err(|_| UNTRUSTED)?,
        );
        // The retained handle prevents PID reuse during the second token check.
        if !crate::platform::is_process_running_as_system(pid).unwrap_or(false) {
            return Err(UNTRUSTED);
        }
        let mut image = vec![0u16; 32768];
        let mut n = image.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                process.0,
                PROCESS_NAME_WIN32,
                PWSTR(image.as_mut_ptr()),
                &mut n,
            )
        }
        .map_err(|_| UNTRUSTED)?;
        let image = PathBuf::from(String::from_utf16(&image[..n as usize]).map_err(|_| UNTRUSTED)?);
        if !lexical(&image, &expected) {
            return Err(UNTRUSTED);
        }
        let mut files = Vec::new();
        let mut path = PathBuf::new();
        for c in expected.parent().ok_or(UNTRUSTED)?.components() {
            path.push(c);
            if matches!(c, Component::Prefix(_)) {
                continue;
            }
            let f = open(&path, true)?;
            audit(&f, path == expected.parent().ok_or(UNTRUSTED)?)?;
            files.push(f);
        }
        let actual = open(&image, false)?;
        let pinned = open(&expected, false)?;
        audit(&pinned, true)?;
        if file_id(&actual)? != file_id(&pinned)? {
            return Err(UNTRUSTED);
        }
        files.push(actual);
        files.push(pinned);
        let after = svc.query_status().map_err(|_| UNTRUSTED)?;
        let mut after_pid = 0;
        unsafe { GetNamedPipeServerProcessId(handle(file), &mut after_pid) }
            .map_err(|_| UNTRUSTED)?;
        if after.process_id != Some(pid)
            || after_pid != pid
            || after.current_state != ServiceState::Running
        {
            return Err(UNTRUSTED);
        }
        Ok(Identity {
            _process: process,
            _files: files,
        })
    }
    pub(super) fn reenrollment(frame: Vec<u8>, expected_hash: &str, execute: bool) -> Result<Vec<u8>, &'static str> {
        struct Sensitive(Vec<u8>);
        impl Drop for Sensitive {fn drop(&mut self){self.0.fill(0)}}
        impl std::ops::Deref for Sensitive {type Target=Vec<u8>;fn deref(&self)->&Vec<u8>{&self.0}}
        impl std::ops::DerefMut for Sensitive {fn deref_mut(&mut self)->&mut Vec<u8>{&mut self.0}}
        let mut frame=Sensitive(frame);
        use sha2::{Digest, Sha256};
        use std::io::{Seek, SeekFrom};
        if !crate::reenrollment_policy::hash(expected_hash) || frame.is_empty() || frame.len() >= crate::reenrollment_policy::MAX_FRAME {
            frame.fill(0); return Err("reenrollment_protocol_rejected");
        }
        let mut pipe = OpenOptions::new().read(true).write(true).access_mode(0x0012019b)
            .open(r"\\.\pipe\samlab-guardian-native-remote-v1").map_err(|_| "reenrollment_capability_required")?;
        let mut identity = verify(&pipe).map_err(|_| "reenrollment_capability_required")?;
        let pinned = identity._files.last_mut().ok_or("reenrollment_capability_required")?;
        let size = pinned.metadata().map_err(|_| "reenrollment_capability_required")?.len();
        if size == 0 || size > 16777216 { frame.fill(0); return Err("reenrollment_capability_required"); }
        let mut bytes = Vec::new();
        pinned.read_to_end(&mut bytes).map_err(|_| "reenrollment_capability_required")?;
        if bytes.len() as u64 != size || hex::encode(Sha256::digest(&bytes)) != expected_hash { frame.fill(0); return Err("reenrollment_capability_required"); }
        pinned.seek(SeekFrom::Start(0)).map_err(|_| "reenrollment_capability_required")?;
        let mode = PIPE_NOWAIT | PIPE_READMODE_MESSAGE;
        unsafe { SetNamedPipeHandleState(handle(&pipe), Some(&mode), None, None) }.map_err(|_| "reenrollment_capability_required")?;
        frame.push(b'\n'); let written=pipe.write_all(&frame); frame.fill(0);
        written.map_err(|_| "reenrollment_execution_unconfirmed")?;
        let deadline=Instant::now()+Duration::from_secs(if execute {crate::reenrollment_policy::EXECUTE_SECONDS}else{20});
        let mut response=Vec::new(); let mut chunk=[0u8;16385];
        while Instant::now()<deadline {
            match pipe.read(&mut chunk) {
                Ok(0)=>break,
                Ok(n)=>{response.extend_from_slice(&chunk[..n]);if response.len()>16384{return Err("reenrollment_protocol_rejected")}
                    if let Some(end)=response.iter().position(|b|*b==b'\n') {
                        if end+1!=response.len(){return Err("reenrollment_protocol_rejected")}
                        let _again=verify(&pipe).map_err(|_| "reenrollment_execution_unconfirmed")?;
                        pipe.write_all(b"\n").map_err(|_| "reenrollment_execution_unconfirmed")?;return Ok(response)
                    }
                },
                Err(e) if matches!(e.raw_os_error(),Some(232|536))=>std::thread::sleep(Duration::from_millis(10)),
                Err(_)=>break,
            }
        }
        Err("reenrollment_execution_unconfirmed")
    }
    pub(super) fn request(gate: &Gate, token: &str) -> Result<VerifiedGrant, &'static str> {
        if token.is_empty() || token.len() > 8192 {
            return Err("management_invalid_request");
        }
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(0x0012019b)
            .open(r"\\.\pipe\samlab-guardian-native-remote-v1")
            .map_err(|_| "management_not_ready")?;
        let _identity = verify(&pipe)?;
        let mode = PIPE_NOWAIT | PIPE_READMODE_MESSAGE;
        unsafe { SetNamedPipeHandleState(handle(&pipe), Some(&mode), None, None) }
            .map_err(|_| "management_verification_unavailable")?;
        let mut frame=serde_json::to_vec(&serde_json::json!({"protocolVersion":1,"operation":"verify-management","environment":"development",
            "operationId":gate.request().operation_id,"commandHash":gate.request().command_hash,"challenge":gate.nonce(),"addressId":gate.address_id(),"grantToken":token}))
            .map_err(|_|"management_invalid_request")?;
        frame.push(b'\n');
        if frame.len() > 16384 {
            return Err("management_invalid_request");
        }
        let written = pipe.write_all(&frame);
        frame.fill(0);
        written.map_err(|_| "management_verification_unavailable")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut response = Vec::new();
        let mut chunk = [0u8; 16385];
        while Instant::now() < deadline {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&chunk[..n]);
                    if response.len() > 16384 {
                        return Err("management_protocol_rejected");
                    }
                    if let Some(end) = response.iter().position(|b| *b == b'\n') {
                        if end + 1 != response.len() {
                            return Err("management_protocol_rejected");
                        }
                        let grant = approval(&response, gate)?;
                        let _again = verify(&pipe)?;
                        pipe.write_all(b"\n")
                            .map_err(|_| "management_verification_unavailable")?;
                        return Ok(grant);
                    }
                }
                Err(e) if matches!(e.raw_os_error(), Some(232 | 536)) => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
        Err("management_verification_unavailable")
    }
}

#[cfg(windows)]
pub(crate) use local::{pin_kiosk, FixedKiosk};
pub(crate) fn reenrollment_request(frame: Vec<u8>, expected_hash: &str, execute: bool) -> Result<Vec<u8>, &'static str> {
    #[cfg(windows)] { local::reenrollment(frame, expected_hash, execute) }
    #[cfg(not(windows))] { let _=(frame,expected_hash,execute);Err("reenrollment_system_required") }
}
pub fn verify(gate: &Gate, token: &str) -> Result<VerifiedGrant, &'static str> {
    #[cfg(windows)]
    {
        local::request(gate, token)
    }
    #[cfg(not(windows))]
    {
        let _ = (gate, token);
        Err("management_system_required")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn gate() -> Gate {
        Gate::new(
            crate::native_management_policy::Request {
                version: 1,
                operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                command_hash: "a".repeat(64),
                timeout_seconds: 60,
                output_limit_bytes: 1024,
            },
            "A".repeat(43),
            "74067020".into(),
            true,
        )
        .unwrap()
    }
    fn response() -> serde_json::Value {
        serde_json::json!({"protocolVersion":1,"ok":true,"managementVersion":1,"authorized":true,"authorizationSource":"fixed-api-online","environment":"development","operationId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","commandHash":"a".repeat(64),"challenge":"A".repeat(43),"merchantId":1,"kioskOptionId":2,"deviceId":"fixture-device","enrollmentId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","addressId":"74067020","actorId":7,"expiresAt":1060})
    }
    #[test]
    fn exact_fixed_api_approval_is_required() {
        assert!(approval(&serde_json::to_vec(&response()).unwrap(), &gate()).is_ok());
    }
    #[test]
    fn changed_response_binding_and_untrusted_authority_are_rejected() {
        for (field, value) in [
            ("protocolVersion", serde_json::json!(2)),
            ("ok", serde_json::json!(false)),
            ("managementVersion", serde_json::json!(2)),
            ("authorized", serde_json::json!(false)),
            ("authorizationSource", serde_json::json!("local-cache")),
            ("environment", serde_json::json!("production")),
            (
                "operationId",
                serde_json::json!("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            ),
            ("commandHash", serde_json::json!("b".repeat(64))),
            ("challenge", serde_json::json!("E".repeat(43))),
            ("addressId", serde_json::json!("11111111")),
            ("actorId", serde_json::json!(0)),
            ("merchantId", serde_json::json!(0)),
            ("kioskOptionId", serde_json::json!(0)),
            ("deviceId", serde_json::json!("")),
            ("enrollmentId", serde_json::json!("invalid")),
            ("grantToken", serde_json::json!("fixture-private")),
        ] {
            let mut v = response();
            v[field] = value;
            assert!(
                approval(&serde_json::to_vec(&v).unwrap(), &gate()).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn incomplete_or_duplicate_json_fields_cannot_be_success() {
        assert!(approval(
            br#"{"protocolVersion":1,"ok":false,"reason":"management_replayed"}"#,
            &gate()
        )
        .is_err());
        let mut bytes = serde_json::to_vec(&response()).unwrap();
        bytes.pop();
        bytes.extend_from_slice(br#", "ok":true}"#);
        assert!(approval(&bytes, &gate()).is_err());
    }
}

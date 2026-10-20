//! Administrative installation command. Secrets are accepted only on redirected stdin.
#[path = "installer_password_policy.rs"]
mod policy;
use hbb_common::{config::Config, tokio};
use serde::{Deserialize, Serialize};
pub const IPC_NAME: &str = "installer-permanent-password";
pub const VERIFY_IPC_NAME: &str = "installer-verify-permanent-password";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    id: String,
    daemon_accepted: bool,
    permanent_password_set: bool,
    persisted: bool,
    matches: bool,
    conflict: bool,
    server_verified: bool,
}
fn status_failure() -> Status {
    Status {
        id: String::new(),
        daemon_accepted: false,
        permanent_password_set: false,
        persisted: false,
        matches: false,
        conflict: false,
        server_verified: false,
    }
}
// Existing main-IPC executable authorization is retained; this operation additionally
// requires an elevated peer and must run inside the installed SYSTEM service.
pub(crate) fn apply_in_service(password: &str, administrator: bool, verify_only: bool) -> Status {
    if !administrator
        || !crate::platform::is_root()
        || crate::core_main::is_cli_setting_change_disabled()
        || Config::is_disable_change_permanent_password()
        || policy::validate_secret(password.as_bytes()).is_err()
    {
        return status_failure();
    }
    if !company_server_verified() {
        return status_failure();
    }
    let update = if verify_only {
        None
    } else {
        Some(Config::set_permanent_password_if_blank_or_same(password))
    };
    let conflict = update == Some(hbb_common::config::PermanentPasswordUpdate::Conflict);
    let accepted =
        verify_only || update == Some(hbb_common::config::PermanentPasswordUpdate::Accepted);
    let matches = Config::permanent_password_matches(password);
    let permanent_set =
        Config::has_permanent_password() && hbb_common::password_security::permanent_enabled();
    let persisted = accepted && matches && verify_service_disk_password(password);
    Status {
        // get_id() may generate and persist a missing ID; verification must not.
        id: Config::get_id_or(String::new()),
        daemon_accepted: accepted,
        permanent_password_set: permanent_set,
        persisted,
        matches,
        conflict,
        server_verified: company_server_verified(),
    }
}
pub(crate) fn company_server_verified() -> bool {
    // Match the service mediator's get_rendezvous_servers()/get_key(true) inputs,
    // including executable-name and persisted overrides. Never change them here.
    let executable_key = crate::platform::windows::get_license_from_exe_name()
        .ok()
        .map(|license| license.key)
        .filter(|key| !key.is_empty());
    let key = executable_key.unwrap_or_else(|| {
        let configured = Config::get_option("key");
        if configured.is_empty() {
            hbb_common::config::RS_PUB_KEY.to_owned()
        } else {
            configured
        }
    });
    policy::company_server_matches(
        &Config::get_rendezvous_servers(),
        &Config::get_rendezvous_server(),
        &key,
        hbb_common::config::RS_PUB_KEY,
    )
}
fn verify_service_disk_password(password: &str) -> bool {
    // The existing setter logs storage errors rather than returning them. Its ACK
    // is insufficient: read the actual configuration file as this SYSTEM service.
    let result = (|| -> Option<bool> {
        let (memory_storage, memory_salt) = Config::get_local_permanent_password_storage_and_salt();
        if memory_storage.is_empty() || memory_salt.is_empty() {
            return Some(false);
        }
        let text = policy::read_config(&Config::file()).ok()?;
        let disk: hbb_common::toml::Value = text.parse().ok()?;
        let storage = disk.get("password")?.as_str()?;
        let salt = disk.get("salt")?.as_str()?;
        let expected = hbb_common::config::compute_permanent_password_h1(password, salt);
        Some(
            storage == memory_storage
                && salt == memory_salt
                && hbb_common::config::decode_permanent_password_h1_from_storage(storage)
                    == Some(expected),
        )
    })();
    result == Some(true)
}
fn read_secret() -> Result<String, &'static str> {
    use std::io::{IsTerminal, Read};
    if std::io::stdin().is_terminal() {
        return Err("redirected_stdin_required");
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = std::io::stdin()
            .take((policy::MAX_SECRET_BYTES + 3) as u64)
            .read_to_end(&mut bytes);
        let result = if read.is_ok() {
            policy::parse_secret(&bytes)
        } else {
            Err("input_read_failed")
        };
        bytes.fill(0);
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|_| "input_timeout")?
}
#[tokio::main(flavor = "current_thread")]
async fn request_password(password: &str, verify_only: bool) -> policy::Outcome {
    let ipc_name = if verify_only {
        VERIFY_IPC_NAME
    } else {
        IPC_NAME
    };
    let result = async {
        let mut connection = crate::ipc::connect(1000, "").await.ok()?;
        connection
            .send(&crate::ipc::Data::Config((
                ipc_name.to_owned(),
                Some(password.to_owned()),
            )))
            .await
            .ok()?;
        match connection.next_timeout(3000).await.ok()? {
            Some(crate::ipc::Data::Config((name, Some(value)))) if name == ipc_name => {
                serde_json::from_str::<Status>(&value).ok()
            }
            _ => None,
        }
    }
    .await;
    match result {
        Some(status) => policy::confirmed_outcome(
            status.id,
            status.daemon_accepted,
            status.permanent_password_set,
            status.persisted,
            status.matches,
            status.conflict,
            status.server_verified,
        ),
        None => policy::Outcome::failure("daemon_response_unconfirmed"),
    }
}
pub fn run(args: &[String]) -> i32 {
    hbb_common::log::set_max_level(hbb_common::log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
    let verify_only = args.first().map(String::as_str) == Some("--verify-permanent-password-stdin");
    let outcome = if args.len() != 1 {
        policy::Outcome::failure("invalid_arguments")
    } else {
        policy::configure(
            policy::Eligibility {
                installed: crate::platform::is_installed(),
                administrator: crate::platform::is_elevated(None).unwrap_or(false)
                    || crate::platform::is_root(),
                settings_allowed: !crate::core_main::is_cli_setting_change_disabled()
                    && !Config::is_disable_change_permanent_password(),
            },
            read_secret,
            |password| request_password(password, verify_only),
        )
    };
    println!(
        "{}",
        serde_json::json!({"id":outcome.id,"daemonAccepted":outcome.daemon_accepted,"matches":outcome.matches,"serverVerified":outcome.server_verified,
        "permanentPasswordSet":outcome.permanent_password_set,"persisted":outcome.persisted,"reason":outcome.reason})
    );
    outcome.exit_code()
}

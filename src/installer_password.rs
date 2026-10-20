//! Administrative installation command. Secrets are accepted only on redirected stdin.
#[path = "installer_password_policy.rs"]
mod policy;
use hbb_common::config::Config;
use serde::{Deserialize, Serialize};
pub const IPC_NAME: &str = "installer-permanent-password";
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Status {
    id: String,
    daemon_accepted: bool,
    permanent_password_set: bool,
    persisted: bool,
}
fn status_failure() -> Status {
    Status {
        id: String::new(),
        daemon_accepted: false,
        permanent_password_set: false,
        persisted: false,
    }
}
// Existing main-IPC executable authorization is retained; this operation additionally
// requires an elevated peer and must run inside the installed SYSTEM service.
pub(crate) fn apply_in_service(password: &str, administrator: bool) -> Status {
    if !administrator
        || !crate::platform::is_root()
        || crate::core_main::is_cli_setting_change_disabled()
        || Config::is_disable_change_permanent_password()
        || policy::validate_secret(password.as_bytes()).is_err()
    {
        return status_failure();
    }
    let accepted = Config::set_permanent_password(password);
    let permanent_set = accepted
        && Config::has_permanent_password()
        && hbb_common::password_security::permanent_enabled();
    let persisted = accepted && verify_service_disk_password(password);
    Status {
        id: Config::get_id(),
        daemon_accepted: accepted,
        permanent_password_set: permanent_set,
        persisted,
    }
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
async fn set_password(password: &str) -> policy::Outcome {
    let result = async {
        let mut connection = crate::ipc::connect(1000, "").await.ok()?;
        connection
            .send_config(IPC_NAME, password.to_owned())
            .await
            .ok()?;
        match connection.next_timeout(3000).await.ok()? {
            Some(crate::ipc::Data::Config((name, Some(value)))) if name == IPC_NAME => {
                serde_json::from_str::<Status>(&value).ok()
            }
            _ => None,
        }
    }
    .await;
    match result {
        Some(status) => {
            let reason = if !status.daemon_accepted {
                "daemon_rejected"
            } else if !policy::valid_id(&status.id) {
                "device_id_unconfirmed"
            } else if !status.permanent_password_set {
                "password_state_unconfirmed"
            } else if !status.persisted {
                "persistence_unconfirmed"
            } else {
                "configured"
            };
            policy::Outcome {
                id: if policy::valid_id(&status.id) {
                    status.id
                } else {
                    String::new()
                },
                daemon_accepted: status.daemon_accepted,
                permanent_password_set: status.permanent_password_set,
                persisted: status.persisted,
                reason,
            }
        }
        None => policy::Outcome::failure("daemon_response_unconfirmed"),
    }
}
pub fn run(args: &[String]) -> i32 {
    hbb_common::log::set_max_level(hbb_common::log::LevelFilter::Off);
    std::panic::set_hook(Box::new(|_| {}));
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
            set_password,
        )
    };
    println!(
        "{}",
        serde_json::json!({"id":outcome.id,"daemonAccepted":outcome.daemon_accepted,
        "permanentPasswordSet":outcome.permanent_password_set,"persisted":outcome.persisted,"reason":outcome.reason})
    );
    outcome.exit_code()
}

//! Installer policy, independent of GUI, IPC and live configuration.
pub const MAX_SECRET_BYTES: usize = 256;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub fn company_server_matches(
    servers: &[String],
    active: &str,
    key: &str,
    expected_key: &str,
) -> bool {
    fn valid_host(host: &str) -> bool {
        host.eq_ignore_ascii_case("r.letmeup.shop")
            || host.eq_ignore_ascii_case("r.letmeup.shop:21116")
    }
    servers.len() == 1
        && valid_host(&servers[0])
        && valid_host(active)
        && !expected_key.is_empty()
        && key == expected_key
}
pub fn read_config(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)?
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_string(&mut text)?;
    if text.len() > MAX_CONFIG_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "configuration_too_large",
        ));
    }
    Ok(text)
}
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|c| c.is_ascii_alphanumeric())
}
pub struct Eligibility {
    pub installed: bool,
    pub administrator: bool,
    pub settings_allowed: bool,
}
pub struct Outcome {
    pub id: String,
    pub daemon_accepted: bool,
    pub permanent_password_set: bool,
    pub persisted: bool,
    pub matches: bool,
    pub server_verified: bool,
    pub reason: &'static str,
}
pub fn confirmed_outcome(
    id: String,
    accepted: bool,
    enabled: bool,
    persisted: bool,
    matches: bool,
    conflict: bool,
    server_verified: bool,
) -> Outcome {
    let reason = if !server_verified {
        "server_unverified"
    } else if conflict {
        "existing_password_conflict"
    } else if !accepted {
        "daemon_rejected"
    } else if !valid_id(&id) {
        "device_id_unconfirmed"
    } else if !matches {
        "password_mismatch"
    } else if !enabled {
        "password_state_unconfirmed"
    } else if !persisted {
        "persistence_unconfirmed"
    } else {
        "configured"
    };
    Outcome {
        id: if valid_id(&id) { id } else { String::new() },
        daemon_accepted: accepted,
        permanent_password_set: enabled,
        persisted,
        matches,
        server_verified,
        reason,
    }
}
impl Outcome {
    pub fn failure(reason: &'static str) -> Self {
        Self {
            id: String::new(),
            daemon_accepted: false,
            permanent_password_set: false,
            persisted: false,
            matches: false,
            server_verified: false,
            reason,
        }
    }
    pub fn exit_code(&self) -> i32 {
        if self.daemon_accepted
            && self.permanent_password_set
            && self.persisted
            && self.matches
            && self.server_verified
            && valid_id(&self.id)
            && self.reason == "configured"
        {
            0
        } else {
            1
        }
    }
}
pub fn validate_secret(bytes: &[u8]) -> Result<&str, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_input")?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    // Empty input must never clear an existing password. Installers supply a generated secret.
    if !(8..=MAX_SECRET_BYTES).contains(&text.len()) || text.chars().any(char::is_control) {
        return Err("invalid_input");
    }
    Ok(text)
}
pub fn parse_secret(bytes: &[u8]) -> Result<String, &'static str> {
    validate_secret(bytes).map(str::to_owned)
}
pub fn configure<R, S>(eligibility: Eligibility, read: R, set: S) -> Outcome
where
    R: FnOnce() -> Result<String, &'static str>,
    S: FnOnce(&str) -> Outcome,
{
    if !eligibility.installed {
        return Outcome::failure("installation_required");
    }
    if !eligibility.administrator {
        return Outcome::failure("administrator_required");
    }
    if !eligibility.settings_allowed {
        return Outcome::failure("settings_disabled");
    }
    let password = match read() {
        Ok(value) => value,
        Err(reason) => return Outcome::failure(reason),
    };
    let outcome = set(&password);
    let mut bytes = password.into_bytes();
    bytes.fill(0);
    outcome
}
#[cfg(test)]
mod tests {
    use super::*;
    fn allowed() -> Eligibility {
        Eligibility {
            installed: true,
            administrator: true,
            settings_allowed: true,
        }
    }
    #[test]
    fn company_host_and_key_must_match_including_effective_overrides() {
        let servers = vec!["r.letmeup.shop".to_owned()];
        assert!(company_server_matches(
            &servers,
            "r.letmeup.shop:21116",
            "fixture-key",
            "fixture-key"
        ));
        for host in [
            "other.example",
            "r.letmeup.shop.example",
            "r.letmeup.shop:21117",
        ] {
            assert!(!company_server_matches(
                &servers,
                host,
                "fixture-key",
                "fixture-key"
            ));
            assert!(!company_server_matches(
                &[host.to_owned()],
                "r.letmeup.shop:21116",
                "fixture-key",
                "fixture-key"
            ));
        }
        assert!(!company_server_matches(
            &servers,
            "r.letmeup.shop:21116",
            "other-key",
            "fixture-key"
        ));
        assert!(!company_server_matches(
            &[],
            "r.letmeup.shop:21116",
            "fixture-key",
            "fixture-key"
        ));
    }
    #[test]
    fn unverified_server_blocks_even_otherwise_complete_result() {
        let outcome = confirmed_outcome("123456789".into(), true, true, true, true, false, false);
        assert_eq!(outcome.reason, "server_unverified");
        assert_ne!(outcome.exit_code(), 0);
    }
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir();
            for attempt in 0..100 {
                let path = base.join(format!(
                    "installer-password-policy-{}-{}-{attempt}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                if std::fs::create_dir(&path).is_ok() {
                    return Self(path);
                }
            }
            panic!("cannot create isolated fixture");
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0.join("config"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    #[test]
    fn actual_disk_reader_reports_missing_invalid_and_oversized_files() {
        let fixture = Fixture::new();
        let path = fixture.0.join("config");
        assert!(read_config(&path).is_err());
        std::fs::write(&path, [255]).unwrap();
        assert!(read_config(&path).is_err());
        std::fs::write(&path, vec![b'x'; MAX_CONFIG_BYTES + 1]).unwrap();
        assert!(read_config(&path).is_err());
    }
    #[test]
    fn actual_disk_reader_returns_the_file_contents_without_profile_access() {
        let fixture = Fixture::new();
        let path = fixture.0.join("config");
        std::fs::write(&path, "fixture-data").unwrap();
        assert_eq!(read_config(&path).unwrap(), "fixture-data");
    }
    #[test]
    fn rejects_empty_short_oversized_multiline_controls_and_invalid_utf8() {
        for bytes in [
            b"".to_vec(),
            b"short".to_vec(),
            vec![b'x'; 257],
            b"abcdefgh\nsecond".to_vec(),
            b"abcd\0efgh".to_vec(),
            vec![255; 8],
        ] {
            assert!(parse_secret(&bytes).is_err());
        }
    }
    #[test]
    fn accepts_one_line_with_exact_spaces_and_optional_line_ending() {
        assert!(parse_secret(b" abcdefgh \r\n")
            .map(|s| s == " abcdefgh ")
            .unwrap_or(false));
        assert!(parse_secret(b"abcdefgh").is_ok());
    }
    #[test]
    fn permission_rejection_neither_reads_secret_nor_calls_daemon() {
        for eligibility in [
            Eligibility {
                installed: false,
                ..allowed()
            },
            Eligibility {
                administrator: false,
                ..allowed()
            },
            Eligibility {
                settings_allowed: false,
                ..allowed()
            },
        ] {
            let outcome = configure(
                eligibility,
                || panic!("must not read"),
                |_| panic!("must not write"),
            );
            assert_ne!(outcome.exit_code(), 0);
            assert!(!outcome.daemon_accepted);
        }
    }
    #[test]
    fn invalid_input_never_reaches_daemon() {
        let result = configure(
            allowed(),
            || Err("invalid_input"),
            |_| panic!("must not write"),
        );
        assert_eq!(result.reason, "invalid_input");
    }
    #[test]
    fn input_timeout_is_preserved_without_a_write() {
        let result = configure(
            allowed(),
            || Err("input_timeout"),
            |_| panic!("must not write"),
        );
        assert_eq!(result.reason, "input_timeout");
        assert_ne!(result.exit_code(), 0);
    }
    #[test]
    fn daemon_rejection_is_not_success() {
        let result = configure(
            allowed(),
            || parse_secret(b"test-input-value"),
            |_| Outcome::failure("daemon_rejected"),
        );
        assert_ne!(result.exit_code(), 0);
    }
    #[test]
    fn readonly_mismatch_is_distinct_from_mutation_rejection() {
        let outcome = confirmed_outcome("123456789".into(), true, true, false, false, false, true);
        assert!(outcome.daemon_accepted);
        assert_eq!(outcome.reason, "password_mismatch");
        assert_ne!(outcome.exit_code(), 0);
    }
    #[test]
    fn existing_password_conflict_never_reports_installation_success() {
        let outcome = confirmed_outcome("123456789".into(), false, true, false, false, true, true);
        assert_eq!(outcome.reason, "existing_password_conflict");
        assert_ne!(outcome.exit_code(), 0);
    }
    #[test]
    fn accepted_memory_state_without_disk_evidence_is_not_success() {
        let result = Outcome {
            id: "123456789".into(),
            daemon_accepted: true,
            permanent_password_set: true,
            persisted: false,
            matches: true,
            server_verified: true,
            reason: "persistence_unconfirmed",
        };
        assert_ne!(result.exit_code(), 0);
    }
    #[test]
    fn every_confirmation_and_valid_id_is_required_for_success() {
        let mut result = Outcome {
            id: "123456789".into(),
            daemon_accepted: true,
            permanent_password_set: true,
            persisted: true,
            matches: true,
            server_verified: true,
            reason: "configured",
        };
        assert_eq!(result.exit_code(), 0);
        result.permanent_password_set = false;
        assert_ne!(result.exit_code(), 0);
        result.permanent_password_set = true;
        result.id = "bad\nvalue".into();
        assert_ne!(result.exit_code(), 0);
    }
}

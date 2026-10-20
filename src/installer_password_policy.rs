//! Installer policy, independent of GUI, IPC and live configuration.
pub const MAX_SECRET_BYTES: usize = 256;
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
    pub reason: &'static str,
}
impl Outcome {
    pub fn failure(reason: &'static str) -> Self {
        Self {
            id: String::new(),
            daemon_accepted: false,
            permanent_password_set: false,
            persisted: false,
            reason,
        }
    }
    pub fn exit_code(&self) -> i32 {
        if self.daemon_accepted
            && self.permanent_password_set
            && self.persisted
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
    fn accepted_memory_state_without_disk_evidence_is_not_success() {
        let result = Outcome {
            id: "123456789".into(),
            daemon_accepted: true,
            permanent_password_set: true,
            persisted: false,
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

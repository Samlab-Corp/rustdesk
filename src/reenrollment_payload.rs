//! Strict public wire contracts. Unknown fields, including credentials, are rejected.
use crate::reenrollment_policy as p;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub reenrollment_version: u8,
    pub environment: String,
    pub operation_id: String,
    pub merchant_id: u64,
    pub kiosk_option_id: u64,
    pub expected_revision: u64,
    pub device_id: String,
    pub location: String,
    pub number: u8,
    pub old_enrollment_id: String,
    pub new_enrollment_id: String,
    pub address_id: String,
}
impl Scope {
    pub fn valid(&self) -> bool {
        self.reenrollment_version == 1
            && self.environment == "development"
            && p::uuid4(&self.operation_id)
            && [
                self.merchant_id,
                self.kiosk_option_id,
                self.expected_revision,
            ]
            .iter()
            .all(|v| (1..=2147483647).contains(v))
            && p::device(&self.device_id)
            && matches!(self.location.as_str(), "outer" | "inner")
            && (1..=99).contains(&self.number)
            && p::uuid4(&self.old_enrollment_id)
            && p::uuid4(&self.new_enrollment_id)
            && self.old_enrollment_id != self.new_enrollment_id
            && p::address(&self.address_id)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err("reenrollment_protocol_rejected");
        }
        let s: Self =
            serde_json::from_slice(bytes).map_err(|_| "reenrollment_protocol_rejected")?;
        if !s.valid() {
            return Err("reenrollment_protocol_rejected");
        }
        Ok(s)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capability {
    pub protocol_version: u8,
    pub ok: bool,
    pub purpose: String,
    pub reenrollment_version: u8,
    pub scope: Scope,
    pub action: String,
    pub command_hash: String,
    pub system: bool,
    pub read_only: bool,
    pub requires_online_authorization: bool,
}
pub fn capability(bytes: &[u8], scope: &Scope, action: &str) -> Result<Capability, &'static str> {
    if bytes.is_empty() || bytes.len() > p::MAX_FRAME {
        return Err("reenrollment_protocol_rejected");
    }
    let c: Capability =
        serde_json::from_slice(bytes).map_err(|_| "reenrollment_capability_required")?;
    if c.protocol_version != 1
        || !c.ok
        || c.purpose != p::PURPOSE
        || c.reenrollment_version != 1
        || &c.scope != scope
        || c.action != action
        || Some(c.command_hash.as_str()) != p::action_hash(action)
        || !c.system
        || !c.read_only
        || !c.requires_online_authorization
    {
        return Err("reenrollment_capability_required");
    }
    Ok(c)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    operation_id: String,
    device_id: String,
    address_id: String,
    old_enrollment_id: String,
    new_enrollment_id: String,
    local_phase: String,
    actual_device_identity_checked: bool,
    new_password_matches: bool,
    old_password_matches: bool,
    observed_at: String,
    command_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    protocol_version: u8,
    ok: bool,
    reason: String,
    operation_id: Option<String>,
    phase: Option<String>,
    verified: bool,
    retry_rotation: bool,
    observed: Option<Observation>,
}
pub fn receipt(bytes: &[u8], s: &Scope, action: &str) -> Result<Receipt, &'static str> {
    if bytes.is_empty() || bytes.len() > p::MAX_FRAME {
        return Err("reenrollment_protocol_rejected");
    }
    let mut r: Receipt =
        serde_json::from_slice(bytes).map_err(|_| "reenrollment_execution_unconfirmed")?;
    if r.protocol_version != 1 || r.retry_rotation {
        return Err("reenrollment_protocol_rejected");
    }
    if !r.ok {
        if r.operation_id.is_some() || r.phase.is_some() || r.observed.is_some() || r.verified {
            return Err("reenrollment_protocol_rejected");
        }
        r.reason = "reenrollment_authorization_rejected".into();
        return Ok(r);
    }
    if r.operation_id.as_ref() != Some(&s.operation_id)
        || !matches!(
            r.phase.as_deref(),
            Some(
                "preparing_server"
                    | "prepared"
                    | "authorizing_rotation"
                    | "applying"
                    | "rotated"
                    | "committed"
            )
        )
    {
        return Err("reenrollment_protocol_rejected");
    }
    if let Some(o) = &r.observed {
        let time = chrono::DateTime::parse_from_rfc3339(&o.observed_at)
            .map_err(|_| "reenrollment_protocol_rejected")?
            .timestamp();
        let age = chrono::Utc::now().timestamp() - time;
        if o.operation_id != s.operation_id
            || o.device_id != s.device_id
            || o.address_id != s.address_id
            || o.old_enrollment_id != s.old_enrollment_id
            || o.new_enrollment_id != s.new_enrollment_id
            || !o.actual_device_identity_checked
            || Some(o.command_hash.as_str()) != p::action_hash(action)
            || !matches!(o.local_phase.as_str(), "prepared" | "rotated" | "committed")
            || !(-5..=120).contains(&age)
        {
            return Err("reenrollment_protocol_rejected");
        }
    }
    let valid = match (action, r.reason.as_str(), r.phase.as_deref(), r.verified) {
        ("prepare", "prepared", Some("prepared"), false) => true,
        ("rotate", "rotation_observed_required", Some("rotated"), false) => true,
        ("status", "uncertain", _, false) => true,
        ("status", "active", Some("committed"), true) => r.observed.as_ref().map_or(false, |o| {
            matches!(o.local_phase.as_str(), "rotated" | "committed")
                && o.new_password_matches
                && !o.old_password_matches
        }),
        _ => false,
    };
    if !valid {
        return Err("reenrollment_protocol_rejected");
    }
    Ok(r)
}
#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn scope() -> Scope {
        Scope {
            reenrollment_version: 1,
            environment: "development".into(),
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            merchant_id: 1,
            kiosk_option_id: 2,
            expected_revision: 1,
            device_id: "fixture".into(),
            location: "outer".into(),
            number: 99,
            old_enrollment_id: "22222222-2222-4222-8222-222222222222".into(),
            new_enrollment_id: "33333333-3333-4333-8333-333333333333".into(),
            address_id: "74067020".into(),
        }
    }
    #[test]
    fn strict_scope_rejects_secrets_and_wrong_environment() {
        let s = scope();
        assert!(s.valid());
        let mut v = serde_json::to_value(&s).unwrap();
        v["password"] = "private".into();
        assert!(Scope::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        let mut s = scope();
        s.environment = "production".into();
        assert!(!s.valid());
    }
    #[test]
    fn hashes_match_canonical_actions() {
        use sha2::{Digest, Sha256};
        for a in ["prepare", "rotate", "status"] {
            let text = format!(
                "{{\"action\":\"{a}\",\"protocolVersion\":1,\"purpose\":\"{}\"}}",
                p::PURPOSE
            );
            assert_eq!(
                hex::encode(Sha256::digest(text.as_bytes())),
                p::action_hash(a).unwrap()
            );
        }
    }
    #[test]
    fn verified_requires_fresh_bound_observation() {
        let s = scope();
        let v = serde_json::json!({"protocolVersion":1,"ok":true,"reason":"active","operationId":s.operation_id,"phase":"committed","verified":true,"retryRotation":false,"observed":null});
        assert!(receipt(&serde_json::to_vec(&v).unwrap(), &s, "status").is_err());
    }
    #[test]
    fn active_receipt_binds_fresh_rotation_evidence_and_rejects_secret_extensions() {
        let s = scope();
        let v = serde_json::json!({"protocolVersion":1,"ok":true,"reason":"active","operationId":s.operation_id,"phase":"committed","verified":true,"retryRotation":false,
            "observed":{"operationId":s.operation_id,"deviceId":s.device_id,"addressId":s.address_id,"oldEnrollmentId":s.old_enrollment_id,"newEnrollmentId":s.new_enrollment_id,"localPhase":"rotated","actualDeviceIdentityChecked":true,"newPasswordMatches":true,"oldPasswordMatches":false,"observedAt":chrono::Utc::now().to_rfc3339(),"commandHash":p::STATUS_HASH}});
        assert!(receipt(&serde_json::to_vec(&v).unwrap(), &s, "status").is_ok());
        for (field, value) in [
            ("deviceId", serde_json::json!("other")),
            ("oldPasswordMatches", serde_json::json!(true)),
            ("actualDeviceIdentityChecked", serde_json::json!(false)),
            ("observedAt", serde_json::json!("2000-01-01T00:00:00Z")),
            ("commandHash", serde_json::json!(p::ROTATE_HASH)),
            ("approvalToken", serde_json::json!("private-fixture")),
        ] {
            let mut bad = v.clone();
            bad["observed"][field] = value;
            assert!(
                receipt(&serde_json::to_vec(&bad).unwrap(), &s, "status").is_err(),
                "{field}"
            );
        }
        let mut bad = v.clone();
        bad["retryRotation"] = true.into();
        assert!(receipt(&serde_json::to_vec(&bad).unwrap(), &s, "status").is_err());
    }
}

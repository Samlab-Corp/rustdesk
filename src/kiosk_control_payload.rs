//! Fixed app command and public receipt schemas; never forward arbitrary output.
use crate::kiosk_control_policy as policy;
use serde_json::Value;
fn exact(v: &Value, keys: &[&str]) -> bool {
    v.as_object().map_or(false, |m| {
        m.len() == keys.len() && keys.iter().all(|k| m.contains_key(*k))
    })
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or("kiosk_control_protocol_rejected")
}
fn bounded_token(v: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
fn assignment(v: &Value, device: &str) -> bool {
    exact(
        v,
        &[
            "environment",
            "merchantId",
            "deviceId",
            "location",
            "number",
        ],
    ) && matches!(
        v["environment"].as_str(),
        Some("development" | "production")
    ) && v["merchantId"]
        .as_u64()
        .map_or(false, |n| n > 0 && n <= 9_007_199_254_740_991)
        && v["deviceId"].as_str() == Some(device)
        && matches!(v["location"].as_str(), Some("outer" | "inner"))
        && v["number"]
            .as_u64()
            .map_or(false, |n| (1..=99).contains(&n))
}
pub fn validate(bytes: &[u8], request: &policy::Request) -> Result<String, &'static str> {
    if bytes.is_empty() || bytes.len() > policy::MAX_PAYLOAD {
        return Err("kiosk_control_protocol_rejected");
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| "kiosk_control_protocol_rejected")?;
    if v["commandVersion"] != 1
        || text(&v, "deliveryId")? != request.delivery_id
        || text(&v, "operationId")? != request.operation_id
    {
        return Err("kiosk_control_protocol_rejected");
    }
    let action = text(&v, "action")?;
    let valid = match action {
        "prepare" => {
            exact(
                &v,
                &[
                    "commandVersion",
                    "deliveryId",
                    "operationId",
                    "action",
                    "assignment",
                ],
            ) && assignment(&v["assignment"], &request.expected_device_id)
        }
        "status" => exact(
            &v,
            &["commandVersion", "deliveryId", "operationId", "action"],
        ),
        "apply" => {
            let a = &v["approval"];
            let c = &a["challenge"];
            exact(
                &v,
                &[
                    "commandVersion",
                    "deliveryId",
                    "operationId",
                    "action",
                    "approval",
                ],
            ) && exact(a, &["approvalToken", "challenge"])
                && a["approvalToken"]
                    .as_str()
                    .map_or(false, |s| bounded_token(s, 32, 8192))
                && exact(
                    c,
                    &[
                        "challengeId",
                        "nonce",
                        "algorithm",
                        "publicKeyFormat",
                        "signatureFormat",
                        "canonicalVersion",
                    ],
                )
                && c["challengeId"]
                    .as_str()
                    .map_or(false, |s| bounded_token(s, 16, 128))
                && c["nonce"]
                    .as_str()
                    .map_or(false, |s| bounded_token(s, 16, 256))
                && c["algorithm"] == "ES256"
                && c["publicKeyFormat"] == "spki-der"
                && c["signatureFormat"] == "asn1-der"
                && c["canonicalVersion"] == 1
        }
        _ => false,
    };
    if !valid {
        return Err("kiosk_control_protocol_rejected");
    }
    Ok(action.into())
}
pub fn receipt(
    bytes: &[u8],
    request: &policy::Request,
    action: &str,
) -> Result<Vec<u8>, &'static str> {
    if bytes.is_empty() || bytes.len() > request.output_limit_bytes as usize {
        return Err("kiosk_control_receipt_invalid");
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| "kiosk_control_receipt_invalid")?;
    let allowed = [
        "commandVersion",
        "deliveryId",
        "operationId",
        "action",
        "ok",
        "reason",
        "assignment",
        "phase",
        "observed",
        "verified",
        "challenge",
        "expiresAt",
        "identity",
        "capabilities",
    ];
    let map = v.as_object().ok_or("kiosk_control_receipt_invalid")?;
    if map.keys().any(|k| !allowed.contains(&k.as_str()))
        || v["commandVersion"] != 1
        || v["deliveryId"] != request.delivery_id
        || v["operationId"] != request.operation_id
        || v["action"] != action
        || !v["ok"].is_boolean()
        || !v["verified"].is_boolean()
    {
        return Err("kiosk_control_receipt_invalid");
    }
    if let Some(a) = v.get("assignment") {
        if !assignment(a, &request.expected_device_id) {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    if let Some(p) = v.get("phase") {
        if !matches!(
            p.as_str(),
            Some("prepared" | "applying" | "applied" | "verified" | "uncertain")
        ) {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    if let Some(o) = v.get("observed") {
        if !exact(o, &["matches", "authenticated", "rendered"])
            || !["matches", "authenticated", "rendered"]
                .iter()
                .all(|k| o[*k].is_boolean())
        {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    if let Some(c) = v.get("challenge") {
        if !c.as_str().map_or(false, policy::nonce) {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    if let Some(t) = v.get("expiresAt") {
        if t.as_u64().is_none() {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    if let Some(i) = v.get("identity") {
        if !exact(i, &["keyId", "publicKey"])
            || !i["keyId"].as_str().map_or(false, policy::nonce)
            || !i["publicKey"]
                .as_str()
                .map_or(false, |s| bounded_token(s, 64, 1024))
        {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    if let Some(c) = v.get("capabilities") {
        if !c.as_array().map_or(false, |a| {
            a.len() <= 2
                && a.iter()
                    .all(|x| matches!(x.as_str(), Some("KCP_SECUREPOS_V1" | "DAOU_VP_V1")))
        }) {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    if let Some(r) = v.get("reason") {
        const REASONS: &[&str] = &[
            "INVALID_OPERATION_ID",
            "INVALID_ASSIGNMENT",
            "DEVICE_IDENTITY_UNAVAILABLE",
            "DEVICE_MISMATCH",
            "ENVIRONMENT_MISMATCH",
            "ENVIRONMENT_CHANGED",
            "DEVELOPMENT_REQUIRED",
            "OPERATION_NOT_FOUND",
            "OPERATION_CORRUPTED",
            "OPERATION_PAYLOAD_CONFLICT",
            "OPERATION_EXPIRED",
            "KIOSK_BUSY",
            "INVALID_PROVISIONING_GRANT",
            "SERVER_ASSIGNMENT_MISMATCH",
            "PROVISIONING_UNCERTAIN_QUERY_STATUS",
            "COMMAND_FAILED",
            "COMMAND_OUTCOME_UNCONFIRMED",
            "COMMAND_DELIVERY_CONFLICT",
            "COMMAND_QUEUE_FULL",
            "INVALID_COMMAND",
        ];
        if !r.as_str().map_or(false, |s| REASONS.contains(&s)) {
            return Err("kiosk_control_receipt_invalid");
        }
    }
    serde_json::to_vec(&v).map_err(|_| "kiosk_control_receipt_invalid")
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> policy::Request {
        policy::Request {
            version: 1,
            delivery_id: "11111111-1111-4111-8111-111111111111".into(),
            operation_id: "22222222-2222-4222-8222-222222222222".into(),
            expected_device_id: "fixture".into(),
            wrapper_sha256: "a".repeat(64),
            payload_sha256: "b".repeat(64),
            timeout_seconds: 60,
            output_limit_bytes: 32768,
            probe_only: false,
        }
    }
    fn status() -> Value {
        serde_json::json!({"commandVersion":1,"deliveryId":request().delivery_id,"operationId":request().operation_id,"action":"status"})
    }
    #[test]
    fn only_fixed_actions_and_exact_scope() {
        let r = request();
        assert_eq!(
            validate(&serde_json::to_vec(&status()).unwrap(), &r).unwrap(),
            "status"
        );
        let mut v = status();
        v["command"] = Value::String("secret command".into());
        assert!(validate(&serde_json::to_vec(&v).unwrap(), &r).is_err());
        v = status();
        v["deliveryId"] = Value::String(r.operation_id.clone());
        assert!(validate(&serde_json::to_vec(&v).unwrap(), &r).is_err());
    }
    #[test]
    fn receipts_cannot_leak_tokens_unknown_fields_or_unbounded_errors() {
        let r = request();
        let mut v = status();
        v["ok"] = Value::Bool(false);
        v["verified"] = Value::Bool(false);
        v["reason"] = Value::String("KIOSK_BUSY".into());
        assert!(receipt(&serde_json::to_vec(&v).unwrap(), &r, "status").is_ok());
        for key in [
            "approvalToken",
            "accessToken",
            "password",
            "stderr",
            "command",
        ] {
            let mut bad = v.clone();
            bad[key] = Value::String("PRIVATE".into());
            assert!(receipt(&serde_json::to_vec(&bad).unwrap(), &r, "status").is_err());
        }
        v["reason"] = Value::String("PRIVATE".into());
        assert!(receipt(&serde_json::to_vec(&v).unwrap(), &r, "status").is_err());
    }
    #[test]
    fn prepared_public_receipt_matches_the_installed_app_contract() {
        let r = request();
        let mut v = status();
        v["action"] = Value::String("prepare".into());
        v["ok"] = Value::Bool(true);
        v["verified"] = Value::Bool(false);
        v["phase"] = Value::String("prepared".into());
        v["assignment"] = serde_json::json!({"environment":"development","merchantId":317,"deviceId":"fixture","location":"outer","number":99});
        v["identity"] = serde_json::json!({"keyId":"z".repeat(43),"publicKey":"a".repeat(122)});
        v["challenge"] = Value::String("n".repeat(43));
        v["expiresAt"] = serde_json::json!(1890000000000u64);
        v["capabilities"] = serde_json::json!(["KCP_SECUREPOS_V1", "DAOU_VP_V1"]);
        assert!(receipt(&serde_json::to_vec(&v).unwrap(), &r, "prepare").is_ok());
        v["assignment"]["deviceId"] = Value::String("other".into());
        assert!(receipt(&serde_json::to_vec(&v).unwrap(), &r, "prepare").is_err());
    }
}

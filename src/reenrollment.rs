//! Purpose-separated SYSTEM RPC. Never creates a terminal or a child command.
use crate::{
    reenrollment_payload::{self as wire, Scope},
    reenrollment_policy as p,
};
use hbb_common::{
    base64::{self, Engine},
    message_proto::*,
    rand::{rngs::OsRng, RngCore},
};
#[derive(Default)]
pub struct Session {
    request: Option<p::Request>,
    scope: Option<Scope>,
    gate: Option<p::Gate>,
    fresh: bool,
    cap: Option<ReenrollmentCapability>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unauthenticated_or_unknown_scope_never_reaches_guardian() {
        let mut value = ReenrollmentSession::default();
        value.reenrollment_version = 1;
        value.scope_json = b"{}".to_vec().into();
        assert!(Session::from_proto(value).is_err());
        let mut s = Session::default();
        assert_eq!(s.prepare("74067020".into()), Err("reenrollment_not_ready"));
        assert!(s.capability().is_none());
    }
}
impl Session {
    pub fn from_proto(v: ReenrollmentSession) -> Result<Self, &'static str> {
        let scope = Scope::parse(&v.scope_json)?;
        let request = p::Request {
            delivery_id: v.delivery_id,
            operation_id: scope.operation_id.clone(),
            action: v.action,
            device_id: scope.device_id.clone(),
            guardian_sha256: v.guardian_sha256,
            scope_json: serde_json::to_vec(&scope).map_err(|_| "reenrollment_protocol_rejected")?,
            probe_only: v.probe_only,
        };
        if v.reenrollment_version != 1 || !request.valid() {
            return Err("reenrollment_protocol_rejected");
        }
        Ok(Self {
            request: Some(request),
            scope: Some(scope),
            ..Default::default()
        })
    }
    pub fn password_verified(&mut self) {
        self.fresh = true;
    }
    pub fn prepare(&mut self, address: String) -> Result<(), &'static str> {
        if self.gate.is_some() {
            return Ok(());
        }
        if !self.fresh {
            return Err("reenrollment_not_ready");
        }
        #[cfg(windows)]
        let (pid, session) = {
            let pid = std::process::id();
            if !crate::platform::is_process_running_as_system(pid).unwrap_or(false) {
                return Err("reenrollment_system_required");
            }
            let mut session = 0;
            if unsafe { winapi::um::processthreadsapi::ProcessIdToSessionId(pid, &mut session) }
                == 0
            {
                return Err("reenrollment_system_required");
            }
            (pid, session)
        };
        #[cfg(not(windows))]
        let (pid, session) = {
            let _ = address;
            return Err("reenrollment_system_required");
            #[allow(unreachable_code)]
            (0, 0)
        };
        let r = self
            .request
            .as_ref()
            .ok_or("reenrollment_protocol_rejected")?;
        let scope = self
            .scope
            .as_ref()
            .ok_or("reenrollment_protocol_rejected")?;
        if address != scope.address_id {
            return Err("reenrollment_identity_untrusted");
        }
        let frame=serde_json::to_vec(&serde_json::json!({"protocolVersion":1,"operation":"guardian-reenrollment-capability","scope":scope,"action":r.action})).map_err(|_|"reenrollment_protocol_rejected")?;
        let bytes = crate::native_management_guardian::reenrollment_request(
            frame,
            &r.guardian_sha256,
            false,
        )?;
        let guardian = wire::capability(&bytes, scope, &r.action)?;
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "reenrollment_not_ready")?;
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let gate = p::Gate::new(r.clone(), challenge.clone(), self.fresh)?;
        self.cap = Some(ReenrollmentCapability {
            reenrollment_version: 1,
            delivery_id: r.delivery_id.clone(),
            operation_id: r.operation_id.clone(),
            action: r.action.clone(),
            command_hash: p::action_hash(&r.action).unwrap().into(),
            scope_json: r.scope_json.clone().into(),
            guardian_sha256: r.guardian_sha256.clone(),
            address_id: address,
            challenge,
            executor_is_system: true,
            executor_process_id: pid,
            executor_session_id: session,
            non_pty: true,
            guardian_capability: serde_json::to_vec(&guardian)
                .map_err(|_| "reenrollment_protocol_rejected")?
                .into(),
            ..Default::default()
        });
        self.gate = Some(gate);
        Ok(())
    }
    pub fn capability(&self) -> Option<ReenrollmentCapability> {
        self.cap.clone()
    }
    pub fn reject_input(&mut self) {
        if let Some(g) = self.gate.as_mut() {
            g.reject()
        }
    }
    pub async fn execute(&mut self, mut input: ReenrollmentExecute) -> ReenrollmentResult {
        let mut result = ReenrollmentResult {
            reenrollment_version: 1,
            status: "rejected".into(),
            reason: "reenrollment_protocol_rejected".into(),
            ..Default::default()
        };
        let Some(r) = self.request.as_ref() else {
            return result;
        };
        result.delivery_id = r.delivery_id.clone();
        result.operation_id = r.operation_id.clone();
        let Some(g) = self.gate.as_mut() else {
            return result;
        };
        if let Err(e) = g.consume(
            input.reenrollment_version,
            &input.delivery_id,
            &input.challenge,
            input.grant_token.len(),
        ) {
            result.reason = e.into();
            return result;
        }
        static IDS: std::sync::OnceLock<std::sync::Mutex<p::Deliveries>> =
            std::sync::OnceLock::new();
        if IDS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| ())
            .and_then(|mut ids| ids.reserve(&r.delivery_id).map_err(|_| ()))
            .is_err()
        {
            result.reason = "reenrollment_replayed".into();
            return result;
        }
        let Some(scope) = self.scope.clone() else {
            return result;
        };
        let r = r.clone();
        let frame = serde_json::to_vec(
            &serde_json::json!({"protocolVersion":1,"operation":"guardian-reenrollment","scope":scope,"action":r.action,"deliveryId":r.delivery_id,"challenge":input.challenge,"commandHash":p::action_hash(&r.action).unwrap(),"grantToken":input.grant_token}),
        );
        let mut secret = std::mem::take(&mut input.grant_token).into_bytes();
        secret.fill(0);
        result.status = "uncertain".into();
        result.reason = "reenrollment_execution_unconfirmed".into();
        let Ok(frame) = frame else { return result };
        let value = hbb_common::tokio::task::spawn_blocking(move || {
            let bytes = crate::native_management_guardian::reenrollment_request(
                frame,
                &r.guardian_sha256,
                true,
            )?;
            let receipt = wire::receipt(&bytes, &scope, &r.action)?;
            serde_json::to_vec(&receipt).map_err(|_| "reenrollment_protocol_rejected")
        })
        .await;
        if let Ok(Ok(bytes)) = value {
            result.status = "completed".into();
            result.reason.clear();
            result.receipt = bytes.into();
            result.response_confirmed = true;
        }
        result
    }
}

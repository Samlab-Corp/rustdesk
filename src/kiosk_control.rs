//! Fixed, password-authorized user action; no interactive terminal is opened.
use crate::kiosk_control_policy::{self as policy, Gate, Request};
use hbb_common::{
    base64::{self, Engine},
    message_proto::*,
    rand::{rngs::OsRng, RngCore},
};
#[derive(Default)]
pub struct Session {
    request: Option<Request>,
    gate: Option<Gate>,
    fresh_password: bool,
    address: String,
    #[cfg(windows)]
    token: Option<crate::server::terminal_helper::kiosk_control::Handle>,
    #[cfg(windows)]
    as_user: bool,
    #[cfg(windows)]
    pinned: Option<crate::native_management_guardian::FixedKiosk>,
}
impl Session {
    pub fn from_proto(value: KioskControlSession) -> Result<Self, &'static str> {
        let r = Request {
            version: value.control_version,
            delivery_id: value.delivery_id,
            operation_id: value.operation_id,
            expected_device_id: value.expected_device_id,
            wrapper_sha256: value.wrapper_sha256,
            payload_sha256: value.payload_sha256,
            timeout_seconds: value.timeout_seconds,
            output_limit_bytes: value.output_limit_bytes,
            probe_only: value.probe_only,
        };
        if !r.valid() {
            return Err("kiosk_control_protocol_rejected");
        }
        Ok(Self {
            request: Some(r),
            ..Default::default()
        })
    }
    pub fn password_verified(&mut self) {
        self.fresh_password = true;
    }
    #[cfg(windows)]
    pub fn prepare(
        &mut self,
        address: String,
        token: Option<crate::terminal_service::UserToken>,
    ) -> Result<(), &'static str> {
        if self.gate.is_some() {
            return Ok(());
        }
        let request = self
            .request
            .as_ref()
            .ok_or("kiosk_control_protocol_rejected")?
            .clone();
        let actual = crate::server::terminal_helper::kiosk_control::user_token(token)?;
        let pinned = crate::native_management_guardian::pin_kiosk(&request.wrapper_sha256)
            .map_err(|_| "kiosk_control_wrapper_unavailable")?;
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "kiosk_control_not_ready")?;
        self.gate = Some(Gate::new(
            request,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
            self.fresh_password,
        )?);
        self.address = address;
        self.token = Some(actual);
        self.as_user = token.is_some();
        self.pinned = Some(pinned);
        Ok(())
    }
    pub fn capability(&self) -> Option<KioskControlCapability> {
        self.gate.as_ref().map(|g| KioskControlCapability {
            control_version: 1,
            delivery_id: g.request().delivery_id.clone(),
            operation_id: g.request().operation_id.clone(),
            expected_device_id: g.request().expected_device_id.clone(),
            wrapper_sha256: g.request().wrapper_sha256.clone(),
            address_id: self.address.clone(),
            challenge: g.challenge().into(),
            action: policy::ACTION.into(),
            non_pty: true,
            current_user: true,
            ..Default::default()
        })
    }
    pub fn reject_input(&mut self) {
        if let Some(g) = self.gate.as_mut() {
            g.reject_input();
        }
    }
    pub async fn execute(&mut self, input: KioskControlExecute) -> KioskControlResult {
        let mut result = KioskControlResult {
            control_version: 1,
            status: "rejected".into(),
            reason: "kiosk_control_protocol_rejected".into(),
            ..Default::default()
        };
        let Some(request) = self.request.as_ref() else {
            return result;
        };
        result.delivery_id = request.delivery_id.clone();
        result.operation_id = request.operation_id.clone();
        let hash = hex::encode(sha2::Sha256::digest(&input.payload));
        let Some(gate) = self.gate.as_mut() else {
            return result;
        };
        if let Err(reason) = gate.begin(
            input.control_version,
            &input.delivery_id,
            &input.challenge,
            input.payload.len(),
            &hash,
        ) {
            result.reason = reason.into();
            return result;
        }
        let action = match crate::kiosk_control_payload::validate(&input.payload, request) {
            Ok(action) => action,
            Err(reason) => {
                result.reason = reason.into();
                return result;
            }
        };
        static DELIVERIES: std::sync::OnceLock<std::sync::Mutex<policy::Deliveries>> =
            std::sync::OnceLock::new();
        let reserved = DELIVERIES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| "kiosk_control_not_ready")
            .and_then(|mut d| d.reserve(&request.delivery_id));
        if let Err(reason) = reserved {
            result.reason = reason.into();
            return result;
        }
        #[cfg(windows)]
        {
            let Some(token) = self.token.take() else {
                return result;
            };
            let Some(pinned) = self.pinned.take() else {
                return result;
            };
            let request = request.clone();
            let as_user = self.as_user;
            let outcome = hbb_common::tokio::task::spawn_blocking(move || {
                let output = crate::server::terminal_helper::kiosk_control::execute(
                    token,
                    as_user,
                    pinned,
                    input.payload.to_vec(),
                    request.clone(),
                );
                let receipt =
                    crate::kiosk_control_payload::receipt(&output.receipt, &request, &action);
                (output, receipt)
            })
            .await;
            result.status = "unconfirmed".into();
            result.reason = "kiosk_control_execution_unconfirmed".into();
            if let Ok((outcome, receipt)) = outcome {
                if matches!(
                    outcome.reason,
                    "kiosk_control_timeout_unconfirmed"
                        | "kiosk_control_output_unconfirmed"
                        | "kiosk_control_not_ready"
                ) {
                    result.reason = outcome.reason.into();
                }
                if let (Some(exit), Ok(receipt)) = (outcome.exit, receipt) {
                    result.status = "completed".into();
                    result.reason.clear();
                    result.exit_code = exit;
                    result.exit_code_confirmed = true;
                    result.receipt = receipt.into();
                }
            }
        }
        result
    }
}
use sha2::Digest;

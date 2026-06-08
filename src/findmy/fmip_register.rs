//! fmip `identityV5` device registration (Task 3 of IDENTITYV5_PLAN.md).
//!
//! Goal: register our device on the account's Find-My-iPhone (fmip) device list
//! with a populated `deviceDiscoveryId`, so it becomes electable as the account
//! `meDeviceId`. That is the upstream gate for Android-driven FindMy People
//! *publish* (see START_HERE.md / SESSION_..._FINDINGS.md).
//!
//! ## What this module does (local, reversible)
//! It assembles the exact identityV5 request and signs it, consuming the two
//! device-signing primitives through the [`OSConfig`] bridge contract:
//!   - [`OSConfig::get_fmip_pcrt_token`]  -> `ifcReceipt` (MobileActivation PCRT)
//!   - [`OSConfig::get_fmip_signature`]   -> X-Mme-Sign1/2 (+5/6)
//! On a non-relay config both default to [`PushError::FmipBridgeUnsupported`], so
//! this path is inert until the relay bridge (Task 2) implements them.
//!
//! ## Wire spec (PROVEN — decompile + capture)
//! Body/field shape is `FMDRequestIdentityV5::requestBody` (@100062f30), verified
//! against the real captured body in
//! `tools/findmy-capture/captures/quic-findmydeviced.log` line 344:
//! ```json
//! {"cmdId":"<uuid>","deviceInfo":{"aps-token":"<hex>","alCapability":5,
//!  "udid":"<40hex>","pscSUILastModified":<ms>},"dsid":"<dsid>",
//!  "deviceContext":{"deviceTS":"<iso8601>"},"serialNumber":"...","ecid":"0x..",
//!  "meid":"...","imei":"...","wifiMac":"..","ifcReceipt":"..","btMac":"..","chipId":"0x.."}
//! ```
//! Note the real body omits `imei2` and `escrowHash` (nil-skipped by
//! `fm_safelyMapKey:toObject:`); we replicate that (omit-when-empty).
//!
//! Signing input is `_calculateSignatureForBody:` (@1000637a0):
//!   `digest = CC_SHA256( authHeaderValue.utf8 || NSJSONSerialization(body) )`
//! then `signatureForData:digest requestUUID:<AL-ID> mode:0` -> [Sign1, Sign2].
//!
//! ## authHeaderValue — CONFIRMED (decompiled `FMDRequest::authHeaderValue` @10003a9b4)
//! The auth string folded into the digest is:
//!   `"Basic " + base64( authId + ":" + authToken )`,  authId = dsid.
//! This is byte-identical to the request's own HTTP `Authorization` header
//! (`.basic_auth(dsid, token)` == `Basic base64(dsid:token)`). So we derive the
//! digest prefix from the SAME string we send, eliminating any mismatch risk.
//! (`authToken` = the account's fmip token; our `mmeFMIPAppToken` is that token —
//! it is what `FindMyPhoneClient` already uses for `/fmipservice/device/`.)
//!
//! ## Remaining gate before a LIVE submit (do NOT overclaim)
//!  - Whether the relay can actually produce Sign1/2 outside findmydeviced — the
//!    load-bearing gate (IDENTITYV5_PLAN.md §Task 2 correction). Until the relay
//!    bridge returns a real signature, `register_identity_v5` returns
//!    `FmipBridgeUnsupported` by construction, so nothing is sent.

use chrono::{SecondsFormat, Utc};
use log::info;
use openssl::sha::sha256;
use rand::Rng;
use serde_json::json;
use uuid::Uuid;

use crate::{
    auth::TokenProvider, util::{base64_encode, encode_hex, REQWEST},
    APSConnection, FmipSignature, OSConfig, PushError,
};
use omnisette::{AnisetteProvider, ArcAnisetteClient};
use std::sync::Arc;

/// The fmip auth-token type used for findmydeviced-class calls (same as
/// `FindMyPhoneClient`). Also folded into the identityV5 signature digest as the
/// Authorization value — see the `authHeaderValue` unknown in the module docs.
const FMIP_TOKEN_NAME: &str = "mmeFMIPAppToken";

/// `alCapability` value observed in every captured identityV5/ack body (activation
/// lock capability). Constant on the captured device.
const AL_CAPABILITY: i64 = 5;

/// Result of a `register_identity_v5` attempt.
#[derive(Debug)]
pub struct IdentityV5Outcome {
    pub http_status: u16,
    pub response_body: String,
    /// The `X-Apple-AL-ID` UUID we sent (also the signature requestUUID).
    pub request_uuid: String,
}

/// Builds and submits the fmip `identityV5` device registration.
///
/// Mirrors `FindMyPhoneClient`'s request context. Constructed per attempt; holds
/// no persistent state.
pub struct FmipRegisterClient<P: AnisetteProvider> {
    pub dsid: String,
    pub server: u8,
    pub anisette: ArcAnisetteClient<P>,
    pub aps: APSConnection,
    pub token_provider: Arc<TokenProvider<P>>,
}

impl<P: AnisetteProvider> FmipRegisterClient<P> {
    /// Assemble the identityV5 JSON body EXACTLY as the captured real request.
    ///
    /// `psc_sui_last_modified` is the `pscSUILastModified` value (ms). It is a
    /// device pref written by the PSC/Provenance subsystem; the relay bridge
    /// should supply the real value. `0` omits it.
    pub fn build_body(
        &self,
        config: &dyn OSConfig,
        aps_token_hex_upper: &str,
        pcrt_receipt: &str,
        psc_sui_last_modified: u64,
    ) -> Result<(serde_json::Value, String), PushError> {
        let hw = config
            .get_fmip_device_hardware()
            .ok_or(PushError::FmipBridgeUnsupported)?;

        // 40-char hardware UDID (lowercase in the captured body).
        let udid = config.get_hardware_udid().to_lowercase();
        // cmdId is a fresh UUID per request (captured as a plain UUID string).
        let cmd_id = Uuid::new_v4().to_string();
        // deviceContext.deviceTS: ISO-8601 with millisecond precision + Z.
        let device_ts = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

        // deviceInfo: minimal set the real body carries (NOT the full status blob).
        let mut device_info = serde_json::Map::new();
        device_info.insert("aps-token".into(), json!(aps_token_hex_upper));
        device_info.insert("alCapability".into(), json!(AL_CAPABILITY));
        device_info.insert("udid".into(), json!(udid));
        if psc_sui_last_modified != 0 {
            device_info.insert("pscSUILastModified".into(), json!(psc_sui_last_modified));
        }

        // Fields added via fm_safelyMapKey:toObject: -> nil/empty are OMITTED.
        let mut body = serde_json::Map::new();
        body.insert("cmdId".into(), json!(cmd_id));
        body.insert("deviceInfo".into(), serde_json::Value::Object(device_info));
        body.insert("dsid".into(), json!(self.dsid));
        body.insert("deviceContext".into(), json!({ "deviceTS": device_ts }));
        body.insert("serialNumber".into(), json!(hw.serial_number));
        insert_if_nonempty(&mut body, "ecid", &hw.ecid);
        insert_if_nonempty(&mut body, "meid", &hw.meid);
        insert_if_nonempty(&mut body, "imei", &hw.imei);
        insert_if_nonempty(&mut body, "imei2", &hw.imei2);
        insert_if_nonempty(&mut body, "wifiMac", &hw.wifi_mac);
        body.insert("ifcReceipt".into(), json!(pcrt_receipt));
        insert_if_nonempty(&mut body, "btMac", &hw.bt_mac);
        insert_if_nonempty(&mut body, "chipId", &hw.chip_id);

        let value = serde_json::Value::Object(body);
        Ok((value, cmd_id))
    }

    /// Compute the identityV5 signing digest: `SHA256(authHeaderValue || bodyJSON)`.
    ///
    /// `body_json` MUST be the exact bytes that will be sent (same serialization).
    /// `auth_header_value` is the request Authorization header string (see the
    /// module-level `authHeaderValue` unknown).
    pub fn signing_digest(auth_header_value: &str, body_json: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(auth_header_value.len() + body_json.len());
        buf.extend_from_slice(auth_header_value.as_bytes());
        buf.extend_from_slice(body_json);
        sha256(&buf)
    }

    /// Full identityV5 registration: build body -> fetch PCRT -> sign -> submit.
    ///
    /// Returns the HTTP status + response body for inspection. A 2xx plus a
    /// subsequent populated `deviceDiscoveryId` in the account device list is the
    /// real success signal (Task 5). This will return
    /// [`PushError::FmipBridgeUnsupported`] on any non-relay config.
    pub async fn register_identity_v5(
        &self,
        config: &dyn OSConfig,
        psc_sui_last_modified: u64,
    ) -> Result<IdentityV5Outcome, PushError> {
        // 1. ifcReceipt (PCRT) from the device bridge.
        let pcrt = config.get_fmip_pcrt_token().await?;
        info!("[FMF-IDV5] Got PCRT/ifcReceipt ({} chars)", pcrt.len());

        // 2. aps token (hex, uppercase — matches captured body + clientContext usage).
        let aps_token = encode_hex(&self.aps.get_token().await).to_uppercase();

        // 3. Build the body — with a FRESH random UDID (curiosity test: first-time
        //    enrollment path). The real hardware (serial/ecid/chipId/MACs) and real
        //    signature still come from the 6s; only the UDID is synthetic.
        let (mut body, cmd_id) = self.build_body(config, &aps_token, &pcrt, psc_sui_last_modified)?;
        // Generate a fresh 40-hex-char UDID (same format as a real iOS UDID).
        let fresh_udid: String = (0..40).map(|_| format!("{:x}", rand::thread_rng().gen_range(0u8..16))).collect();
        info!("[FMF-IDV5] ★ FRESH-UDID EXPERIMENT: using synthetic udid={} (NOT the relay's registered one)", fresh_udid);
        // Patch the body's deviceInfo.udid to the fresh value.
        if let Some(obj) = body.as_object_mut() {
            if let Some(di) = obj.get_mut("deviceInfo").and_then(|v| v.as_object_mut()) {
                di.insert("udid".to_string(), serde_json::Value::String(fresh_udid.clone()));
            }
        }
        let body_bytes = serde_json::to_vec(&body)?;
        info!("[FMF-IDV5] Built identityV5 body cmdId={} ({} bytes)", cmd_id, body_bytes.len());

        // 4. Auth token + the exact Authorization header value.
        //    CONFIRMED shape (FMDRequest::authHeaderValue @10003a9b4):
        //    "Basic " + base64(authId ":" authToken), authId = dsid. We build this
        //    ONCE and use the identical string for both the signing digest and the
        //    request's Authorization header, so they can never diverge.
        let token = self.token_provider.get_mme_token(FMIP_TOKEN_NAME).await?;
        let auth_header_value = format!("Basic {}", base64_encode(format!("{}:{}", self.dsid, token).as_bytes()));

        // 5. Digest + signature (the load-bearing bridge call).
        let digest = Self::signing_digest(&auth_header_value, &body_bytes);
        let request_uuid = Uuid::new_v4().to_string().to_uppercase();
        let sig: FmipSignature = config.get_fmip_signature(&digest, &request_uuid).await?;
        info!(
            "[FMF-IDV5] Got signature sign1={}c sign2={}c baa={}",
            sig.sign1.len(),
            sig.sign2.len(),
            sig.sign5.is_some()
        );

        // 6. Submit — use the FRESH UDID in the URL path too (must match the body).
        let url = format!(
            "https://p{}-fmip.icloud.com/fmipservice/findme/{}/{}/identityV5",
            self.server, self.dsid, fresh_udid.to_uppercase()
        );
        info!("[FMF-IDV5] Submitting to URL with fresh UDID: {}", url);

        let mut req = REQWEST
            .post(&url)
            .headers(super::get_find_my_headers(config, "3.0", &mut *self.anisette.lock().await, "Find%20My/375.20").await?)
            // Use the SAME auth string that was folded into the signing digest,
            // rather than .basic_auth() re-encoding it independently.
            .header("Authorization", &auth_header_value)
            .header("Content-Type", "application/json")
            .header("X-Mme-Sign1", &sig.sign1)
            .header("X-Mme-Sign2", &sig.sign2)
            .header("X-Apple-AL-ID", &request_uuid);
        if let Some(s5) = &sig.sign5 {
            req = req.header("X-Mme-Sign5", s5);
        }
        if let Some(s6) = &sig.sign6 {
            req = req.header("X-Mme-Sign6", s6);
        }

        let response = req.body(body_bytes).send().await?;
        let status = response.status().as_u16();

        // Capture the response headers BEFORE consuming the body. reqwest 0.11 /
        // hyper discards the custom HTTP reason phrase (so we can't read
        // "Identity Service Failed" vs "Internal Server Error" off the status
        // line). Instead we use a MORE reliable discriminator for WHICH layer
        // rejected, straight from the captures:
        //   - fmip IDENTITY SERVICE reached  -> response carries
        //       X-Responding-Instance: fmipservice:...  (+ X-Responding-Server,
        //       X-Responding-Partition, X-Apple-Request-UUID) and usually an
        //       empty body. This is the "Identity Service Failed" case → the
        //       synthetic-UDID/real-silicon binding was refused (likely dead end).
        //   - EDGE / WAF rejection            -> body is
        //       {"desc":"default response from ResponseContentFilter"} and the
        //       fmipservice X-Responding-* headers are ABSENT. This means the
        //       request never reached the identity service → still malformed /
        //       inconsistent (fixable).
        // Log every diagnostic header so the reason layer is unambiguous.
        let diag_header = |name: &str| -> String {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("<absent>")
                .to_string()
        };
        let h_responding_instance = diag_header("X-Responding-Instance");
        let h_responding_server = diag_header("X-Responding-Server");
        let h_responding_partition = diag_header("X-Responding-Partition");
        let h_request_uuid = diag_header("X-Apple-Request-UUID");
        let h_retry_after = diag_header("X-Apple-Retry-After");
        let reached_identity_service = h_responding_instance.starts_with("fmipservice");

        let text = response.text().await?;
        info!("[FMF-IDV5] identityV5 response status={} body={}", status, &text[..text.len().min(500)]);
        info!(
            "[FMF-IDV5] REASON-LAYER: reached_identity_service={} \
             X-Responding-Instance={} X-Responding-Server={} X-Responding-Partition={} \
             X-Apple-Request-UUID={} X-Apple-Retry-After={}",
            reached_identity_service,
            h_responding_instance,
            h_responding_server,
            h_responding_partition,
            h_request_uuid,
            h_retry_after,
        );
        if status == 500 {
            if reached_identity_service {
                info!("[FMF-IDV5] => 500 came from the fmip IDENTITY SERVICE (not the edge filter). \
                       This is the 'Identity Service Failed' layer -> the enrollment was evaluated \
                       and refused (synthetic-UDID/real-silicon binding is the likely wall).");
            } else if text.contains("ResponseContentFilter") {
                info!("[FMF-IDV5] => 500 came from the EDGE/WAF (ResponseContentFilter), request never \
                       reached the identity service -> still malformed/inconsistent (fixable).");
            } else {
                info!("[FMF-IDV5] => 500 from an UNKNOWN layer (no fmipservice headers, no \
                       ResponseContentFilter body) - inspect the headers above.");
            }
        }

        Ok(IdentityV5Outcome {
            http_status: status,
            response_body: text,
            request_uuid,
        })
    }
}

fn insert_if_nonempty(map: &mut serde_json::Map<String, serde_json::Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.to_string(), json!(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_manual_concat() {
        // The digest MUST equal SHA256 over auth-bytes followed by body-bytes,
        // in that order. Guards against accidentally hashing body-first.
        let auth = "Basic dGVzdA==";
        let body = br#"{"a":1}"#;
        let got = FmipRegisterClient::<omnisette::DefaultAnisetteProvider>::signing_digest(auth, body);

        let mut expected_buf = Vec::new();
        expected_buf.extend_from_slice(auth.as_bytes());
        expected_buf.extend_from_slice(body);
        let expected = openssl::sha::sha256(&expected_buf);
        assert_eq!(got, expected);
        assert_eq!(got.len(), 32);
    }
}

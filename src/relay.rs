
use std::{collections::HashMap, time::{Duration, SystemTime}};

use async_trait::async_trait;
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::{activation::ActivationInfo, util::{base64_decode, base64_encode, encode_hex, REQWEST}, DebugMeta, FmipDeviceHardware, FmipSignature, OSConfig, PushError, RegisterMeta};

#[derive(Deserialize)]
pub struct DataResp {
    data: String,
}

/// Response of the relay bridge `POST /api/v1/bridge/get-pcrt-token` endpoint
/// (IDENTITYV5_PLAN.md Task 2). Wraps `MAECopyPCRTToken()`.
#[derive(Deserialize)]
struct FmipPcrtResp {
    pcrt: String,
}

/// Response of `POST /api/v1/bridge/fmip/sign`. The relay produces these via
/// `FMDAbsintheV3SigningInterface signatureForData:` (must run inside/attached to
/// findmydeviced context — see IDENTITYV5_PLAN.md §Task 2 correction).
#[derive(Deserialize)]
struct FmipSignResp {
    sign1: String,
    sign2: String,
    #[serde(default)]
    sign5: Option<String>,
    #[serde(default)]
    sign6: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct VersionsResp {
    versions: Versions,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Versions {
    software_build_id: String,
    software_name: String,
    software_version: String,
    serial_number: String,
    hardware_version: String,
    unique_device_id: String,

    // --- fmip identityV5 hardware descriptor (IDENTITYV5_PLAN.md Task 2/3) ---
    // Optional so existing relays (which don't emit these) still deserialize.
    // A relay bridge that supports identityV5 populates them from its activation
    // record + MobileGestalt. `ecid`/`chip_id` are the pre-formatted `0x%llx`
    // strings the wire uses. When absent, the identityV5 path stays inert.
    #[serde(default)]
    imei: Option<String>,
    #[serde(default)]
    imei2: Option<String>,
    #[serde(default)]
    meid: Option<String>,
    #[serde(default)]
    ecid: Option<String>,
    #[serde(default)]
    chip_id: Option<String>,
    #[serde(default)]
    wifi_mac: Option<String>,
    #[serde(default)]
    bt_mac: Option<String>,
    /// `pscSUILastModified` (ms) for the identityV5 deviceInfo. Optional.
    #[serde(default)]
    psc_sui_last_modified: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RelayConfig {
    pub version: Versions,
    pub icloud_ua: String,
    pub aoskit_version: String,
    pub dev_uuid: String,
    pub protocol_version: u32,
    pub host: String,
    pub code: String,
    pub beeper_token: Option<String>,
    pub udid: Option<String>,
}

impl RelayConfig {
    pub async fn get_versions(host: &str, code: &str, beeper_token: &Option<String>) -> Result<Versions, PushError> {
        let mut data = REQWEST.post(format!("{}/api/v1/bridge/get-version-info", host))
            .bearer_auth(code)
            .header("Content-Length", "0");

        if let Some(token) = beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;

        match result.status().as_u16() {
            200 => {},
            404 => {
                return Err(PushError::DeviceNotFound)
            },
            _status => {
                return Err(PushError::RelayError(_status, result.text().await?))
            }
        }

        let result: VersionsResp = result.json().await?;

        Ok(result.versions)
    }
}

#[async_trait]
impl OSConfig for RelayConfig {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.version.software_build_id.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: "iMac13,1".to_string(),
            product_version: self.version.software_version.clone(),
            serial_number: self.version.serial_number.clone(),
            unique_device_id: self.version.unique_device_id.clone().to_uppercase(),
        }
    }

    fn get_udid(&self) -> String {
        self.udid.clone().expect("missing udid!")
    }

    fn get_hardware_udid(&self) -> String {
        self.version.unique_device_id.clone()
    }
    fn get_normal_ua(&self, item: &str) -> String {
        let part = self.icloud_ua.split_once(char::is_whitespace).unwrap().0;
        format!("{item} {part}")
    }

    fn get_serial_number(&self) -> String {
        self.version.serial_number.clone()
    }

    fn get_mme_clientinfo(&self, item: &str) -> String {
        format!("<{}> <{};{};{}> <{}>", self.version.hardware_version, self.version.software_name, self.version.software_version, self.version.software_build_id, item)
    }

    fn get_adi_mme_info(&self, item: &str, require_mac: bool) -> String {
        if require_mac {
            // must be mac for ClearADI
            format!("<iMac13,1> <macOS;13.6.4;22G513> <{}>", item)
        } else {
            self.get_mme_clientinfo(item)
        }
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        [
            ("X-Apple-I-SRL-NO", &self.version.serial_number),
        ].into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn get_version_ua(&self) -> String {
        format!("[{},{},{},{}]", self.version.software_name, self.version.software_version, self.version.software_build_id, self.version.hardware_version)
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/prefpane/loginDelegates"
    }

    fn get_activation_device(&self) -> String {
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.dev_uuid.clone()
    }

    fn get_device_name(&self) -> String {
        format!("iPhone-{}", self.version.serial_number)
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        let mut data = REQWEST.post(format!("{}/api/v1/bridge/get-validation-data", self.host))
            .bearer_auth(&self.code)
            .header("Content-Length", "0");

        if let Some(token) = &self.beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;

        match result.status().as_u16() {
            200 => {},
            404 => {
                return Err(PushError::DeviceNotFound)
            },
            _status => {
                return Err(PushError::RelayError(_status, result.text().await?))
            }
        }

        let result: DataResp = result.json().await?;

        Ok(base64_decode(&result.data))
    }

    fn get_fmip_device_hardware(&self) -> Option<FmipDeviceHardware> {
        // Requires the relay bridge to have populated the identityV5 hardware
        // fields. `ecid`/`chipId` are the load-bearing ones (the server needs the
        // silicon identity); gate on ecid being present.
        let ecid = self.version.ecid.clone()?;
        Some(FmipDeviceHardware {
            serial_number: self.version.serial_number.clone(),
            imei: self.version.imei.clone().unwrap_or_default(),
            imei2: self.version.imei2.clone().unwrap_or_default(),
            meid: self.version.meid.clone().unwrap_or_default(),
            ecid,
            chip_id: self.version.chip_id.clone().unwrap_or_default(),
            wifi_mac: self.version.wifi_mac.clone().unwrap_or_default(),
            bt_mac: self.version.bt_mac.clone().unwrap_or_default(),
        })
    }

    async fn get_fmip_pcrt_token(&self) -> Result<String, PushError> {
        // The registration server maps the URL path segment directly to the relay
        // websocket command verb (e.g. get-version-info). So the segment MUST equal
        // the relay's poll() command name exactly, with no extra slash.
        let mut data = REQWEST.post(format!("{}/api/v1/bridge/get-pcrt-token", self.host))
            .bearer_auth(&self.code)
            .header("Content-Length", "0");
        if let Some(token) = &self.beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;
        match result.status().as_u16() {
            200 => {},
            // Older relays without the fmip bridge return 404 -> unsupported.
            404 => return Err(PushError::FmipBridgeUnsupported),
            status => return Err(PushError::RelayError(status, result.text().await?)),
        }

        let result: FmipPcrtResp = result.json().await?;
        Ok(result.pcrt)
    }

    async fn get_fmip_signature(&self, digest: &[u8], request_uuid: &str) -> Result<FmipSignature, PushError> {
        // The beeper registration server (internal/api/routes.go bridgeExecuteCommand)
        // forwards ONLY the URL path segment as the relay websocket command name — it
        // never reads the HTTP request body (confirmed from source + the DIAG that
        // returned `raw data=null`). All other bridge commands are parameterless for
        // this reason. So we encode the fmip-sign parameters INTO the command segment:
        //     fmip-sign.<digest_hex>.<request_uuid>
        // - digest_hex: 64 lowercase hex chars (URL-safe; no '/','+','=' like base64).
        // - request_uuid: standard UUID (hex + '-'); '.' separates and appears in
        //   neither hex nor a UUID, so the relay splits unambiguously.
        // chi's {command} wildcard matches any non-'/' run (incl. '.'), so the whole
        // string arrives at the relay verbatim as the command name. The relay
        // prefix-matches "fmip-sign." and parses the two fields back out.
        let digest_hex = encode_hex(digest);
        let segment = format!("fmip-sign.{}.{}", digest_hex, request_uuid);

        let mut data = REQWEST.post(format!("{}/api/v1/bridge/{}", self.host, segment))
            .bearer_auth(&self.code)
            .header("Content-Length", "0");
        if let Some(token) = &self.beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;
        match result.status().as_u16() {
            200 => {},
            404 => return Err(PushError::FmipBridgeUnsupported),
            status => return Err(PushError::RelayError(status, result.text().await?)),
        }

        let result: FmipSignResp = result.json().await?;
        if let Some(err) = result.error {
            // The signing engine itself reported a failure (e.g. PSC session /
            // Cadmium round-trip failed). Surface it rather than sending a bad sig.
            return Err(PushError::RelayError(0, format!("fmip sign error: {}", err)));
        }
        Ok(FmipSignature {
            sign1: result.sign1,
            sign2: result.sign2,
            sign5: result.sign5,
            sign6: result.sign6,
        })
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.version.hardware_version.clone(),
            os_version: format!("{},{},{}", self.version.software_name, self.version.software_version, self.version.software_build_id),
            software_version: self.version.software_build_id.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.version.software_version.clone(),
            hardware_version: self.version.hardware_version.clone(),
            serial_number: self.version.serial_number.clone(),
        }
    }

    fn get_private_data(&self) -> Dictionary {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Dictionary::from_iter([
            // apple pay
            ("ap", Value::String("0".to_string())),

            ("d", Value::String(format!("{:.6}", apple_epoch.elapsed().unwrap().as_secs_f64()))),
            // device type
            ("dt", Value::Integer(1.into())),
            // green tea - ??
            ("gt", Value::String("0".to_string())),
            // supports handoff
            ("h", Value::String("1".to_string())),
            // supports phone calls
            ("p", Value::String("0".to_string())),

            ("pb", Value::String(self.version.software_build_id.clone())),
            ("pn", Value::String(if self.version.software_name == "MacOS" { "macOS".to_string() } else { self.version.software_name.clone() })),
            ("pv", Value::String(self.version.software_version.clone())),
            
            // mms router support
            ("m", Value::String("1".to_string())),
            // sms router support
            ("s", Value::String("1".to_string())),

            // tethering support
            // ec = enclosure color
            // c = data color
            // ss = service signatures
            // ktf = key transparency flags
            // ktv = key transparency version
            ("t", Value::String("0".to_string())),
            ("u", Value::String(self.dev_uuid.clone().to_uppercase())),
            // version
            ("v", Value::String("1".to_string())),
        ])
    }

}


mod activation;
mod aps;
mod util;
mod imessage;
mod error;
mod auth;
mod ids;
pub mod sharedstreams;
pub mod findmy;
pub mod facetime;
pub mod icloud;
pub mod statuskit;
pub mod passwords;
pub mod notes;
pub mod sticker_sync;
pub use imessage::cloud_messages;
pub use imessage::posterkit;
pub use util::KeyedArchive;

pub use icloud::cloudkit;
pub use icloud::keychain;
pub use icloud::mmcs;
pub use icloud::pcs;

pub use util::CompactECKey;

#[cfg(feature = "macos-validation-data")]
pub mod macos;

mod relay;

pub mod mmcsp {
    include!(concat!(env!("OUT_DIR"), "/mmcsp.rs"));
}

use std::collections::HashMap;
use std::fmt::Debug;

pub use icloud_auth::{DefaultAnisetteProvider, GenerateVerificationTokenRequest, default_provider, ArcAnisetteClient, LoginClientInfo, LoginState, AppleAccount, VerifyBody, TrustedPhoneNumber};

pub use util::{DebugRwLock, DebugMutex};
use activation::ActivationInfo;
pub use aps::{APSConnectionResource, APSConnection, APSMessage, APSState};
use async_trait::async_trait;
pub use auth::{request_update_account, UpdateAccountFinish};
pub use mmcs::{FileContainer, prepare_put};
pub use omnisette::AnisetteProvider;
pub use imessage::messages::{TypingApp, SetTranscriptBackgroundMessage, UpdateProfileMessage, UpdateProfileSharingMessage, MessageInst, ShareProfileMessage, SharedPoster, ScheduleMode, PermanentDeleteMessage, OperatedChat, DeleteTarget, MoveToRecycleBinMessage, TextFormat, TextEffect, TextFlags, LinkMeta, LPLinkMetadata, LPSpecializationMetadata, ReactMessageType, ErrorMessage, Reaction, UnsendMessage, EditMessage, UpdateExtensionMessage, PartExtension, ReactMessage, ChangeParticipantMessage, LPImageMetadata, RichLinkImageAttachmentSubstitute, LPIconMetadata, AttachmentType, ExtensionApp, BalloonLayout, Balloon, ConversationData, Message, MessageType, Attachment, NormalMessage, RenameMessage, IconChangeMessage, MessageParts, MessagePart, MMCSFile, IndexedMessagePart};
pub use imessage::aps_client::{IMClient, MADRID_SERVICE};
use util::encode_hex;
pub use util::{NSArrayClass, EntitlementsResponse, EntitlementAuthState, ResourceState, NSDictionaryClass, NSURL, NSArray, ResourceFailure, NSAttributedString, NSString, NSDictionaryTypedCoder, NSNumber, coder_encode_flattened, coder_decode_flattened, StCollapsedValue};
pub use ids::user::{IDSUser, register, IDSUserIdentity, IDSNGMIdentity, PrivateDeviceInfo, SupportAlert, SupportAction, ReportMessage};
pub use ids::identity_manager::{SendJob, MessageTarget, IdentityManager, KeyCache};
pub use ids::CertifiedContext;
pub use auth::{authenticate_apple, login_apple_delegates, authenticate_phone, authenticate_smsless, AuthPhone, LoginDelegate, CircleClientSession, TokenProvider};
pub use error::PushError;
pub use cloudkit_proto;
pub use cloudkit_derive;
pub use imessage::name_photo_sharing;

pub use auth::{IdmsAuthListener, IdmsMessage, IdmsRequestedSignIn, ApsData, ApsAlert, AkData, TeardownSignIn, CircleServerSession, IdmsCircleMessage};

use plist::Dictionary;
pub use relay::RelayConfig;
pub use util::get_gateways_for_mccmnc;


pub struct RegisterMeta {
    pub hardware_version: String,
    pub os_version: String,
    pub software_version: String,
}

pub struct DebugMeta {
    pub user_version: String,
    pub hardware_version: String,
    pub serial_number: String,
}

/// Genuine iPhone hardware identifiers required by the fmip `identityV5`
/// registration body. Sourced from the relay device (activation record +
/// MobileGestalt). See `findmy::fmip_register` and IDENTITYV5_PLAN.md Task 3.
///
/// Field values mirror the captured real body
/// (tools/findmy-capture/captures/quic-findmydeviced.log line 344), e.g.
/// `ecid`/`chip_id` are the pre-formatted `0x%llx` strings the wire uses.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FmipDeviceHardware {
    pub serial_number: String,
    /// IMEI ("355684070514858"). Omitted from the body if empty.
    pub imei: String,
    /// Second IMEI (dual-SIM). Omitted from the body if empty.
    pub imei2: String,
    /// MEID ("35568407051485"). Omitted from the body if empty.
    pub meid: String,
    /// ECID pre-formatted as `0x%llx` (e.g. "0x574c1208363ba").
    pub ecid: String,
    /// chipId pre-formatted as `0x%llx` (e.g. "0x8003").
    pub chip_id: String,
    /// Wi-Fi MAC ("1c:91:48:52:87:db").
    pub wifi_mac: String,
    /// Bluetooth MAC ("1c:91:48:52:87:dc").
    pub bt_mac: String,
}

/// Output of `FMDAbsintheV3SigningInterface signatureForData:` for an
/// identityV5 registration: the mandatory Sign1/2 pair plus the optional,
/// best-effort BAA Sign5/6 attestation headers.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FmipSignature {
    /// X-Mme-Sign1 (signatureHeader), base64.
    pub sign1: String,
    /// X-Mme-Sign2 (skAuthHeader), base64.
    pub sign2: String,
    /// X-Mme-Sign5 (baaAttestationHeader), base64. Optional.
    pub sign5: Option<String>,
    /// X-Mme-Sign6 (baaSignatureHeader), base64. Optional.
    pub sign6: Option<String>,
}

#[async_trait]
pub trait OSConfig: Sync + Send {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo;
    fn get_activation_device(&self) -> String;
    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError>;
    fn get_protocol_version(&self) -> u32;
    fn get_register_meta(&self) -> RegisterMeta;
    fn get_normal_ua(&self, item: &str) -> String;
    fn get_mme_clientinfo(&self, for_item: &str) -> String;
    fn get_version_ua(&self) -> String;
    fn get_device_name(&self) -> String;
    fn get_device_uuid(&self) -> String;
    fn get_private_data(&self) -> Dictionary;
    fn get_debug_meta(&self) -> DebugMeta;
    fn get_login_url(&self) -> &'static str;
    fn get_serial_number(&self) -> String;
    fn get_gsa_hardware_headers(&self) -> HashMap<String, String>;
    fn get_aoskit_version(&self) -> String;
    fn get_udid(&self) -> String;

    /// Returns the real hardware UDID (e.g. the relay device's actual Apple UDID).
    /// Defaults to get_udid() but relay overrides to return version.unique_device_id.
    fn get_hardware_udid(&self) -> String {
        self.get_udid()
    }

    /// fmip identityV5 device-hardware descriptor, read from the underlying device.
    ///
    /// These are the genuine iPhone hardware identifiers the fmip `identityV5`
    /// registration requires (imei/meid/ecid/chipId/wifi+bt MAC). They are only
    /// available on a real activated iPhone (the relay), so the default returns
    /// `None` and the identityV5 path is a no-op for non-relay configs.
    ///
    /// See `findmy::fmip_register` and IDENTITYV5_PLAN.md Task 3.
    fn get_fmip_device_hardware(&self) -> Option<FmipDeviceHardware> {
        None
    }

    /// Fetch the MobileActivation PCRT token (`ifcReceipt`) from the device.
    ///
    /// PROVEN static/reusable per device (see SESSION_..._FINDINGS 2026-07-16). On
    /// the relay this maps to a bridge call to `_MAECopyPCRTToken`. Standalone-safe.
    /// Default: unsupported (only the relay can produce a genuine token).
    async fn get_fmip_pcrt_token(&self) -> Result<String, PushError> {
        Err(PushError::FmipBridgeUnsupported)
    }

    /// Produce the identityV5 request signature via the device's
    /// `FMDAbsintheV3SigningInterface signatureForData:` (Cadmium/PSC-bound).
    ///
    /// `digest` is SHA256(authHeaderValue || bodyJSON); `request_uuid` is the
    /// X-Apple-AL-ID value. Returns the Sign1/2 pair (+ optional BAA Sign5/6).
    /// This is the ONE gate that must run inside findmydeviced context on the
    /// relay (see IDENTITYV5_PLAN.md §Task 2 correction). Default: unsupported.
    async fn get_fmip_signature(&self, _digest: &[u8], _request_uuid: &str) -> Result<FmipSignature, PushError> {
        Err(PushError::FmipBridgeUnsupported)
    }

    fn get_adi_mme_info(&self, for_item: &str, require_mac: bool) -> String {
        self.get_mme_clientinfo(for_item)
    }

    fn get_gsa_config(&self, push: &APSState, require_mac: bool) -> LoginClientInfo {
        LoginClientInfo {
            ak_context_type: "imessage".to_string(),
            client_app_name: "Messages".to_string(),
            client_bundle_id: "com.apple.MobileSMS".to_string(),
            mme_client_info_akd: self.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.akd/1.0)", require_mac),
            mme_client_info: self.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)", require_mac),
            akd_user_agent: "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0".to_string(),
            browser_user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string(),
            hardware_headers: self.get_gsa_hardware_headers(),
            push_token: push.token.map(|i| encode_hex(&i).to_uppercase()),
            update_account_bundle_id: self.get_adi_mme_info("com.apple.AppleAccount/1.0 (com.apple.systempreferences.AppleIDSettings/1)", require_mac),
        }
    }
}

extern crate pretty_env_logger;
extern crate log;

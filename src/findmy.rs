use std::{collections::HashMap, str::FromStr, sync::{Arc, atomic::{AtomicI64, Ordering}}, time::{Duration, SystemTime, UNIX_EPOCH}, u8};

use aes::{cipher::consts::U16, Aes128, Aes256};
use aes_gcm::{Aes256Gcm, AesGcm, Nonce, Tag, aead::{Aead, AeadMutInPlace}};
use chrono::{DateTime, NaiveTime, Utc};
use cloudkit_derive::CloudKitRecord;
use deku::{DekuContainerRead, DekuRead};
use hkdf::Hkdf;
use keystore::{AesKeystoreKey, EncryptMode, KeystoreAccessRules, KeystoreEncryptKey};
use openssl::{bn::{BigNum, BigNumContext}, derive::Deriver, ec::{EcGroup, EcKey, EcPoint}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, sha::sha256, sign::{Signer, Verifier}};
use sha2::Sha256;
use icloud_auth::AppleAccount;
use log::{debug, warn};
use omnisette::{AnisetteClient, AnisetteError, AnisetteHeaders, AnisetteProvider, ArcAnisetteClient};
use plist::{Data, Dictionary, Value};
use rand::Rng;
use reqwest::{Request, header::{HeaderMap, HeaderName, HeaderValue}};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use tokio::sync::{Mutex, broadcast};
use aes_gcm::KeyInit;
use uuid::Uuid;
use crate::{CompactECKey, cloudkit::{DeleteRecordOperation, SaveRecordOperation, should_reset}, ids::user::QueryOptions, util::{DebugMutex, base64_decode, base64_encode, bin_deserialize, bin_deserialize_opt_vec, bin_serialize, bin_serialize_opt_vec, decode_hex, plist_to_bin}};
use crate::{aps::APSInterestToken, auth::{MobileMeDelegateResponse, TokenProvider}, cloudkit::{pcs_keys_for_record, record_identifier, CloudKitClient, CloudKitContainer, CloudKitOpenContainer, CloudKitSession, FetchRecordChangesOperation, FetchRecordOperation, ALL_ASSETS, NO_ASSETS}, ids::{identity_manager::{DeliveryHandle, IDSSendMessage, IdentityManager, MessageTarget, Raw}, user::IDSService, IDSRecvMessage}, keychain::{derive_key_into, KeychainClient}, login_apple_delegates, pcs::PCSService, util::{duration_since_epoch, encode_hex, REQWEST}, APSConnection, APSMessage, LoginDelegate, OSConfig, PushError};

pub mod fmip_register;

pub const MULTIPLEX_SERVICE: IDSService = IDSService {
    name: "com.apple.private.alloy.multiplex1",
    sub_services: &[
        "com.apple.private.alloy.fmf",
        "com.apple.private.alloy.fmd",
        "com.apple.private.alloy.status.keysharing",
        "com.apple.private.alloy.status.personal",
        "com.apple.private.alloy.findmy.itemsharing-crossaccount",
        "com.apple.private.alloy.kcsharing.invite",
    ],
    client_data: &[
        ("supports-fmd-v2", Value::Boolean(true)),
        ("supports-incoming-fmd-v1", Value::Boolean(true)),
        ("supports-findmy-plugin-messages", Value::Boolean(true)),
        ("supports-beacon-sharing-v3", Value::Boolean(true)),
        ("supports-beacon-sharing-v2", Value::Boolean(true)),
        // Required so friends' devices recognize us as a valid secure-locations target and
        // deliver the inbound secureLocationsKeyUpdate (T:10). The outbound T:10 is sent with
        // IDSSendMessageOptionRequireAllRegistrationProperties = {("supports-secure-loc-v1")},
        // so without advertising this our handle is silently skipped as a delivery target and
        // friend_secure_keys never gets populated. (Real iOS devices advertise this — confirmed
        // present 53x in friends' delivery-data lookups in the device log.)
        ("supports-secure-loc-v1", Value::Boolean(true)),
    ],
    flags: 1,
    capabilities_name: "com.apple.private.alloy"
};

/// Minimum interval between *automatic* `publish_secure_location` triggers,
/// in milliseconds. The manual UI button (testPublishSecureLocation) bypasses
/// this — it calls `publish_secure_location` directly, not via the trigger
/// sites that consult this gate.
///
/// Real iOS publishes "shallow" locations every few minutes; we land at 5 min
/// to be conservative without being so slow that the user can't see updates
/// land within a reasonable test session. INVESTIGATION.md §25 saw repeated
/// submits get 428 ACL Check Failed (suspected rate-limit / anti-replay), so
/// the minimum exists primarily to avoid hammering Apple while the protocol
/// is still being characterized.
const FMF_AUTO_PUBLISH_MIN_INTERVAL_MS: i64 = 5 * 60 * 1000;

/// Last automatic `publish_secure_location` timestamp (Unix ms). 0 = never.
/// Module-level so both `sync_item_positions` and `refresh_background_following`
/// (in the FFI crate) share the same gate.
static FMF_LAST_AUTO_PUBLISH_MS: AtomicI64 = AtomicI64::new(0);

/// Returns true if enough time has elapsed since the last successful auto-publish
/// for another one to fire. On `true`, atomically updates the timestamp so that
/// concurrent triggers don't both pass through.
///
/// Designed to be called *only* from the autonomous trigger sites
/// (`sync_item_positions`, `refresh_background_following`). Manual / UI publishes
/// should not consult this gate.
pub fn fmf_auto_publish_should_fire() -> bool {
    let now_ms = duration_since_epoch().as_millis() as i64;
    let last = FMF_LAST_AUTO_PUBLISH_MS.load(Ordering::Relaxed);
    if last != 0 && now_ms.saturating_sub(last) < FMF_AUTO_PUBLISH_MIN_INTERVAL_MS {
        return false;
    }
    // Try to claim the slot. If a concurrent caller beat us to it, back off.
    FMF_LAST_AUTO_PUBLISH_MS
        .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
}

/// Minimum interval between *keyless* subscribe attempts for a SINGLE friend, in
/// milliseconds. The keyed pull (friends we already hold a key for) is NOT gated —
/// it runs every fetch cycle so locations stay fresh.
///
/// A keyless subscribe ("ids":[] for a friend we have no key for) is only the
/// trigger that asks Apple to push `distributeKeys` to that publisher; once we hold
/// their key the keyless path is no longer used for them. Running it every 5s for
/// every unkeyed friend would hammer Apple needlessly, so each unkeyed friend is
/// throttled to one keyless subscribe per this interval. ~30s balances "key arrives
/// quickly after the map opens" against request volume, and is robust to the ~10%
/// of cycles where MME refresh fails (a once-on-open trigger would miss those).
const FMF_SUBSCRIBE_MIN_INTERVAL_MS: i64 = 30 * 1000;

/// Per-friend (keyed by findMyId / Follow.id) last keyless-subscribe timestamp in
/// Unix ms. Module-level so the gate persists across `fetch_locations` calls.
static FMF_LAST_SUBSCRIBE_MS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, i64>>> =
    std::sync::OnceLock::new();

/// Returns true if a keyless subscribe should fire for `fm_id` now (enough time has
/// elapsed since its last keyless subscribe). On `true`, records `now` as the new
/// last-subscribe time for that friend so the next cycle within the window is gated.
fn fmf_subscribe_should_fire(fm_id: &str) -> bool {
    let now_ms = duration_since_epoch().as_millis() as i64;
    let map = FMF_LAST_SUBSCRIBE_MS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut guard = match map.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let last = guard.get(fm_id).copied().unwrap_or(0);
    if last != 0 && now_ms.saturating_sub(last) < FMF_SUBSCRIBE_MIN_INTERVAL_MS {
        return false;
    }
    guard.insert(fm_id.to_string(), now_ms);
    true
}

#[derive(Deserialize, Serialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BeaconAttributes {
    pub name: String,
    pub role_id: i64,
    pub emoji: String,
    pub system_version: String,
    pub serial_number: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SharedBeaconClient {
    start_date: u64,
    pub attributes: BeaconAttributes,

    pub last_report: Option<LocationReport>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FindMyShareState {
    pub peer_trust: HashMap<String, OwnerPeerTrust>,
    pub peer_trust_member: HashMap<String, MemberPeerTrust>,
    pub circles: HashMap<String, OwnerSharingCircle>,
    pub circles_member: HashMap<String, MemberSharingCircle>,
    pub secrets: HashMap<String, SharingCircleSecret>,
    pub shared_beacons: HashMap<String, SharedBeaconRecord>,
    pub tags: HashMap<String, String>,
    pub shared_beacons_client: HashMap<String, SharedBeaconClient>,
}

impl FindMyShareState {
    async fn send_circle_message(&self, circle_id: &str, identity: &IdentityManager, msg: ItemSharingMessage) -> Result<(), PushError> {
        let circle = self.circles_member.get(circle_id).ok_or(PushError::CircleNotFound(circle_id.to_string()))?;

        let topic = "com.apple.private.alloy.findmy.itemsharing-crossaccount";

        let handle = identity.get_handles().await.remove(0);
        let peer_trust = self.peer_trust_member.get(&circle.owner).expect("Member not found!");
        let target = plist::from_bytes::<CommunicationId>(&peer_trust.communications_identifier)?.ids.destination.destination;
        identity.cache_keys(
            topic,
            &[target.clone()],
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true }
        ).await?;
        let targets = identity.cache.lock().await.get_participants_targets(&topic, &handle, &[target.clone()]);
        identity.send_message(topic, IDSSendMessage {
            sender: handle,
            raw: Raw::Body(plist_to_bin(&msg)?),
            send_delivered: false,
            command: 242,
            no_response: true,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                // wants App Ack
                ("wA".to_string(), Value::Boolean(true))
            ]),
        }, targets).await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct FindMyState {
    pub dsid: String,
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    state_token: Option<Vec<u8>>,
    #[serde(default)]
    pub accessories: HashMap<String, BeaconAccessory>,
    #[serde(default)]
    pub share_state: FindMyShareState,
    /// Publisher's P-224 private key scalar (28 bytes) for secure location sharing.
    /// Generated once on first access, persisted across sessions.
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    pub secure_locations_private_key: Option<Vec<u8>>,
    /// Publisher's P-224 public key (57 bytes, uncompressed SEC1: 0x04 || x || y).
    /// Paired with secure_locations_private_key above.
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    pub secure_locations_public_key: Option<Vec<u8>>,
    /// AES-256 symmetric key (32 bytes) that friends use to decrypt our published locations.
    /// Shared with friends via MappingPacket.
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    pub secure_locations_shared_secret: Option<Vec<u8>>,
    /// Per-friend key material received from inbound MappingPackets.
    /// Key: friend's IDS handle (e.g. "tel:+1234567890" or sender from IDS message)
    /// Value: FriendSecureLocationKeys containing their pubkey + shared secret
    #[serde(default)]
    pub friend_secure_keys: HashMap<String, FriendSecureLocationKeys>,
}

/// Key material for decrypting a FRIEND's published secure locations.
///
/// Received from an inbound `secureLocationsKeyUpdate` (T:10) IDS message that the
/// friend sends us when they share their location. The friend hands us THEIR OWN
/// private key so we can fetch + decrypt the locations they publish under their key_id.
/// (Proven from keyupdate-capture2.log — see SESSION_2026_06_12_RECEIVE_FINDINGS.md.)
#[derive(Serialize, Deserialize, Clone)]
pub struct FriendSecureLocationKeys {
    /// Friend's P-224 private key scalar (28 bytes) — handed to us in their key update.
    /// This is what we decrypt their location blobs with.
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub private_key: Vec<u8>,
    /// Friend's P-224 public key (57 bytes, uncompressed SEC1: 0x04 || x || y).
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub public_key: Vec<u8>,
    /// Friend's AES-256 shared secret (32 bytes) — legacy/vestigial under the ECIES model.
    /// Kept for serialization compatibility; not used for ECIES decrypt.
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize", default)]
    pub shared_secret: Vec<u8>,
    /// Friend's findMyId (= base64(their DSID) = their Follow.id). Used to map decrypted
    /// locations back to the correct friend.
    #[serde(default)]
    pub find_my_id: String,
}

impl FindMyState {
    pub fn new(dsid: String) -> FindMyState {
        FindMyState {
            dsid,
            state_token: None,
            accessories: Default::default(),
            share_state: Default::default(),
            secure_locations_private_key: None,
            secure_locations_public_key: None,
            secure_locations_shared_secret: None,
            friend_secure_keys: Default::default(),
        }
    }

    /// Returns (private_key[28], public_key[57], shared_secret[32]).
    /// Generates once on first call, then persists in state. Caller must save
    /// the state after this returns if it generated new keys.
    pub fn get_or_generate_secure_location_keys(&mut self) -> Result<([u8; 28], [u8; 57], [u8; 32]), PushError> {
        if let (Some(priv_key), Some(pub_key), Some(shared)) = (
            &self.secure_locations_private_key,
            &self.secure_locations_public_key,
            &self.secure_locations_shared_secret,
        ) {
            info!("[FMF-MAPPING] Using existing persisted secure location keys");
            let priv_arr: [u8; 28] = priv_key.clone().try_into()
                .map_err(|_| PushError::KeyedArchiveError("persisted private key not 28 bytes".to_string()))?;
            let pub_arr: [u8; 57] = pub_key.clone().try_into()
                .map_err(|_| PushError::KeyedArchiveError("persisted public key not 57 bytes".to_string()))?;
            let secret_arr: [u8; 32] = shared.clone().try_into()
                .map_err(|_| PushError::KeyedArchiveError("persisted shared secret not 32 bytes".to_string()))?;
            return Ok((priv_arr, pub_arr, secret_arr));
        }

        info!("[FMF-MAPPING] Generating new P-224 keypair + shared secret for secure locations");

        // Generate P-224 keypair
        let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
        let keypair = EcKey::generate(&group)?;
        keypair.check_key()?;

        // Extract private scalar (28 bytes)
        let priv_bytes = keypair.private_key().to_vec_padded(28)
            .map_err(|e| PushError::KeyedArchiveError(format!("Failed to export P-224 private key: {}", e)))?;
        assert_eq!(priv_bytes.len(), 28);

        // Extract public key as uncompressed SEC1 (04 || x || y = 57 bytes)
        let mut ctx = BigNumContext::new()?;
        let pub_bytes = keypair.public_key()
            .to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        assert_eq!(pub_bytes.len(), 57);

        // Generate random 32-byte AES-256 shared secret
        let shared_secret: [u8; 32] = rand::thread_rng().gen();

        info!("[FMF-MAPPING]   Generated pubkey (first 8): {}", encode_hex(&pub_bytes[..8]));
        info!("[FMF-MAPPING]   Generated shared_secret (first 8): {}", encode_hex(&shared_secret[..8]));

        let priv_arr: [u8; 28] = priv_bytes.clone().try_into().unwrap();
        let pub_arr: [u8; 57] = pub_bytes.clone().try_into().unwrap();

        // Persist in state
        self.secure_locations_private_key = Some(priv_bytes);
        self.secure_locations_public_key = Some(pub_bytes);
        self.secure_locations_shared_secret = Some(shared_secret.to_vec());

        Ok((priv_arr, pub_arr, shared_secret))
    }

    pub fn encode(&self) -> Result<Vec<u8>, PushError> {
        let findmy_key = AesKeystoreKey::ensure("findmy:state-key", 256, KeystoreAccessRules {
            block_modes: vec![EncryptMode::Gcm],
            can_encrypt: true,
            can_decrypt: true,
            ..Default::default()
        })?;
        let result = findmy_key.encrypt(&plist_to_bin(self)?, &mut EncryptMode::Gcm)?;
        Ok(result)
    }

    pub fn restore(data: &[u8]) -> Result<Self, PushError> {
        let findmy_key = AesKeystoreKey::ensure("findmy:state-key", 256, KeystoreAccessRules {
            block_modes: vec![EncryptMode::Gcm],
            can_encrypt: true,
            can_decrypt: true,
            ..Default::default()
        })?;
        Ok(plist::from_bytes(&findmy_key.decrypt(data, &EncryptMode::Gcm)?)?)
    }
}

pub struct FindMyStateManager {
    pub state: DebugMutex<FindMyState>,
    pub update: Box<dyn Fn(Vec<u8>) + Send + Sync>,
}

impl FindMyStateManager {
    

    pub fn new(data: &[u8], update: Box<dyn Fn(Vec<u8>) + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            state: DebugMutex::new(FindMyState::restore(data).expect("Failed to restore!")),
            update
        })
    }

    

    pub fn save(&self, state: &FindMyState) -> Result<(), PushError> {
        (self.update)(state.encode()?);
        Ok(())
    }
}

async fn get_find_my_headers<T: AnisetteProvider>(config: &dyn OSConfig, api_ver: &str, anisette: &mut AnisetteClient<T>, ua: &str) -> Result<HeaderMap, PushError> {
    let mut map = HeaderMap::new();
    map.insert("User-Agent", config.get_normal_ua(ua).parse().unwrap());
    map.insert("X-Apple-Realm-Support", "1.0".parse().unwrap());
    map.insert("X-Apple-AuthScheme", "Forever".parse().unwrap());
    // X-FMF-Model-Version
    map.insert("X-Apple-Find-API-Ver", api_ver.parse().unwrap());
    map.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
    map.insert("Accept", "application/json".parse().unwrap());
    map.insert("X-Apple-I-Locale", "en_US".parse().unwrap());

    let mut base_headers = anisette.get_headers().await?.clone();

    base_headers.insert("X-Mme-Client-Info".to_string(), config.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.findmy/375.20)", !base_headers["X-Mme-Client-Info"].contains("iPhone OS")));

    map.extend(base_headers.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())));

    Ok(map)
}

#[derive(Deserialize)]
#[serde(tag = "kFMFServicePayloadKey", rename_all = "camelCase")]
enum FMFPayload {
    MappingPacket {
        p: String
    }
}

pub struct FindMyClient<P: AnisetteProvider> {
    pub conn: APSConnection,
    pub identity: IdentityManager,
    _interest_token: APSInterestToken,
    pub daemon: DebugMutex<FindMyFriendsClient<P>>,
    config: Arc<dyn OSConfig>,
    pub state: Arc<FindMyStateManager>,
    pub container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    pub client: Arc<CloudKitClient<P>>,
    pub keychain: Arc<KeychainClient<P>>,
    token_provider: Arc<TokenProvider<P>>,
    anisette: ArcAnisetteClient<P>,
}

const SEARCH_PARTY_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: cloudkit_proto::request_operation::header::Database::PrivateDb,
    bundleid: "com.apple.icloud.searchpartyd",
    containerid: "com.apple.icloud.searchparty",
    env: cloudkit_proto::request_operation::header::ContainerEnvironment::Production,
};

use log::info;
use log::error;
use cloudkit_proto::{request_operation::header::IsolationLevel, CloudKitEncryptor, CloudKitRecord};
use crate::cloudkit_proto::RecordIdentifier;

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "OwnerPeerTrust", encrypted, rename_all = "camelCase")]
pub struct OwnerPeerTrust {
    display_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    communications_identifier: Vec<u8>,
    state: i64,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    peer_trust_shared_secret: Vec<u8>,
    peer_trust_type: i64,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "MemberPeerTrust", encrypted, rename_all = "camelCase")]
pub struct MemberPeerTrust {
    display_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    communications_identifier: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    peer_trust_shared_secret: Vec<u8>,
    peer_trust_type: i64,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "OwnerSharingCircle", encrypted, rename_all = "camelCase")]
pub struct OwnerSharingCircle {
    sharing_circle_type: i64,
    acceptance_state: i64,
    beacon_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    members: Vec<u8>,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "MemberSharingCircle", encrypted, rename_all = "camelCase")]
pub struct MemberSharingCircle {
    owner: String,
    pub sharing_circle_identifier: String,
    pub acceptance_state: i64,
    pub beacon_identifier: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    members: Vec<u8>,
}

impl MemberSharingCircle {
    fn get_members(&self) -> Vec<String> {
        let parsed: Vec<Value> = plist::from_bytes(&self.members).expect("no member list??");
        parsed.into_iter().filter_map(|a| a.into_string()).collect()
    }
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "SharingCircleSecret", encrypted, rename_all = "camelCase")]
pub struct SharingCircleSecret {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    secret_data: Vec<u8>,
    sharing_circle_identifier: String,
    pub secret_type: String,
}

impl SharingCircleSecret {
    pub fn circle_shared_secret(&self) -> Option<CircleSecretKey> {
        if self.secret_type.as_str() == "circleSharedSecret" {
            Some(CircleSecretKey(self.secret_data.clone()))
        } else { None }
    }

    pub fn wild_root_key(&self) -> Option<WildRootKey> {
        if self.secret_type.as_str() == "circleWildRootKey" {
            Some(WildRootKey(self.secret_data.clone()))
        } else { None }
    }

    pub fn join_token(&self) -> Option<DecodedCircleJoinToken> {
        if self.secret_type.as_str() == "joinToken" {
            plist::from_bytes(&self.secret_data).ok()
        } else { None }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NearOwnerLocationKey {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DecodedCircleJoinToken {
    #[serde(rename = "memberUUID")]
    pub member_uuid: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub private_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ItemSharingMessage {
    #[serde(rename = "T")]
    r#type: u32,
    #[serde(rename = "V")]
    version: u32,
    #[serde(rename = "P")]
    payload: Data,
}

impl ItemSharingMessage {
    fn new(msg: &impl Serialize, r#type: u32) -> Self {
        Self {
            r#type,
            version: 1,
            payload: plist_to_bin(msg).expect("Failed to serialize msg!").into(),
        }
    }
}

impl DecodedCircleJoinToken {
    pub fn key(&self) -> CompactECKey<Private> {
        CompactECKey::decompress_private_small(self.private_key.clone().try_into().unwrap())
    }

    pub fn member_token(&self) -> Vec<u8> {
        [vec![0x02], self.key().compress().to_vec()].concat()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WildRootKey(Vec<u8>);

impl WildRootKey {
    pub fn idx(&self, idx: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut recv_send = [0u8; 32];
        hk.expand(idx.to_string().as_bytes(), &mut recv_send).expect("Failed to expand key!");
        recv_send
    }

    pub fn get_bundle_data(&self, idx: u64) -> serde_json::Value {
        json!({
            "startIndex": (idx - 1) * 96,
            "endIndex": (idx * 96) - 1,
            "bundleIndex": idx,
            "bundleDecryptionKey": base64_encode(&self.idx(idx)),
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CircleSecretKey(Vec<u8>);

impl CircleSecretKey {
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PushError> {
        let decoded: Vec<Data> = plist::from_bytes(ciphertext)?;

        let mut cipher = Aes256Gcm::new_from_slice(&self.0).unwrap();
        let mut data = decoded[2].as_ref().to_vec();
        cipher.decrypt_in_place_detached(Nonce::from_slice(decoded[0].as_ref()), &[], &mut data, Tag::from_slice(decoded[1].as_ref())).unwrap();

        Ok(data)
    }
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "BeaconNamingRecord", encrypted, rename_all = "camelCase")]
pub struct BeaconNamingRecord {
    pub emoji: String,
    pub name: String,
    pub associated_beacon: String,
    pub role_id: i64,
}

#[derive(Deserialize, Debug)]
pub struct MiscData {
    data: Data,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "MasterBeaconRecord", encrypted, rename_all = "camelCase")]
pub struct MasterBeaconRecord {
    pub product_id: i64,
    pub stable_identifier: String,
    pub pairing_date: Option<SystemTime>, // option for default
    pub battery_level: i64,
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    pub shared_secret_2: Option<Vec<u8>>,
    #[serde(serialize_with = "bin_serialize_opt_vec", deserialize_with = "bin_deserialize_opt_vec", default)]
    pub secure_locations_shared_secret: Option<Vec<u8>>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub private_key: Vec<u8>,
    pub system_version: String,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub shared_secret: Vec<u8>,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub public_key: Vec<u8>,
    pub model: String,
    pub vendor_id: i64,
    pub is_zeus: i64,
}

#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "SharedBeaconRecord", encrypted, rename_all = "camelCase")]
pub struct SharedBeaconRecord {
    pub product_id: i64,
    pub accepted: i64,
    pub owner_handle: String,
    pub share_type: i64,
    pub correlation_identifier: String,
    // DO NOT RELY ON, THIS IS NOT RELIABLE
    pub share_identifier: String,
    pub advertised_index: i64,
    pub system_version: String,
    pub role: i64,
    pub share_date: Option<SystemTime>,
    pub model: String,
    pub vendor_id: i64,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    pub name: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UnifiedData {
    Base64(String),
    Data(Data),
}

impl UnifiedData {
    fn get_data(&self) -> Vec<u8> {
        match self {
            Self::Base64(b) => base64_decode(b),
            Self::Data(d) => d.clone().into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UnifiedTimestamp {
    Date(plist::Date),
    MsSinceEpoch(u64),
}

impl UnifiedTimestamp {
    fn get_ms_since_epoch(&self) -> u64 {
        match self {
            Self::Date(d) => {
                let time: SystemTime = (*d).into();
                time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64
            },
            Self::MsSinceEpoch(e) => *e,
        }
    }
}

// NOTE: this key package serialization handles both JSON and PLIST. Serde is great, but be careful!
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageAlignment {
    base_date: UnifiedTimestamp,
    last_observed_date: UnifiedTimestamp,
    last_observed_index: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageKey {
    index: u32,
    key: UnifiedData,
}

impl KeyPackageKey {
    fn decrypt(&self, secret: &CircleSecretKey) -> Result<Vec<u8>, PushError> {
        secret.decrypt(&self.key.get_data())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackage {
    keys: Vec<KeyPackageKey>,
    r#type: String,
    alignment: KeyPackageAlignment,
    range_end: Option<u64>,
}

#[derive(Deserialize, Debug)]
pub struct IDSTrustedPeerSharedSecret {
    key: MiscData,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct IDSTrustedPeer {
    identifier: String,
    display_identifier: String,
    shared_secret: IDSTrustedPeerSharedSecret
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct IDSSharedItem {
    share_identifier: String,
    beacon_identifier: String,
    owner_beacon_identifier: Option<String>,
    model: String,
    system_version: String,
    vendor_id: i64,
    product_id: i64,
    beacon_name: String,
    role: i64,
    emoji: String,
    key_packages: Data,
    share_type: i64,
    trusted_peers: Vec<IDSTrustedPeer>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareIdObject {
    share_identifier: String
}


#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommunicationIdIdsDestination {
    r#type: u32,
    destination: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommunicationIdIds {
    destination: CommunicationIdIdsDestination,
    correlation_identifier: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommunicationId {
    ids: CommunicationIdIds
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BeaconRatchet {
    index: usize,
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize")]
    secret: Vec<u8>,
}

impl BeaconRatchet {
    fn new(secret: Vec<u8>) -> Self {
        Self {
            index: 0,
            secret,
        }
    }

    fn ratchet(&self) -> Self {
        let mut secret = vec![0u8; self.secret.len()];
        derive_key_into::<Sha256>(&self.secret, b"update", &mut secret);
        Self {
            secret,
            index: self.index + 1,
        }
    }
    
    fn seek(&self, idx: usize, original: &[u8]) -> Self {
        let mut ratchet = self.clone();
        if idx < ratchet.index { 
            ratchet = Self::new(original.to_vec());
        }
        while ratchet.index < idx {
            ratchet = ratchet.ratchet();
        }
        ratchet
    }

    fn window(&self, count: usize) -> Vec<BeaconRatchet> {
        let mut ratchets = vec![self.clone()];
        for _i in 0..count {
            ratchets.push(ratchets.last().unwrap().ratchet());
        }
        ratchets
    }
}

pub fn count_4am_between_dt(start: DateTime<Utc>, end: DateTime<Utc>) -> u64 {
    if end <= start {
        return 0;
    }

    // 04:00:00 time-of-day
    let four = NaiveTime::from_hms_opt(4, 0, 0).unwrap();

    // 04:00 on the start's calendar day (UTC)
    let mut first = start.date_naive().and_time(four).and_utc();

    // We want the first 04:00 strictly AFTER `start`
    if first <= start {
        first = first + chrono::Duration::days(1);
    }

    if end < first {
        0
    } else {
        (end - first).num_days() as u64 + 1
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BeaconAccessory {
    pub master_record: MasterBeaconRecord,
    pub naming: BeaconNamingRecord,
    pub naming_id: String,
    pub naming_prot_tag: Option<String>,
    pub alignment: KeyAlignmentRecord,
    pub alignment_id: String,
    pub aligment_prot_tag: Option<String>,

    // not in cloudkit
    pub local_alignment: KeyAlignmentRecord,


    pub last_report: Option<LocationReport>,

    pub primary_ratchet: BeaconRatchet,
    pub secondary_ratchet: BeaconRatchet,
}

impl BeaconAccessory {
    fn new(
        master_record: MasterBeaconRecord,
        naming: (String, Option<String>, BeaconNamingRecord),
        alignment: (String, Option<String>, KeyAlignmentRecord),
    ) -> Self {
        Self {
            primary_ratchet: BeaconRatchet::new(master_record.shared_secret.clone()),
            secondary_ratchet: BeaconRatchet::new(master_record.shared_secret_2.clone().unwrap_or_else(|| master_record.secure_locations_shared_secret.clone().unwrap())),

            last_report: None,

            master_record,
            naming: naming.2,
            naming_prot_tag: naming.1,
            naming_id: naming.0,
            alignment: alignment.2.clone(),
            aligment_prot_tag: alignment.1,
            alignment_id: alignment.0,

            local_alignment: alignment.2,
        }
    }

    fn derive_ps_key(&self, key: &[u8]) -> Result<EcKey<Private>, PushError> {
        let mut secret = vec![0u8; 72];
        derive_key_into::<Sha256>(key, b"diversify", &mut secret);

        let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
        let mut n = BigNum::new()?;
        let mut ctx = BigNumContext::new()?;
        group.order(&mut n, &mut ctx)?;

        let mut n1 = n.to_owned()?;
        n1.sub_word(1)?;

        let mut ctx = BigNumContext::new()?;
        let u = BigNum::from_slice(&secret[..36])?;
        let mut u1 = BigNum::new()?;
        u1.nnmod(&u, &n1, &mut ctx)?;
        u1.add_word(1)?;

        let v = BigNum::from_slice(&secret[36..])?;
        let mut v1 = BigNum::new()?;
        v1.nnmod(&v, &n1, &mut ctx)?;
        v1.add_word(1)?;

        let private_number = BigNum::from_slice(&self.master_record.private_key[self.master_record.private_key.len() - 28..])?;
        let mut i1 = BigNum::new()?;
        i1.mod_mul(&u1, &private_number, &n, &mut ctx)?;
        let mut result = BigNum::new()?;
        result.mod_add(&i1, &v1, &n, &mut ctx)?;

        let mut pub_point = EcPoint::new(&group)?;
        pub_point.mul_generator(&group, &result, &mut ctx)?;

        Ok(EcKey::from_private_components(&group, &result, &pub_point)?)
    }

    fn get_current(&mut self) -> Result<Vec<(usize, EcKey<Private>)>, PushError> {
        let mut primary = self.get_current_primary();
        primary.extend(self.get_current_secondary());
        primary.into_iter().map(|i| Ok((i.index, self.derive_ps_key(&i.secret)?))).collect()
    }

    fn get_current_primary(&mut self) -> Vec<BeaconRatchet> {
        // how long has it been since we last saw them?
        let time_since_last_seen = SystemTime::now().duration_since(self.local_alignment.last_index_observation_date.unwrap()).unwrap_or(Duration::ZERO);
        
        // keys refresh every 15 mins
        let slots_elapsed = time_since_last_seen.as_secs() / (60 * 15);

        // we want to query most recent (up to) (4 (per hour) * 24 * 7) + (12 * 4) = 720 keys since then, to see if anyone has seen this in the last week + 12 hours
        const LOOKAHEAD_TIME: u64 = 48; // 12 hours
        const LOOKBACK_TIME: u64 = 720; // week + 12 hours
        let seek_slots = slots_elapsed.saturating_sub(LOOKBACK_TIME);

        let start_slot = (self.local_alignment.last_index_observed as u64) + seek_slots;
        self.primary_ratchet = self.primary_ratchet.seek(start_slot as usize, &self.master_record.shared_secret);

        let slot_window = slots_elapsed - seek_slots + LOOKAHEAD_TIME;
        info!("primary range {}-{}", start_slot, slot_window + start_slot);
        self.primary_ratchet.window(slot_window as usize)
    }

    fn get_current_secondary(&mut self) -> Vec<BeaconRatchet> {
        let rotations = count_4am_between_dt(self.master_record.pairing_date.unwrap().into(), (SystemTime::now() + Duration::from_secs(60 * 60 * 12)).into());

        const LOOKAHEAD_TIME: u64 = 1;
        const LOOKBACK_TIME: u64 = 7; // week
        let seek_slots = rotations.saturating_sub(LOOKBACK_TIME);

        self.secondary_ratchet = self.secondary_ratchet.seek(seek_slots as usize, &self.master_record.shared_secret);

        let slot_window = rotations - seek_slots + LOOKAHEAD_TIME;
        info!("primary range {}-{}", seek_slots, slot_window + seek_slots);
        self.secondary_ratchet.window(slot_window as usize)
    }
}


#[derive(CloudKitRecord, Default, Debug, Serialize, Deserialize, Clone)]
#[cloudkit_record(type = "KeyAlignmentRecord", encrypted, rename_all = "camelCase")]
pub struct KeyAlignmentRecord {
    beacon_identifier: String,
    last_index_observed: i64,
    last_index_observation_date: Option<SystemTime>, // option for default
}

#[derive(DekuRead, Debug)]
#[deku(endian = "big")]
pub struct EncryptedReport {
    lat: i32, // multiplied by 10000000
    long: i32, // multiplied by 10000000
    horizontal_accuracy: u8,
    status: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocationReport {
    pub lat: f32,
    pub long: f32,
    pub horizontal_accuracy: u8,
    pub status: u8,
    pub confidence: u8,
    pub timestamp: SystemTime,
    pub key_index: usize,
}

#[derive(CloudKitRecord, Default, Debug)]
#[cloudkit_record(type = "LeashRecord", encrypted, rename_all = "camelCase")]
pub struct LeashRecord {
    associated_beacons: Vec<u8>,
}

const FIND_MY_SERVICE: PCSService = PCSService {
    name: "com.apple.icloud.searchparty",
    view_hint: "Manatee",
    zone: "Manatee",
    r#type: 82,
    keychain_type: 82,
    v2: true,
    global_record: false,
};

impl<P: AnisetteProvider> FindMyClient<P> {
    pub async fn new(conn: APSConnection, client: Arc<CloudKitClient<P>>, keychain: Arc<KeychainClient<P>>, config: Arc<dyn OSConfig>, state: Arc<FindMyStateManager>, token_provider: Arc<TokenProvider<P>>, anisette: ArcAnisetteClient<P>, identity: IdentityManager) -> Result<FindMyClient<P>, PushError> {
        let daemon = FindMyFriendsClient::new(config.as_ref(), state.state.lock().await.dsid.clone(), token_provider.clone(), conn.clone(), anisette.clone(), true).await?;
        Ok(FindMyClient {
            _interest_token: conn.request_topics(&["com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd", "com.apple.private.alloy.findmy.itemsharing-crossaccount", "com.apple.icloud.searchpartyd.securelocations"]).await,
            conn,
            identity,
            daemon: DebugMutex::new(daemon),
            config,
            state,
            container: Mutex::new(None),
            client,
            keychain,
            token_provider,
            anisette,
        })
    }

    pub async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone())
        }
        *locked = Some(Arc::new(SEARCH_PARTY_CONTAINER.init(self.client.clone()).await?));
        return Ok(locked.clone().unwrap())
    }

    pub async fn sync_items(&self, fetch_shares: bool) -> Result<(), PushError> {
        let container = self.get_container().await?;
        
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());

        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;


        let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
        let mut naming_records: HashMap<String, (String, Option<String>, BeaconNamingRecord)> = HashMap::new();
        let mut alignment_records: HashMap<String, (String, Option<String>, KeyAlignmentRecord)> = HashMap::new();

        let mut state = self.state.state.lock().await;

        let mut result = FetchRecordChangesOperation::do_sync(&container, &[(beacon_zone.clone(), state.state_token.clone())], &NO_ASSETS).await;
        if should_reset(result.as_ref().err()) {
            state.state_token = None;
            state.accessories.clear();
            state.share_state = Default::default();
            result = FetchRecordChangesOperation::do_sync(&container, &[(beacon_zone.clone(), state.state_token.clone())], &NO_ASSETS).await;
        }

        let (_, changes, continuation) = result?.remove(0);
        
        state.state_token = continuation.clone();

        let state = &mut *state;

        let accessories = &mut state.accessories;
        let circles = &mut state.share_state.circles;
        let circles_member = &mut state.share_state.circles_member;
        let peer_trust = &mut state.share_state.peer_trust;
        let peer_trust_member = &mut state.share_state.peer_trust_member;
        let secrets = &mut state.share_state.secrets;
        let shared_beacons = &mut state.share_state.shared_beacons;
        let tags = &mut state.share_state.tags;
        let shared_beacons_client = &mut state.share_state.shared_beacons_client;
        
        for change in changes {
            let identifier = change.identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();
            let Some(record) = change.record else {
                accessories.remove(&identifier);
                circles.remove(&identifier);
                peer_trust.remove(&identifier);
                secrets.remove(&identifier);
                shared_beacons.remove(&identifier);
                tags.remove(&identifier);
                circles_member.remove(&identifier);
                peer_trust_member.remove(&identifier);
                shared_beacons_client.remove(&identifier);
                continue
            };
            let Some(protection_info) = &record.protection_info else { continue };
            let protection_info_tag = protection_info.protection_info_tag().to_string();

            if record.r#type.as_ref().unwrap().name() == MasterBeaconRecord::record_type() {
                let item = MasterBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                info!("Got beacon {:?} {}", item, identifier);

                if let Some(accessory) = accessories.get_mut(&identifier) {
                    accessory.master_record = item;
                } else {
                    beacon_records.insert(identifier, item);
                }
            } else if record.r#type.as_ref().unwrap().name() == BeaconNamingRecord::record_type() {
                let item = BeaconNamingRecord::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                if let Some(accessory) = accessories.get_mut(&item.associated_beacon) {
                    accessory.naming = item;
                    accessory.naming_id = identifier;
                } else {
                    naming_records.insert(item.associated_beacon.clone(), (identifier, Some(protection_info_tag), item));
                }
            } else if record.r#type.as_ref().unwrap().name() == KeyAlignmentRecord::record_type() {
                let item = KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                if let Some(accessory) = accessories.get_mut(&item.beacon_identifier) {
                    accessory.alignment = item.clone();
                    accessory.local_alignment = item;
                    accessory.alignment_id = identifier;
                } else {
                    alignment_records.insert(item.beacon_identifier.clone(), (identifier, Some(protection_info_tag), item));
                }
            } else if record.r#type.as_ref().unwrap().name() == SharingCircleSecret::record_type() {
                let item = SharingCircleSecret::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                secrets.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == OwnerSharingCircle::record_type() {
                let item = OwnerSharingCircle::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                circles.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == OwnerPeerTrust::record_type() {
                let item = OwnerPeerTrust::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                peer_trust.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == MemberPeerTrust::record_type() {
                let item = MemberPeerTrust::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                peer_trust_member.insert(identifier, item);
            } else if record.r#type.as_ref().unwrap().name() == MemberSharingCircle::record_type() {
                let item = MemberSharingCircle::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                circles_member.insert(identifier.clone(), item);
                tags.insert(identifier, protection_info_tag);
            } else if record.r#type.as_ref().unwrap().name() == SharedBeaconRecord::record_type() {
                let item = SharedBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs_keys_for_record(&record, &key)?));

                shared_beacons.insert(identifier, item);
            } else {
                // Log unknown record types for discovery
                let record_type_name = record.r#type.as_ref().map(|t| t.name().to_string()).unwrap_or_else(|| "<unknown>".to_string());
                let field_names: Vec<String> = record.record_field.iter()
                    .map(|f| f.identifier.as_ref().map(|id| id.name.clone().unwrap_or_default()).unwrap_or_default())
                    .collect();
                info!("[FMF-BEACONSTORE] Unknown record type: '{}', id='{}', fields={:?}", 
                    record_type_name, identifier, field_names);
                continue
            }
        }

        for (id, record) in beacon_records {
            let Some(naming) = naming_records.remove(&id) else { continue };
            let last_index_observation_date = record.pairing_date;
            accessories.insert(id.clone(), BeaconAccessory::new(
                record,
                naming,
                alignment_records.remove(&id).unwrap_or((Uuid::new_v4().to_string().to_uppercase(), None, KeyAlignmentRecord { 
                    beacon_identifier: id.clone(), 
                    last_index_observed: 0, 
                    last_index_observation_date,
                })),
            ));
        }

        
        for (id, circle) in circles_member {
            // we haven't joined the circle yet
            if circle.acceptance_state != 1 || !fetch_shares { continue }

            let Some(join_key) = secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle.sharing_circle_identifier)
                .find_map(|(_, a)| a.join_token()) else { continue };

            let Some(shared_secret) = secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle.sharing_circle_identifier)
                .find_map(|(_, a)| a.circle_shared_secret()) else { continue };

            let key_packages = self.query_share(&state.dsid, &circle, &join_key).await?;

            let Some(primary) = key_packages.iter().find(|k| &k.r#type == "primaryAddress") else { continue };
            let Some(attributes) = key_packages.iter().find(|k| &k.r#type == "beaconAttributes") else { continue };
            
            let beacon_attrs: BeaconAttributes = plist::from_bytes(&attributes.keys[0].decrypt(&shared_secret)?)?;
            
            let item = shared_beacons_client.entry(circle.beacon_identifier.clone()).or_default();
            item.start_date = primary.alignment.base_date.get_ms_since_epoch();
            item.attributes = beacon_attrs;
        }

        self.state.save(&state)?;

        Ok(())
    }

    fn build_secrets(share: &str, secret_key: &CircleSecretKey, queried_packages: &[KeyPackage], existing: &HashMap<String, SharingCircleSecret>) -> Result<HashMap<String, SharingCircleSecret>, PushError> {
        let mut secrets = HashMap::new();
        
        if !existing.values().any(|e| &e.secret_type == "circleWildRootKey" && &e.sharing_circle_identifier == share) {
            if let Some(root_key) = queried_packages.iter().find(|k| &k.r#type == "circleWildRootKey") {
                let root_key = root_key.keys[0].decrypt(secret_key)?;
                secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                    secret_data: root_key,
                    sharing_circle_identifier: share.to_string(),
                    secret_type: "circleWildRootKey".to_string(),
                });
            }
        }
        
        if !existing.values().any(|e| &e.secret_type == "nearOwnerKey" && &e.sharing_circle_identifier == share) {
            if let Some(near_owner_key) = queried_packages.iter().find(|k| &k.r#type == "nearOwnerKey") {
                let near_owner_key = near_owner_key.keys[0].decrypt(secret_key)?;
                secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                    secret_data: near_owner_key,
                    sharing_circle_identifier: share.to_string(),
                    secret_type: "nearOwnerKey".to_string(),
                });
            }
        }

        Ok(secrets)
    }

    async fn query_share(&self, dsid: &str, circle: &MemberSharingCircle, join_key: &DecodedCircleJoinToken) -> Result<Vec<KeyPackage>, PushError> {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct ReturnedShare {
            key_packages: Vec<KeyPackage>,
        }

        let fetch_share: ReturnedShare = self.make_searchparty_request(dsid, "https://gateway.icloud.com/findmyservice/itemsharing/getShare", &json!({
            "timestamp": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis(),
            "type": "item",
            "shareId": &circle.sharing_circle_identifier,
            "memberId": &circle.owner,
            "packages": [
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "primaryAddress"
                },
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "beaconAttributes"
                },
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "circleWildRootKey"
                },
                {
                    "maxKeys": 300,
                    "startIndex": 0,
                    "metadata": false,
                    "type": "nearOwnerKey"
                },
            ]
        }), Some(join_key.key())).await?;

        Ok(fetch_share.key_packages)
    }

    pub async fn accept_item_share(&self, circle_id: &str) -> Result<(), PushError> {
        let mut item = self.state.state.lock().await;
        let item = &mut *item;


        let circle = item.share_state.circles_member.get(circle_id).ok_or(PushError::CircleNotFound(circle_id.to_string()))?;
        
        let Some(join_key) = item.share_state.secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle_id)
                .find_map(|(_, a)| a.join_token()) else { panic!("Circle not found!d") };
    
        let Some(secret_key) = item.share_state.secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == circle_id)
                .find_map(|(_, a)| a.circle_shared_secret()) else { panic!("Circle not found!de") };

        // make sure the share still exists before adding it
        let queried_packages = self.query_share(&item.dsid, &circle, &join_key).await?;

        item.share_state.secrets.extend(Self::build_secrets(circle_id, &secret_key, &queried_packages, &item.share_state.secrets)?);



        item.share_state.send_circle_message(circle_id, &self.identity, ItemSharingMessage::new(&vec![ShareIdObject {
            share_identifier: circle_id.to_string(),
        }], 4 /* accept */)).await?;


        let mut circle_modified = circle.clone();
        circle_modified.acceptance_state = 1;

        let container = self.get_container().await?;
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;
        let (op, id) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), circle_id), 
                    &circle_modified, &key, item.share_state.tags.get(circle_id).cloned());
        container.perform(&CloudKitSession::new(), op).await?;
        item.share_state.tags.insert(circle_id.to_string(), id);

        item.share_state.circles_member.insert(circle_id.to_string(), circle_modified);

        self.state.save(&item)?;

        Ok(())
    }

    pub async fn make_searchparty_request<T: DeserializeOwned + Default>(&self, dsid: &str, url: &str, body: &impl Serialize, sign_key: Option<CompactECKey<Private>>) -> Result<T, PushError> {
        let mut request = self.anisette.lock().await.get_headers().await?.clone();
        request.remove("X-Mme-Client-Info").unwrap();
        let mut anisette_headers: HeaderMap = request.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();

        let body = serde_json::to_string(&body)?;

        if let Some(sign_key) = sign_key {
            let mut my_signer = Signer::new(MessageDigest::sha256(), sign_key.get_pkey().as_ref())?;
            let data = my_signer.sign_oneshot_to_vec(body.as_bytes())?;
            anisette_headers.append("x-apple-share-auth", HeaderValue::from_str(&base64_encode(&data)).unwrap());
        }

        let token = self.token_provider.get_mme_token("searchPartyToken").await?;

        let description = REQWEST.post(url)
            .basic_auth(&format!("{}", dsid), Some(token))
            .headers(anisette_headers)
            .header("X-MMe-Client-Info", self.config.get_mme_clientinfo("com.apple.icloud.searchpartyuseragent/1.0"))
            .header("x-apple-setup-proxy-request", "true")
            .header("accept-version", "4")
            .header("user-agent", "searchpartyuseragent/1 iMac13,1/13.6.4")
            .header("x-apple-i-device-type", "1")
            .header("Content-Type", "application/json")
            .body(body)
            .send().await?
            .bytes().await?;

        if description.is_empty() {
            return Ok(Default::default())
        }

        Ok(serde_json::from_slice(&description)?)
    }

    /// Submit the device's own location to Apple's FindMy service.
    /// This publishes the location so friends who follow this user can see it.
    /// Uses the same endpoint and auth as beacon location fetching (`/findmyservice/v2/submit`).
    ///
    /// The location is encrypted using the device's beacon keys (same crypto as AirTag reports)
    /// and submitted to Apple's servers where followers can fetch and decrypt it.
    pub async fn submit_own_location(
        &self,
        latitude: f64,
        longitude: f64,
        altitude: f64,
        horizontal_accuracy: f64,
    ) -> Result<(), PushError> {
        let state = self.state.state.lock().await;

        // Get the first accessory's primary key to encrypt with
        // (own device location uses the same key infrastructure as beacons)
        let Some((device_id, accessory)) = state.accessories.iter().next() else {
            return Err(PushError::KeyedArchiveError("No accessories/devices found for location submit".to_string()));
        };

        // Encode location as EncryptedReport format: lat*10^7 (i32 BE), lon*10^7 (i32 BE), accuracy (u8), status (u8)
        let lat_encoded = (latitude * 10_000_000.0) as i32;
        let lon_encoded = (longitude * 10_000_000.0) as i32;
        let accuracy = (horizontal_accuracy.min(255.0)) as u8;
        let status = 0u8; // 0 = normal

        let plaintext = [
            &lat_encoded.to_be_bytes()[..],
            &lon_encoded.to_be_bytes()[..],
            &[accuracy],
            &[status],
        ].concat();

        // Generate an ephemeral key pair for ECDH
        let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
        let ephemeral = EcKey::generate(&group)?;
        let mut ctx = BigNumContext::new()?;
        let ephemeral_pub_bytes = ephemeral.public_key().to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)?;

        // Derive the decryption key from the primary ratchet
        let primary_key_bytes = &accessory.master_record.shared_secret;
        let mut derived = vec![0u8; 72];
        derive_key_into::<Sha256>(primary_key_bytes, b"diversify", &mut derived);

        // Derive shared secret via ECDH with the accessory's public key
        let adv_key = {
            let mut secret = vec![0u8; 72];
            derive_key_into::<Sha256>(primary_key_bytes, b"diversify", &mut secret);
            let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
            let mut n = BigNum::new()?;
            let mut ctx = BigNumContext::new()?;
            group.order(&mut n, &mut ctx)?;
            let u = BigNum::from_slice(&secret[..36])?;
            let mut private_scalar = BigNum::new()?;
            private_scalar.nnmod(&u, &n, &mut ctx)?;
            private_scalar.add_word(1)?;
            let mut pub_point = EcPoint::new(&group)?;
            pub_point.mul_generator(&group, &private_scalar, &mut ctx)?;
            EcKey::from_private_components(&group, &private_scalar, &pub_point)?
        };

        let adv_pkey = PKey::from_ec_key(adv_key)?;
        let eph_pkey = PKey::from_ec_key(ephemeral.clone())?;

        // ECDH: derive shared secret
        let mut deriver = openssl::derive::Deriver::new(&eph_pkey)?;
        deriver.set_peer(&adv_pkey)?;
        let shared_secret = deriver.derive_to_vec()?;

        // Derive symmetric key: SHA256(shared_secret || 0x00000001 || ephemeral_pub)
        let symmetric = sha256(&[
            &shared_secret[..],
            &[0x00, 0x00, 0x00, 0x01],
            &ephemeral_pub_bytes[..],
        ].concat());

        // Encrypt with AES-128-GCM
        use aes_gcm::{Aes128Gcm, aead::Aead, KeyInit, Nonce};
        let cipher = Aes128Gcm::new_from_slice(&symmetric[..16]).unwrap();
        let nonce = Nonce::from_slice(&symmetric[16..28]);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|_| PushError::KeyedArchiveError("AES-GCM encryption failed".to_string()))?;

        // Build the payload: timestamp (4 bytes BE) + confidence (1 byte) + ephemeral_pub + encrypted
        let apple_epoch_offset = 978307200u64;
        let now_secs = duration_since_epoch().as_secs();
        let apple_ts = (now_secs - apple_epoch_offset) as u32;

        let payload_bytes = [
            &apple_ts.to_be_bytes()[..],
            &[100u8], // confidence = 100
            &ephemeral_pub_bytes[..],
            &encrypted[..],
        ].concat();

        let payload_b64 = base64_encode(&payload_bytes);

        // Compute the advertisement key hash (same as used in fetch)
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let adv_key_reconstructed = {
            let mut secret = vec![0u8; 72];
            derive_key_into::<Sha256>(primary_key_bytes, b"diversify", &mut secret);
            let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
            let mut n = BigNum::new()?;
            let mut ctx = BigNumContext::new()?;
            group.order(&mut n, &mut ctx)?;
            let u = BigNum::from_slice(&secret[..36])?;
            let mut private_scalar = BigNum::new()?;
            private_scalar.nnmod(&u, &n, &mut ctx)?;
            private_scalar.add_word(1)?;
            let mut pub_point = EcPoint::new(&group)?;
            pub_point.mul_generator(&group, &private_scalar, &mut ctx)?;
            EcKey::from_private_components(&group, &private_scalar, &pub_point)?
        };
        adv_key_reconstructed.public_key().affine_coordinates_gfp(adv_key_reconstructed.group(), &mut x, &mut y, &mut ctx)?;
        let adv_id = base64_encode(&sha256(&x.to_vec_padded(28)?));

        info!("[FMF-SUBMIT] Submitting own location: lat={}, lon={}, acc={}", latitude, longitude, horizontal_accuracy);
        info!("[FMF-SUBMIT] Payload size: {} bytes, adv_id: {}", payload_bytes.len(), adv_id);

        // Submit to Apple
        let response: serde_json::Value = self.make_searchparty_request(
            &state.dsid,
            "https://gateway.icloud.com/findmyservice/v2/submit",
            &json!({
                "clientContext": {
                    "clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                    "policy": "foregroundClient",
                },
                "payloads": [{
                    "id": adv_id,
                    "locationInfo": [payload_b64],
                }]
            }),
            None,
        ).await?;

        info!("[FMF-SUBMIT] Submit response: {:?}", response);
        Ok(())
    }

    /// Publish location via the modern secure-locations channel (People surface).
    ///
    /// This is the correct mechanism for appearing under "People" in friends' Find My.
    /// Uses ECIES with P-224 + X9.63 KDF (SHA-256) + AES-128-GCM-KDFIV.
    /// Submits to gateway.icloud.com/findmyservice/submit (same auth as AirTag submit).
    ///
    /// Algorithm: algid:encrypt:ECIES:ECDH:KDFX963:SHA256:AESGCM-KDFIV
    /// Key ID: SHA256(public_key_x_coordinate)
    /// Endpoint: POST /findmyservice/submit with searchPartyToken auth
    ///
    /// Crypto verified bidirectionally against `Security.framework`. See
    /// `tools/findmy-capture/INVESTIGATION.md` §29-31.
    pub async fn publish_secure_location(
        &self,
        latitude: f64,
        longitude: f64,
        altitude: f64,
        horizontal_accuracy: f64,
        vertical_accuracy: f64,
        speed: f64,
        course: f64,
    ) -> Result<(), PushError> {
        // NOTE: no forced token refresh here. searchPartyToken is valid ~1 week and
        // `get_mme_token` (below) refreshes lazily when the cached token is missing/stale.
        // The old unconditional `refresh_mme()` ran a full relay-backed GSA + MobileMe
        // delegate-login on every publish, which intermittently failed
        // (DelegateLoginFailed / UnauthorizedAccountError) for no benefit. We instead refresh
        // REACTIVELY: only if the submit comes back 401 do we refresh once and retry (see the
        // retry loop around the POST below). Matches the fetch_locations pattern.

        // Log available tokens for diagnostics
        {
            let mme = self.token_provider.mme_delegate.lock().await;
            if let Some(ref mme_resp) = *mme {
                let token_names: Vec<&String> = mme_resp.tokens.keys().collect();
                info!("[FMF-SECURE] Available MME tokens: {:?}", token_names);
            } else {
                info!("[FMF-SECURE] No MME delegate available at all");
            }
        }

        let mut state = self.state.state.lock().await;

        // Generate or retrieve persistent secure location keys.
        // On first call, this creates a P-224 keypair + AES-256 shared secret.
        // The key_id derivation (base64(SHA256(pubkey_x))) stays the same.
        let (priv_key, pub_key, shared_secret) = state.get_or_generate_secure_location_keys()?;
        // Save state if keys were just generated
        self.state.save(&state)?;

        let x_bytes = &pub_key[1..29]; // skip 0x04 prefix
        let y_bytes = &pub_key[29..57];

        // Key ID = base64(SHA256(x_coordinate))
        let key_id = base64_encode(&sha256(x_bytes));

        info!("[FMF-SECURE] Using generated publisher pubkey");
        info!("[FMF-SECURE] Derived key_id: {}", key_id);
        info!("[FMF-SECURE] Pubkey (first 8): {}", encode_hex(&pub_key[..8]));

        let now_ms = duration_since_epoch().as_millis() as i64;
        // Cocoa epoch = seconds since 2001-01-01 (NOT Unix epoch).
        // Apple's plaintext uses this format; verified against captured publish.
        let unix_secs = duration_since_epoch().as_secs_f64();
        let cocoa_epoch_secs = unix_secs - 978307200.0;

        // Build the JSON plaintext exactly as captured from a real iOS publish.
        // Field order matches the capture in case Apple's parser is order-sensitive
        // (untested, but cheap to match).
        //
        // findMyId is `base64(dsid_string)` with the standard `=` padding chars
        // replaced by `~` — verified against the captured value:
        //   captured: "MTgyNDMxMzE5MDY~"
        //   decoded:  base64_decode("MTgyNDMxMzE5MDY=") == "18243131906"
        // (The earlier inline comment claimed `base64url("dsid~")`, but that's
        // wrong — the trailing `~` is base64 padding, not part of the input.)
        let dsid_b64 = base64_encode(state.dsid.as_bytes());
        let find_my_id = dsid_b64.replace('=', "~");
        info!("[FMF-SECURE] findMyId derived from state.dsid: {} (was hardcoded MTgyNDMxMzE5MDY~)", find_my_id);

        let plaintext_json = serde_json::to_string(&json!({
            "speed": speed,
            "locationLabel": serde_json::Value::Null,
            "timestamp": cocoa_epoch_secs,
            "longitude": longitude,
            "motionActivityState": 0,
            "latitude": latitude,
            "verticalAccuracy": vertical_accuracy,
            "publishReason": 4,           // 4 = bystander
            "findMyId": find_my_id,
            "course": course,
            "floor": 0,
            "altitude": altitude,
            "horizontalAccuracy": horizontal_accuracy,
        })).map_err(|e| PushError::KeyedArchiveError(format!("JSON serialize failed: {}", e)))?;

        let plaintext = plaintext_json.as_bytes();

        info!("[FMF-SECURE] Publishing: lat={}, lon={}, key_id={}, {} bytes plaintext (JSON, Cocoa epoch)",
            latitude, longitude, key_id, plaintext.len());

        // ECIES encrypt with the publisher's own public key (broadcast model)
        let x_arr: [u8; 28] = x_bytes.try_into().map_err(|_| PushError::KeyedArchiveError("x not 28 bytes".to_string()))?;
        let y_arr: [u8; 28] = y_bytes.try_into().map_err(|_| PushError::KeyedArchiveError("y not 28 bytes".to_string()))?;
        let encrypted = Self::ecies_p224_encrypt(plaintext, &x_arr, &y_arr)?;
        let encrypted_b64 = base64_encode(&encrypted);

        info!("[FMF-SECURE] Encrypted blob: {} bytes (expected {} = 57 + {} + 16)",
            encrypted.len(), 57 + plaintext.len() + 16, plaintext.len());

        // Get APNs token for clientContext.
        //
        // For the first end-to-end test we hardcode the captured iPhone-6s
        // (capture device) apsToken to keep all clientContext fields consistent
        // with the captured submit. If Apple cross-validates apsToken against the
        // searchPartyToken's account/DSID, mixing them would cause a 4xx; using
        // the same one across the board avoids surfacing that variable until
        // we've verified the crypto+protocol path end-to-end.
        //
        // (This is the 6s Frida-rig device's APNs token, NOT the iPhone 6
        // validation-data relay's — the relay is account-less and doesn't have
        // a relevant APNs identity here.)
        //
        // For production use, this needs to come from `self.conn.get_token()`
        // (the live Android APNs token).
        let aps_token = encode_hex(&self.conn.get_token().await).to_uppercase();
        info!("[FMF-SECURE] Using device apsToken: {}...{}", &aps_token[..8], &aps_token[aps_token.len()-8..]);

        // clientId: per the USER HYPOTHESIS + 6s diff, this should be a device identity Apple
        // RECOGNIZES on the account. The Android isn't a registered device; the iPhone-6 RELAY is
        // (it owns our GSAuth and appears in the account's Devices list). So use the RELAY's UDID,
        // not a fabricated Android-derived value (my earlier sha1(android_uuid) was a value Apple has
        // never seen) and not the stale 6s capture. Logged so we can see its exact format/value.
        let client_id = self.config.get_udid().to_lowercase();
        info!("[FMF-SECURE] clientId (relay device UDID via config.get_udid): {}", client_id);

        info!("[FMF-SECURE] Using apsToken: {}...{}", &aps_token[..8], &aps_token[aps_token.len()-8..]);

        // Build the request body
        let request_body = json!({
            "clientContext": {
                "apsToken": aps_token,
                "clientId": client_id,
                "contextApp": "searchpartyd",
                "autoMeStatus": 0,
                "publishReason": "bystander",
            },
            "submit": [{
                "id": key_id,
                "locationInfo": [{
                    "locationTs": now_ms,
                    "location": encrypted_b64,
                }]
            }]
        });

        info!("[FMF-SECURE] Request body (truncated): {}", &serde_json::to_string(&request_body).unwrap_or_default()[..500.min(serde_json::to_string(&request_body).unwrap_or_default().len())]);

        let body = serde_json::to_string(&request_body)?;
        let submit_url = "https://gateway.icloud.com/findmyservice/submit";
        info!("[FMF-SECURE] POST {} | dsid={} | key_id={} | unix_ms={}",
            submit_url, state.dsid, key_id, now_ms);
        //
        // Send the submit, refreshing the token REACTIVELY only on a 401 (expired/invalid token).
        // Attempt 0 uses the cached token; on 401 we force-refresh the MME delegate once and retry
        // attempt 1 with the fresh token. Any other status (incl. the known 428 ACL) is handled by
        // the status branch below — retrying those wouldn't help. Token + anisette headers are
        // rebuilt each attempt so the retry actually carries the refreshed token. Body is cloned.
        let (status, resp_headers, response_body) = {
            let mut attempt = 0u8;
            loop {
                // Get searchPartyToken from MobileMe delegation (lazy; refreshed once on 401 below).
                let search_party_token = self.token_provider.get_mme_token("searchPartyToken").await
                    .map_err(|e| {
                        error!("[FMF-SECURE] searchPartyToken not available from delegation: {:?}", e);
                        e
                    })?;
                info!("[FMF-SECURE] Got searchPartyToken from delegation (attempt {})", attempt);

                let mut request_headers: HeaderMap = self.anisette.lock().await.get_headers().await?.clone().into_iter()
                    .map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();
                request_headers.remove("X-Mme-Client-Info");
                let sent_header_names: Vec<String> = request_headers.keys().map(|k| k.as_str().to_string()).collect();
                info!("[FMF-SECURE] Submit request anisette header names: {:?} (+ X-MMe-Client-Info, x-apple-setup-proxy-request, accept-version:4, user-agent, x-apple-i-device-type, Content-Type)", sent_header_names);

                let description = REQWEST.post(submit_url)
                    .basic_auth(&format!("{}", state.dsid), Some(&search_party_token))
                    .headers(request_headers)
                    .header("X-MMe-Client-Info", self.config.get_mme_clientinfo("com.apple.icloud.searchpartyuseragent/1.0"))
                    .header("x-apple-setup-proxy-request", "true")
                    .header("accept-version", "4")
                    .header("user-agent", "searchpartyuseragent/1 iMac13,1/13.6.4")
                    .header("x-apple-i-device-type", "1")
                    .header("Content-Type", "application/json")
                    .body(body.clone())
                    .send().await?;

                let status = description.status();
                // Capture response headers before consuming body (response.text() consumes self).
                let resp_headers: Vec<(String, String)> = description.headers().iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("<non-utf8>").to_string()))
                    .collect();
                let response_body = description.text().await.unwrap_or_default();

                // 401 on the first attempt → token likely expired; refresh once and retry.
                if status.as_u16() == 401 && attempt == 0 {
                    info!("[FMF-SECURE] Submit got 401 — refreshing MME token and retrying once");
                    if let Err(e) = self.token_provider.refresh_mme().await {
                        info!("[FMF-SECURE] MME refresh after 401 failed: {:?}", e);
                        break (status, resp_headers, response_body);
                    }
                    attempt += 1;
                    continue;
                }

                break (status, resp_headers, response_body);
            }
        };

        info!("[FMF-SECURE] Submit HTTP status: {}", status);
        // For 4xx/5xx, log full body (Apple sometimes returns larger messages
        // than the 500-char window). For 2xx, keep the truncated form.
        if status.is_client_error() || status.is_server_error() {
            info!("[FMF-SECURE] Submit response body (full): {}", response_body);
            info!("[FMF-SECURE] Submit response headers: {:?}", resp_headers);
            // Propagate the failure so callers (and the [FMF-SUMMARY] line) reflect reality.
            // Previously this returned Ok(()) on ANY status, which masked 428 ACL failures.
            return Err(PushError::KeyedArchiveError(format!(
                "publish submit rejected: HTTP {} body={}", status, response_body)));
        } else {
            info!("[FMF-SECURE] Submit response body: {}", &response_body[..response_body.len().min(500)]);
        }
        Ok(())
    }

    /// Fetch friends' secure locations from `findmyservice/fetch` and decrypt them
    /// with the PER-FRIEND private keys they sent us via `secureLocationsKeyUpdate`.
    ///
    /// Proven via Ghidra + live capture (see SESSION_2026_06_12_RECEIVE_FINDINGS.md, incl. the
    /// 2026-06-14 CORRECTION):
    /// - When a friend shares their location with us, they send a T:10 secureLocationsKeyUpdate
    ///   IDS message containing THEIR OWN private key (85B), their key_id (=SHA256(their pubkey_x)),
    ///   and their findMyId (=base64(their DSID) = their Follow.id).
    /// - We store that in state.friend_secure_keys keyed by their findMyId.
    /// - To fetch their location: POST findmyservice/fetch with fmId=their Follow.id and
    ///   ids=[their key_id], then ECIES-decrypt the returned blob with THEIR private key.
    ///
    /// `fm_ids` are the friends' Follow.id values to fetch. Returns map findMyId -> location JSON.
    pub async fn fetch_locations(&self, fm_ids: &[String]) -> Result<HashMap<String, serde_json::Value>, PushError> {
        info!("[FMF-FETCH] Fetching secure locations for {} friends", fm_ids.len());

        if fm_ids.is_empty() {
            return Ok(HashMap::new());
        }

        // NOTE: we deliberately do NOT force a token refresh here. searchPartyToken is valid
        // for ~1 week, and `get_mme_token` (below) already refreshes lazily when the cached
        // token is missing or older than a week. The previous unconditional `refresh_mme()`
        // ran a full GSA + MobileMe delegate-login every 5s cycle through the relay's anisette
        // identity, which intermittently failed (DelegateLoginFailed / UnauthorizedAccountError)
        // and was the dominant FMF error source. We instead refresh REACTIVELY: only if the
        // fetch comes back 401 do we refresh the token once and retry (see retry loop below).

        // Gather the per-friend key material we've received. Build a fetch entry per friend
        // that we hold a key for, keyed by THAT FRIEND's key_id.
        // friend_keys: fmId(Follow.id) -> (key_id, private_key[28], public_key[57])
        let (friend_keys, dsid) = {
            let state = self.state.state.lock().await;
            let mut map: HashMap<String, (String, [u8; 28], [u8; 57])> = HashMap::new();
            for (find_my_id, keys) in state.friend_secure_keys.iter() {
                // Only fetch for friends in the requested set.
                if !fm_ids.iter().any(|f| f == find_my_id) {
                    continue;
                }
                let priv_arr: [u8; 28] = match keys.private_key.clone().try_into() {
                    Ok(a) => a,
                    Err(_) => { info!("[FMF-FETCH]   skip {}: priv key not 28 bytes", find_my_id); continue; }
                };
                let pub_arr: [u8; 57] = match keys.public_key.clone().try_into() {
                    Ok(a) => a,
                    Err(_) => { info!("[FMF-FETCH]   skip {}: pub key not 57 bytes", find_my_id); continue; }
                };
                let key_id = base64_encode(&sha256(&pub_arr[1..29]));
                map.insert(find_my_id.clone(), (key_id, priv_arr, pub_arr));
            }
            (map, state.dsid.clone())
        };

        info!("[FMF-FETCH] Have keys for {}/{} friends; subscribing (ids:[]) for the rest",
            friend_keys.len(), fm_ids.len());

        let aps_token = encode_hex(&self.conn.get_token().await).to_uppercase();
        // Same clientId as publish_secure_location — the RELAY device UDID (recognized on the account),
        // so submit + fetch present one consistent client identity. Was hardcoded 6s UDID / sha1 guess.
        let client_id = self.config.get_udid().to_lowercase();

        // Build a fetch entry for EVERY following friend — not only the ones we hold keys for.
        //
        // KEY INSIGHT (proven via Ghidra on searchpartyd, 2026-06-24): iOS SubscribeAndFetch
        // registers a viewer by findMyId (FUN_1002a2654 gates on "findMyIds", not on a held key),
        // and FUN_1001f1ae4 issues a fetch even with no key to "request new keys". The act of
        // subscribing is what makes Apple push `distributeKeys` to the publisher, which causes the
        // publisher to send us the T:10 secureLocationsKeyUpdate. Without ever subscribing we are
        // never registered as a viewer, so no key is ever distributed to us -> blank map.
        //
        // The `ids` field on the fetch entry is a NON-optional Swift.Array (proven from the
        // __swift5_fieldmd metadata of the fetch-entry struct), so the encoder always emits it:
        // a keyless first subscribe sends "ids":[] (empty array), NOT an omitted field. Friends we
        // already hold a key for send ids:[their key_id] so the response includes their location.
        //
        // THROTTLING: keyed friends are included EVERY cycle (we want their location refreshed at
        // the loop's full cadence). Unkeyed friends only get a keyless "ids":[] subscribe at most
        // once per FMF_SUBSCRIBE_MIN_INTERVAL_MS each (fmf_subscribe_should_fire gate) — the keyless
        // subscribe is just the "please distribute a key to me" trigger, so re-sending it every few
        // seconds is wasteful. Once their key arrives they move to the keyed (un-throttled) path.
        let mut subscribe_skipped = 0usize;
        let fetch_entries: Vec<serde_json::Value> = fm_ids.iter().filter_map(|fm_id| {
            match friend_keys.get(fm_id) {
                Some((key_id, _, _)) => Some(json!({
                    "fmId": fm_id,
                    "intent": "startLocationUpdates",
                    "mode": "shallow",
                    "ids": [key_id],
                })),
                None => {
                    if fmf_subscribe_should_fire(fm_id) {
                        Some(json!({
                            "fmId": fm_id,
                            "intent": "startLocationUpdates",
                            "mode": "shallow",
                            "ids": [],
                        }))
                    } else {
                        subscribe_skipped += 1;
                        None
                    }
                }
            }
        }).collect();

        let request_body = json!({
            "fetch": fetch_entries,
            "clientContext": {
                "apsToken": aps_token,
                "clientId": client_id,
                "contextApp": "com.apple.findmy.fmfcore",
                "shallowStats": {},
            }
        });

        let body = serde_json::to_string(&request_body)?;
        let fetch_url = "https://gateway.icloud.com/findmyservice/fetch";
        let subscribe_only = fetch_entries.len() - friend_keys.len();
        info!("[FMF-FETCH] POST {} | dsid={} | {} entries ({} with key, {} subscribe-only ids:[], {} keyless throttled this cycle)",
            fetch_url, dsid, fetch_entries.len(), friend_keys.len(), subscribe_only, subscribe_skipped);

        // If every entry was throttled out (all friends unkeyed and within their subscribe
        // window) there is nothing to ask Apple for this cycle — skip the round trip.
        if fetch_entries.is_empty() {
            info!("[FMF-FETCH] No fetch entries this cycle (all unkeyed friends throttled); skipping POST");
            return Ok(HashMap::new());
        }

        // Send the fetch, refreshing the token REACTIVELY only on a 401. We try at most twice:
        // attempt 0 uses the cached token; if Apple rejects it with 401 (expired/invalid), we
        // force-refresh the MME delegate once and retry attempt 1 with the fresh token. Any other
        // non-success status is a hard error (no point retrying). This replaces the old
        // per-cycle unconditional refresh_mme().
        let (status, response_body) = {
            let mut attempt = 0u8;
            loop {
                // (Re)acquire the token each attempt — refresh_mme() on a 401 updates the cached
                // value, so attempt 1 must read it again to pick up the fresh token.
                let search_party_token = self.token_provider.get_mme_token("searchPartyToken").await
                    .map_err(|e| {
                        error!("[FMF-FETCH] searchPartyToken not available: {:?}", e);
                        e
                    })?;

                let mut request_headers: HeaderMap = self.anisette.lock().await.get_headers().await?.clone().into_iter()
                    .map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();
                request_headers.remove("X-Mme-Client-Info");

                let response = REQWEST.post(fetch_url)
                    .basic_auth(&format!("{}", dsid), Some(&search_party_token))
                    .headers(request_headers)
                    .header("X-MMe-Client-Info", self.config.get_mme_clientinfo("com.apple.icloud.searchpartyuseragent/1.0"))
                    .header("x-apple-setup-proxy-request", "true")
                    .header("accept-version", "4")
                    .header("user-agent", "searchpartyuseragent/1 iMac13,1/13.6.4")
                    .header("x-apple-i-device-type", "1")
                    .header("Content-Type", "application/json")
                    .body(body.clone())
                    .send().await?;

                let status = response.status();
                let response_body = response.text().await.unwrap_or_default();
                info!("[FMF-FETCH] HTTP status: {} (attempt {})", status, attempt);

                // 401 on the first attempt → token likely expired; force one refresh and retry.
                if status.as_u16() == 401 && attempt == 0 {
                    info!("[FMF-FETCH] 401 — refreshing MME token and retrying once");
                    if let Err(e) = self.token_provider.refresh_mme().await {
                        info!("[FMF-FETCH] MME refresh after 401 failed: {:?}", e);
                        // Nothing more we can do; surface the 401.
                        break (status, response_body);
                    }
                    attempt += 1;
                    continue;
                }

                break (status, response_body);
            }
        };

        if !status.is_success() {
            info!("[FMF-FETCH] Non-success body: {}", &response_body[..response_body.len().min(500)]);
            return Err(PushError::KeyedArchiveError(format!("fetch failed: HTTP {}", status)));
        }

        let parsed: serde_json::Value = serde_json::from_str(&response_body)
            .map_err(|e| PushError::KeyedArchiveError(format!("fetch response parse failed: {}", e)))?;

        let payloads = parsed.get("locationPayload")
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default();
        info!("[FMF-FETCH] locationPayload entries: {}", payloads.len());

        // Build a reverse lookup: key_id -> (fmId, priv, pub) so we can match each response
        // entry (response `id` == the friend's key_id) to the right friend + decrypt key.
        let by_key_id: HashMap<String, (String, [u8; 28], [u8; 57])> = friend_keys.iter()
            .map(|(fm_id, (key_id, priv_arr, pub_arr))| (key_id.clone(), (fm_id.clone(), *priv_arr, *pub_arr)))
            .collect();

        let mut result = HashMap::new();

        for entry in &payloads {
            let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let Some((fm_id, priv_arr, pub_arr)) = by_key_id.get(id) else {
                info!("[FMF-FETCH]   response id {} matches no known friend key", id);
                continue;
            };
            let loc_infos = entry.get("locationInfo").and_then(|v| v.as_array());
            let Some(loc_infos) = loc_infos else { continue };

            let best = loc_infos.iter().max_by_key(|li|
                li.get("locationTs").and_then(|v| v.as_i64()).unwrap_or(0));
            let Some(best) = best else { continue };

            let Some(loc_b64) = best.get("location").and_then(|v| v.as_str()) else { continue };
            let blob = base64_decode(loc_b64);
            let blob_prefix = if blob.is_empty() { 0 } else { blob[0] };
            info!("[FMF-FETCH]   friend fmId={} id={} blob={} bytes prefix={:#04x} (expect 0x04, len>=73)",
                fm_id, id, blob.len(), blob_prefix);

            match Self::ecies_p224_decrypt(&blob, priv_arr, pub_arr) {
                Ok(plaintext) => {
                    match serde_json::from_slice::<serde_json::Value>(&plaintext) {
                        Ok(loc_json) => {
                            info!("[FMF-FETCH]   DECRYPT OK for {}: {}", fm_id,
                                &serde_json::to_string(&loc_json).unwrap_or_default()[..200.min(serde_json::to_string(&loc_json).unwrap_or_default().len())]);
                            result.insert(fm_id.clone(), loc_json);
                        },
                        Err(e) => info!("[FMF-FETCH]   plaintext not JSON: {:?} (len {}, first bytes {})",
                            e, plaintext.len(), encode_hex(&plaintext[..plaintext.len().min(16)])),
                    }
                },
                // decrypt failure here almost always means key mismatch (our stored friend key
                // doesn't match the key the location was encrypted to) vs a malformed blob
                // (bad prefix / too short, visible in the line above).
                Err(e) => info!("[FMF-FETCH]   decrypt FAILED for fmId={} (likely key mismatch): {:?}", fm_id, e),
            }
        }

        info!("[FMF-FETCH] Decrypted {} friend locations", result.len());
        Ok(result)
    }

    /// Low-level POST to /findmyservice/fetch with the standard anisette headers.
    /// Returns (status_code_string, response_body). Used by verify_published_location's
    /// two-phase self-subscribe test so phase 1 (keyless) and phase 2 (keyed) share one path.
    async fn post_findmy_fetch(&self, body: &serde_json::Value, dsid: &str) -> Result<(String, String), PushError> {
        let search_party_token = self.token_provider.get_mme_token("searchPartyToken").await?;
        let mut request_headers: HeaderMap = self.anisette.lock().await.get_headers().await?.clone().into_iter()
            .map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())).collect();
        request_headers.remove("X-Mme-Client-Info");
        let body_str = serde_json::to_string(body)?;
        let response = REQWEST.post("https://gateway.icloud.com/findmyservice/fetch")
            .basic_auth(&format!("{}", dsid), Some(&search_party_token))
            .headers(request_headers)
            .header("X-MMe-Client-Info", self.config.get_mme_clientinfo("com.apple.icloud.searchpartyuseragent/1.0"))
            .header("x-apple-setup-proxy-request", "true")
            .header("accept-version", "4")
            .header("user-agent", "searchpartyuseragent/1 iMac13,1/13.6.4")
            .header("x-apple-i-device-type", "1")
            .header("Content-Type", "application/json")
            .body(body_str)
            .send().await?;
        let status = response.status().to_string();
        let resp_body = response.text().await.unwrap_or_default();
        Ok((status, resp_body))
    }

    /// END-TO-END SELF-VERIFICATION: self-SUBSCRIBE then fetch our OWN published blob and decrypt it.
    ///
    /// ⚠️ EXPERIMENTAL (2026-06-25): earlier self-fetch returned empty, and a 6s probe showed iOS
    /// never self-fetches — so we concluded self-verification was impossible. BUT that self-fetch
    /// skipped PHASE 1: the receive flow is two-phase (keyless subscribe ids:[] REGISTERS a viewer,
    /// THEN keyed fetch ids:[key_id] returns the blob). This version now does a keyless self-subscribe
    /// to our OWN findMyId first, waits, then keyed-fetches. If the server honors a self-subscribe,
    /// it returns our own blob -> full LOCAL proof with no friend. If phase 2 is still empty after a
    /// successful phase-1 subscribe, self-verification really is impossible and only a friend can test.
    ///
    /// Why: an HTTP 200 on `/findmyservice/submit` proves ONLY that Apple accepted+stored
    /// the blob. It does NOT prove the chain a friend depends on:
    ///   stored under a fetchable key_id -> retrievable via /fetch -> decryptable.
    /// We publish encrypted to our OWN P-224 pubkey and hold the matching private key, so
    /// we can fetch our own key_id and decrypt it ourselves — no friend/human needed.
    ///
    /// A round-trip back to the coords we published (e.g. Montreal 45.5017, -73.5673)
    /// PROVES: blob stored + fetchable-under-key_id + decryptable-with-our-key. It does NOT
    /// prove a friend received the T:10 key-update; that remains a separate dispatch fact.
    ///
    /// Returns the decrypted location JSON on success.
    pub async fn verify_published_location(&self) -> Result<serde_json::Value, PushError> {
        info!("[FMF-SELFTEST] === self-fetch verification START ===");

        // NOTE: no forced token refresh here. post_findmy_fetch (used for both phases below)
        // acquires the token via get_mme_token, which lazily refreshes only when the cached
        // token is missing or >1 week old. The old unconditional refresh_mme() was a copy of the
        // fetch_locations pattern (since removed) — it ran a full relay-backed delegate login that
        // intermittently failed (UnauthorizedAccountError) for no benefit, so it's gone here too.

        // Load OUR persistent keypair — the SAME one publish_secure_location encrypts to.
        // Must NOT depend on friend_secure_keys (that's the receive path).
        let (our_priv, our_pub, _shared, our_key_id, find_my_id, dsid) = {
            let mut state = self.state.state.lock().await;
            let (priv_key, pub_key, shared) = state.get_or_generate_secure_location_keys()?;
            self.state.save(&state)?;
            // key_id = base64(SHA256(pubkey_x)), x = pub_key[1..29] (skip 0x04 prefix).
            let key_id = base64_encode(&sha256(&pub_key[1..29]));
            // findMyId = base64(dsid).replace('=','~') == our Follow.id (matches publish).
            let fm_id = base64_encode(state.dsid.as_bytes()).replace('=', "~");
            (priv_key, pub_key, shared, key_id, fm_id, state.dsid.clone())
        };

        info!("[FMF-SELFTEST] our key_id={} | findMyId={} | dsid={}", our_key_id, find_my_id, dsid);

        let aps_token = encode_hex(&self.conn.get_token().await).to_uppercase();
        let client_id = self.config.get_udid().to_lowercase();

        // === PHASE 1: keyless SELF-SUBSCRIBE to our OWN findMyId (ids:[]). ===
        // The receive agent proved the real fetch flow is two-phase: a keyless subscribe (ids:[])
        // REGISTERS us as a viewer of an fmId, THEN a keyed fetch (ids:[key_id]) returns the blob.
        // Our earlier self-fetch skipped phase 1 and went straight to the keyed fetch — which is why
        // it returned empty (we were never registered as a subscriber to our own key_id). Here we
        // first subscribe to OURSELVES, give the server a moment, then keyed-fetch. If the server
        // treats a self-subscribe like any other, it will serve our own blob back -> full local proof.
        // If it refuses self-subscription, phase 2 stays empty and self-verification is truly impossible.
        let subscribe_body = json!({
            "fetch": [{
                "fmId": find_my_id,
                "intent": "startLocationUpdates",
                "mode": "shallow",
                "ids": [],
            }],
            "clientContext": {
                "apsToken": aps_token,
                "clientId": client_id,
                "contextApp": "com.apple.findmy.fmfcore",
                "shallowStats": {},
            }
        });
        match self.post_findmy_fetch(&subscribe_body, &dsid).await {
            Ok((st, body)) => info!("[FMF-SELFTEST] PHASE1 keyless self-subscribe -> HTTP {} body={}",
                st, &body[..body.len().min(300)]),
            Err(e) => info!("[FMF-SELFTEST] PHASE1 keyless self-subscribe FAILED: {:?}", e),
        }
        // Give the server a moment, then begin polling.
        tokio::time::sleep(Duration::from_secs(5)).await;

        // === PHASE 2: keyed fetch of OUR key_id, RETRIED over several minutes. ===
        // The receive path measured ~2 MINUTES between a keyless subscribe and keys/data arriving
        // (server: subscribe -> distributeKeys -> publisher-send -> fan-out). A single 3s-delayed
        // fetch (our earlier mistake) is far too short to conclude anything. So we poll the keyed
        // fetch for up to ~5 min, re-subscribing every other cycle, and only declare "impossible"
        // if it's STILL empty after the full window.
        let keyed_body = json!({
            "fetch": [{
                "fmId": find_my_id,
                "intent": "startLocationUpdates",
                "mode": "shallow",
                "ids": [our_key_id],
            }],
            "clientContext": {
                "apsToken": aps_token,
                "clientId": client_id,
                "contextApp": "com.apple.findmy.fmfcore",
                "shallowStats": {},
            }
        });

        const MAX_ATTEMPTS: usize = 15;       // ~15 * 20s = 5 min
        const POLL_INTERVAL_SECS: u64 = 20;
        let mut last_raw = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            // Re-issue the keyless subscribe every 3rd attempt in case the first didn't stick.
            if attempt > 1 && attempt % 3 == 1 {
                match self.post_findmy_fetch(&subscribe_body, &dsid).await {
                    Ok((st, _)) => info!("[FMF-SELFTEST] re-subscribe (attempt {}) -> HTTP {}", attempt, st),
                    Err(e) => info!("[FMF-SELFTEST] re-subscribe (attempt {}) failed: {:?}", attempt, e),
                }
            }

            let (status, response_body) = match self.post_findmy_fetch(&keyed_body, &dsid).await {
                Ok(v) => v,
                Err(e) => {
                    info!("[FMF-SELFTEST] attempt {}/{} keyed fetch error: {:?}", attempt, MAX_ATTEMPTS, e);
                    tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                    continue;
                }
            };
            last_raw = response_body.clone();
            if !status.starts_with("200") {
                info!("[FMF-SELFTEST] attempt {}/{} HTTP {} body={}", attempt, MAX_ATTEMPTS, status,
                    &response_body[..response_body.len().min(300)]);
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                continue;
            }

            let parsed: serde_json::Value = serde_json::from_str(&response_body)
                .map_err(|e| PushError::KeyedArchiveError(format!("self-fetch response parse failed: {}", e)))?;
            let payloads = parsed.get("locationPayload").and_then(|p| p.as_array()).cloned().unwrap_or_default();
            info!("[FMF-SELFTEST] attempt {}/{}: locationPayload entries: {}", attempt, MAX_ATTEMPTS, payloads.len());

            if payloads.is_empty() {
                // Still nothing this cycle — wait and retry (this is the EXPECTED early-cycle state
                // given the ~2min server latency; NOT yet a failure).
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                continue;
            }

            // We got payload(s) — try to match + decrypt our key_id.
            for entry in &payloads {
                let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if id != our_key_id {
                    info!("[FMF-SELFTEST]   response id {} != our key_id, skipping", id);
                    continue;
                }
                let Some(loc_infos) = entry.get("locationInfo").and_then(|v| v.as_array()) else { continue };
                let best = loc_infos.iter().max_by_key(|li|
                    li.get("locationTs").and_then(|v| v.as_i64()).unwrap_or(0));
                let Some(best) = best else { continue };
                let Some(loc_b64) = best.get("location").and_then(|v| v.as_str()) else { continue };
                let blob = base64_decode(loc_b64);
                let blob_prefix = if blob.is_empty() { 0 } else { blob[0] };
                info!("[FMF-SELFTEST]   blob={} bytes prefix={:#04x} (expect 0x04, len>=73)", blob.len(), blob_prefix);

                match Self::ecies_p224_decrypt(&blob, &our_priv, &our_pub) {
                    Ok(plaintext) => match serde_json::from_slice::<serde_json::Value>(&plaintext) {
                        Ok(loc_json) => {
                            let lat = loc_json.get("latitude").and_then(|v| v.as_f64());
                            let lon = loc_json.get("longitude").and_then(|v| v.as_f64());
                            info!("[FMF-SELFTEST] DECRYPT OK (attempt {}) — lat={:?} lon={:?} | full={}",
                                attempt, lat, lon, serde_json::to_string(&loc_json).unwrap_or_default());
                            info!("[FMF-SELFTEST] === SELF-FETCH VERIFIED: stored + fetchable + decryptable ===");
                            return Ok(loc_json);
                        },
                        Err(e) => return Err(PushError::KeyedArchiveError(
                            format!("self-fetch decrypt plaintext not JSON: {} (first bytes {})",
                                e, encode_hex(&plaintext[..plaintext.len().min(16)])))),
                    },
                    Err(e) => return Err(PushError::KeyedArchiveError(
                        format!("self-fetch decrypt FAILED (our own key should always work — blob/key bug?): {:?}", e))),
                }
            }

            // Payload present but none matched our key_id — log and keep polling.
            let returned_ids: Vec<String> = payloads.iter()
                .filter_map(|e| e.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())).collect();
            info!("[FMF-SELFTEST] attempt {}: payload present but no match; expected key_id={} got ids={:?}",
                attempt, our_key_id, returned_ids);
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }

        // Exhausted the full ~5min window with no payload for our key_id. NOW this is a meaningful
        // negative: even with repeated subscribes over minutes, the server never served us our own
        // blob. This is the proper basis for the "publisher cannot self-fetch" conclusion.
        info!("[FMF-SELFTEST] EXHAUSTED {} attempts over ~{}s — no self-payload. last_raw={}",
            MAX_ATTEMPTS, MAX_ATTEMPTS as u64 * POLL_INTERVAL_SECS, &last_raw[..last_raw.len().min(400)]);
        Err(PushError::KeyedArchiveError(format!(
            "self-fetch empty after {} attempts over ~5min — self-verification not possible (or blob not stored)",
            MAX_ATTEMPTS)))
    }

    /// ECIES encrypt using P-224 + ANSI X9.63 KDF (SHA-256) + **AES-128**-GCM-KDFIV.
    ///
    /// This is Apple's `algid:encrypt:ECIES:ECDH:KDFX963:SHA256:AESGCM-KDFIV`,
    /// also known as `kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM`.
    ///
    /// Key facts (verified bidirectionally against `Security.framework`, see
    /// `tools/findmy-capture/INVESTIGATION.md` §29-31):
    /// - KDF output is **32 bytes** total: AES-128 key (16) || GCM IV (16)
    /// - Cipher is **AES-128**, NOT AES-256 (the "VariableIV" / KDFIV flavor)
    /// - X9.63 KDF with single SHA-256 block (counter=1), shared_info = ephemeral pub
    ///
    /// Returns: 0x04 || ephemeral_pub_x(28) || ephemeral_pub_y(28) || ciphertext || tag(16)
    fn ecies_p224_encrypt(plaintext: &[u8], pub_x: &[u8; 28], pub_y: &[u8; 28]) -> Result<Vec<u8>, PushError> {
        let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
        let mut ctx = BigNumContext::new()?;

        // Reconstruct public key from x, y coordinates
        let pub_point = {
            let x = BigNum::from_slice(pub_x)?;
            let y = BigNum::from_slice(pub_y)?;
            let mut point = EcPoint::new(&group)?;
            point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)?;
            point
        };
        let target_ec = EcKey::from_public_key(&group, &pub_point)?;
        let target_pkey = PKey::from_ec_key(target_ec)?;

        // Generate ephemeral P-224 keypair
        let ephemeral = EcKey::generate(&group)?;
        let ephemeral_pub_bytes = ephemeral.public_key()
            .to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)?;
        let ephemeral_pkey = PKey::from_ec_key(ephemeral)?;

        // ECDH: derive shared secret (28 bytes for P-224)
        let mut deriver = openssl::derive::Deriver::new(&ephemeral_pkey)?;
        deriver.set_peer(&target_pkey)?;
        let shared_secret = deriver.derive_to_vec()?;

        // X9.63 KDF with SHA-256, shared_info = ephemeral public key bytes (uncompressed).
        // dk_len=32 fits in one SHA-256 block; produces aes_key(16) || gcm_iv(16).
        let kdf_block = sha256(&[
            &shared_secret[..],
            &[0x00, 0x00, 0x00, 0x01],
            &ephemeral_pub_bytes[..],
        ].concat());

        let aes_key: &[u8; 16] = (&kdf_block[..16]).try_into().expect("16 bytes");
        let gcm_iv: &[u8; 16] = (&kdf_block[16..32]).try_into().expect("16 bytes");

        // AES-128-GCM with 16-byte IV (Apple's KDFIV variant uses non-standard IV size)
        use aes_gcm::aead::generic_array::GenericArray;
        let cipher: AesGcm<Aes128, U16> = AesGcm::new(GenericArray::from_slice(aes_key));
        let nonce = GenericArray::from_slice(gcm_iv);
        let encrypted = cipher.encrypt(nonce, plaintext)
            .map_err(|_| PushError::KeyedArchiveError("AES-128-GCM encryption failed".to_string()))?;

        // Wire format: ephemeral_pub_uncompressed(57) || ciphertext || tag(16)
        let result = [&ephemeral_pub_bytes[..], &encrypted[..]].concat();

        Ok(result)
    }

    /// Decrypt a friend's secure-location blob with OUR P-224 private key.
    ///
    /// This is the exact inverse of `ecies_p224_encrypt`. The blob fetched from
    /// `findmyservice/fetch` has the form:
    ///
    /// ```text
    /// 0x04 || eph_pub_x(28) || eph_pub_y(28) || ciphertext || tag(16)   (>= 57 + 16 bytes)
    /// ```
    ///
    /// algid:encrypt:ECIES:ECDH:KDFX963:SHA256:AESGCM-KDFIV
    ///   - ECDH(our_priv, eph_pub) -> shared secret (28 bytes for P-224)
    ///   - X9.63 KDF (SHA-256, counter=1, shared_info = eph_pub uncompressed) -> 32 bytes
    ///   - split into aes_key(16) || gcm_iv(16)
    ///   - AES-128-GCM with 16-byte IV
    ///
    /// `our_private_key` is the 28-byte private scalar; `our_public_key` is the
    /// 57-byte uncompressed pubkey (used to reconstruct the EC key for ECDH).
    fn ecies_p224_decrypt(
        blob: &[u8],
        our_private_key: &[u8; 28],
        our_public_key: &[u8; 57],
    ) -> Result<Vec<u8>, PushError> {
        if blob.len() < 57 + 16 {
            return Err(PushError::KeyedArchiveError(format!(
                "ECIES blob too short: {} bytes (need >= 73)", blob.len())));
        }

        let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
        let mut ctx = BigNumContext::new()?;

        // Parse the ephemeral public key (first 57 bytes, uncompressed SEC1).
        let eph_pub_bytes = &blob[..57];
        if eph_pub_bytes[0] != 0x04 {
            return Err(PushError::KeyedArchiveError(format!(
                "ECIES ephemeral pubkey bad prefix: {:#04x}", eph_pub_bytes[0])));
        }
        let eph_point = EcPoint::from_bytes(&group, eph_pub_bytes, &mut ctx)?;
        let eph_ec = EcKey::from_public_key(&group, &eph_point)?;
        let eph_pkey = PKey::from_ec_key(eph_ec)?;

        // Reconstruct OUR private key for ECDH.
        let priv_bn = BigNum::from_slice(our_private_key)?;
        let our_point = {
            let x = BigNum::from_slice(&our_public_key[1..29])?;
            let y = BigNum::from_slice(&our_public_key[29..57])?;
            let mut point = EcPoint::new(&group)?;
            point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)?;
            point
        };
        let our_ec = EcKey::from_private_components(&group, &priv_bn, &our_point)?;
        our_ec.check_key()?;
        let our_pkey = PKey::from_ec_key(our_ec)?;

        // ECDH: shared secret (28 bytes for P-224).
        let mut deriver = openssl::derive::Deriver::new(&our_pkey)?;
        deriver.set_peer(&eph_pkey)?;
        let shared_secret = deriver.derive_to_vec()?;

        // X9.63 KDF (SHA-256, counter=1, shared_info = ephemeral pubkey uncompressed).
        let kdf_block = sha256(&[
            &shared_secret[..],
            &[0x00, 0x00, 0x00, 0x01],
            &eph_pub_bytes[..],
        ].concat());

        let aes_key: &[u8; 16] = (&kdf_block[..16]).try_into().expect("16 bytes");
        let gcm_iv: &[u8; 16] = (&kdf_block[16..32]).try_into().expect("16 bytes");

        // AES-128-GCM with 16-byte IV. ciphertext+tag is everything after the eph pubkey.
        use aes_gcm::aead::generic_array::GenericArray;
        let cipher: AesGcm<Aes128, U16> = AesGcm::new(GenericArray::from_slice(aes_key));
        let nonce = GenericArray::from_slice(gcm_iv);
        let ct_and_tag = &blob[57..];
        let plaintext = cipher.decrypt(nonce, ct_and_tag)
            .map_err(|_| PushError::KeyedArchiveError("AES-128-GCM decryption failed (wrong key?)".to_string()))?;

        Ok(plaintext)
    }

    /// Decrypt an inbound v1 MappingPacket `p` blob from a friend.
    ///
    /// The `p` blob format: version(1) + nonce(16) + AES-256-GCM(plaintext_123, per_friend_key) + tag(16) = 156 bytes
    /// The plaintext contains: header(6) + friend_private_key(28) + friend_public_key(57) + shared_secret(32)
    /// The per_friend_key = SHA256(ECDH(friend_priv, OUR_pub)) = SHA256(ECDH(OUR_priv, friend_pub))
    ///
    /// But we have a bootstrap problem: we need the friend's pubkey to derive the per_friend_key,
    /// and the friend's pubkey is inside the encrypted blob. However, since we proved Apple doesn't
    /// validate the crypto, the friend likely encrypted with ECDH(their_priv, OUR_pub). We can
    /// derive the same key using ECDH(OUR_priv, their_pub) — but we don't have their pub yet.
    ///
    /// Workaround: try decryption with our own ECDH(priv, pub) first (degenerate case — friend
    /// might have used our pubkey as placeholder too), then if that fails, log the failure and
    /// store the raw blob for later when we learn the friend's pubkey.
    ///
    /// Returns Ok(FriendSecureLocationKeys) if decrypt succeeds, Err otherwise.
    fn decrypt_inbound_mapping_packet(
        our_private_key: &[u8; 28],
        our_public_key: &[u8; 57],
        p_encoded: &str,
    ) -> Result<FriendSecureLocationKeys, PushError> {
        info!("[FMF-MAPPING-DECRYPT] Attempting to decrypt inbound MappingPacket");
        info!("[FMF-MAPPING-DECRYPT]   p string length: {}, starts with: {}", p_encoded.len(), &p_encoded[..20.min(p_encoded.len())]);

        // Decode: strip leading /, replace ~ with /, base64 decode
        if !p_encoded.starts_with('/') {
            return Err(PushError::KeyedArchiveError("p blob doesn't start with /".to_string()));
        }
        let b64 = p_encoded[1..].replace('~', "/");
        let p_blob = base64_decode(&b64);
        info!("[FMF-MAPPING-DECRYPT]   decoded blob: {} bytes", p_blob.len());

        if p_blob.len() != 156 {
            return Err(PushError::KeyedArchiveError(format!("p blob wrong size: {} (expected 156)", p_blob.len())));
        }

        // Parse structure: version(1) + nonce(16) + ciphertext(123) + tag(16)
        let version = p_blob[0];
        if version != 0x01 {
            info!("[FMF-MAPPING-DECRYPT]   WARNING: unexpected version byte: {:#04x}", version);
        }
        let nonce_bytes = &p_blob[1..17];
        let encrypted = &p_blob[17..]; // 139 bytes (123 ct + 16 tag)
        info!("[FMF-MAPPING-DECRYPT]   version={:#04x}, nonce={}, encrypted={} bytes",
            version, encode_hex(nonce_bytes), encrypted.len());

        // Derive per-friend key: ECDH(our_priv, friend_pub)
        // Since we don't know the friend's pub yet, try with our own pub (degenerate ECDH).
        // If the friend used ECDH(their_priv, our_pub) to encrypt, and we try
        // ECDH(our_priv, our_pub), this WON'T match unless the friend IS us.
        // But if a real friend sent this, we need their pubkey from somewhere else.
        //
        // Strategy: try ECDH(our_priv, our_pub) first. If it fails (expected for real friends),
        // we can't decrypt yet. Log everything and return an error.
        // When we learn the friend's pubkey (from another source), we can retry.

        let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
        let mut ctx = BigNumContext::new()?;

        // Reconstruct our private key
        let priv_bn = BigNum::from_slice(our_private_key)?;
        let pub_point = {
            let x = BigNum::from_slice(&our_public_key[1..29])?;
            let y = BigNum::from_slice(&our_public_key[29..57])?;
            let mut point = EcPoint::new(&group)?;
            point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)?;
            point
        };
        let our_ec = EcKey::from_private_components(&group, &priv_bn, &pub_point)?;
        let our_pkey = PKey::from_ec_key(our_ec)?;

        // For now, try ECDH with our own pubkey (self-ECDH)
        // This will only work if the sender used our pubkey as the friend_pub parameter
        let friend_pkey = PKey::from_ec_key(EcKey::from_public_key(&group, &pub_point)?)?;

        let mut deriver = openssl::derive::Deriver::new(&our_pkey)?;
        deriver.set_peer(&friend_pkey)?;
        let ecdh_shared = deriver.derive_to_vec()?;
        let per_friend_key = sha256(&ecdh_shared);
        info!("[FMF-MAPPING-DECRYPT]   per_friend_key (self-ECDH, first 8): {}", encode_hex(&per_friend_key[..8]));

        // Try AES-256-GCM decrypt
        use aes_gcm::aead::generic_array::GenericArray;
        let cipher: AesGcm<Aes256, U16> = AesGcm::new(GenericArray::from_slice(&per_friend_key));
        let nonce = GenericArray::from_slice(nonce_bytes);

        match cipher.decrypt(nonce, encrypted) {
            Ok(plaintext) => {
                info!("[FMF-MAPPING-DECRYPT]   Decrypt SUCCESS! Plaintext: {} bytes", plaintext.len());
                if plaintext.len() != 123 {
                    info!("[FMF-MAPPING-DECRYPT]   WARNING: expected 123 bytes, got {}", plaintext.len());
                }

                // Parse plaintext: header(6) + private_key(28) + public_key(57) + shared_secret(32)
                if plaintext.len() >= 123 {
                    let header = &plaintext[0..6];
                    let friend_priv = &plaintext[6..34];
                    let friend_pub = &plaintext[34..91];
                    let friend_secret = &plaintext[91..123];

                    info!("[FMF-MAPPING-DECRYPT]   header: {}", encode_hex(header));
                    info!("[FMF-MAPPING-DECRYPT]   friend private_key (first 8): {}", encode_hex(&friend_priv[..8]));
                    info!("[FMF-MAPPING-DECRYPT]   friend public_key (first 8): {}", encode_hex(&friend_pub[..8]));
                    info!("[FMF-MAPPING-DECRYPT]   friend shared_secret (first 8): {}", encode_hex(&friend_secret[..8]));

                    // Validate the pubkey starts with 0x04 (uncompressed SEC1)
                    if friend_pub[0] != 0x04 {
                        info!("[FMF-MAPPING-DECRYPT]   WARNING: friend pubkey doesn't start with 0x04!");
                    }

                    Ok(FriendSecureLocationKeys {
                        private_key: friend_priv.to_vec(),
                        public_key: friend_pub.to_vec(),
                        shared_secret: friend_secret.to_vec(),
                        find_my_id: String::new(),
                    })
                } else {
                    Err(PushError::KeyedArchiveError(format!("Decrypted plaintext too short: {} bytes", plaintext.len())))
                }
            },
            Err(e) => {
                info!("[FMF-MAPPING-DECRYPT]   Decrypt FAILED (expected if real friend — need their pubkey): {:?}", e);
                info!("[FMF-MAPPING-DECRYPT]   Raw blob hex (for later retry): {}", encode_hex(&p_blob));
                Err(PushError::KeyedArchiveError("AES-256-GCM decrypt failed — friend's pubkey unknown".to_string()))
            }
        }
    }

    /// Relay a server-provided mapping packet token to a friend via IDS.
    /// The token (p blob) was already constructed by Apple's server via offerLocation.
    /// We just wrap it in the IDS message format and send it.
    ///
    /// Parameters:
    /// - `friend_handle`: The friend's IDS URI (e.g. "tel:+1234567890" or "mailto:friend@example.com")
    /// - `p_token`: The pre-built p blob string from Apple's requestTokens response
    pub async fn relay_mapping_packet(
        &self,
        friend_handle: &str,
        p_token: &str,
    ) -> Result<(), PushError> {
        info!("[FMF-RELAY] Relaying mapping packet to: {} ({} chars)", friend_handle, p_token.len());

        // Build the IDS payload as a binary plist:
        // { kFMFServicePayloadKey: "mappingPacket", p: <token_string>, v: 1 }
        let payload = plist::Dictionary::from_iter([
            ("kFMFServicePayloadKey".to_string(), Value::String("mappingPacket".to_string())),
            ("p".to_string(), Value::String(p_token.to_string())),
            ("v".to_string(), Value::String("1".to_string())),
        ]);
        let payload_bytes = plist_to_bin(&payload)?;

        // Normalize handle to IDS URI format
        let uri_handle = if friend_handle.starts_with("tel:") || friend_handle.starts_with("mailto:") {
            friend_handle.to_string()
        } else if friend_handle.contains('@') {
            format!("mailto:{}", friend_handle)
        } else {
            format!("tel:{}", friend_handle)
        };

        // Send on fmf topic
        let topic = "com.apple.private.alloy.fmf";
        let handle = self.identity.get_handles().await.remove(0);

        match self.identity.cache_keys(
            topic,
            &[uri_handle.clone()],
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true },
        ).await {
            Ok(()) => {},
            Err(e) => {
                info!("[FMF-RELAY]   cache_keys failed: {:?}", e);
                return Err(e);
            }
        }

        let targets = self.identity.cache.lock().await
            .get_participants_targets(topic, &handle, &[uri_handle.clone()]);

        if targets.is_empty() {
            info!("[FMF-RELAY]   No targets for {}", uri_handle);
            return Ok(());
        }

        match self.identity.send_message(topic, IDSSendMessage {
            sender: handle.clone(),
            raw: Raw::Body(payload_bytes),
            send_delivered: false,
            command: 242,
            no_response: true,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                ("wA".to_string(), Value::Boolean(true))
            ]),
        }, targets).await {
            Ok(_) => info!("[FMF-RELAY] Sent to {}", uri_handle),
            Err(e) => info!("[FMF-RELAY]   send failed: {:?}", e),
        }

        Ok(())
    }

    /// Distribute OUR P-224 private key to a follower via a `secureLocationsKeyUpdate` (T:10) IDS
    /// message, so the follower can decrypt the location we publish to /findmyservice/submit.
    ///
    /// This is the MISSING publish step: without it, our submit (encrypted to our own pubkey) is
    /// undecryptable by friends. Proven via Frida captures (see SESSION_2026_06_12_RECEIVE_FINDINGS.md):
    /// the publisher hands each follower its OWN private key in this message.
    ///
    /// Wire format (mirror of `handle_secure_locations_key_update`, byte-validated from capture):
    ///   outer bplist: { "T": 10, "V": 1, "P": <nested bplist> }
    ///   nested P:     [ { "hashedAdvertisement": {"key":{"data": <32B SHA256(our pubkey_x)>}},
    ///                     "entityIdentifier": <our findMyId = base64(our DSID) with '=' -> '~'>,
    ///                     "identifier": <UUID>,
    ///                     "privateKey": {"key":{"data": <85B = 04||x||y||priv>}},
    ///                     "index": <int> } ]
    /// Transport: IDS topic `com.apple.private.alloy.fmd`, command 242 (confirmed: live Android logs
    /// show alloy.fmd content msgs carry c:242). Sent per follower handle.
    pub async fn distribute_secure_location_key(&self, follower_handle: &str) -> Result<(), PushError> {
        info!("[FMF-KEYDIST] === distribute_secure_location_key START for {} ===", follower_handle);
        // Load (or generate) our persistent P-224 keypair — the SAME one publish_secure_location uses.
        let (priv_key, pub_key, find_my_id) = {
            let mut state = self.state.state.lock().await;
            let (priv_arr, pub_arr, _shared) = match state.get_or_generate_secure_location_keys() {
                Ok(k) => k,
                Err(e) => { error!("[FMF-KEYDIST] STEP=load_keys FAIL: {:?}", e); return Err(e); }
            };
            self.state.save(&state)?;
            // findMyId = base64(DSID) with '=' padding replaced by '~' (matches captured format).
            let find_my_id = base64_encode(state.dsid.as_bytes()).replace('=', "~");
            info!("[FMF-KEYDIST] STEP=load_keys OK dsid={} findMyId={} pub8={} priv8={}",
                state.dsid, find_my_id, encode_hex(&pub_arr[..8]), encode_hex(&priv_arr[..8]));
            (priv_arr, pub_arr, find_my_id)
        };

        // 85-byte key export = 04 || x(28) || y(28) || priv(28) = pub(57) || priv(28).
        let mut key_data = Vec::with_capacity(85);
        key_data.extend_from_slice(&pub_key);   // 57 bytes (0x04 || x || y)
        key_data.extend_from_slice(&priv_key);  // 28 bytes (private scalar)
        if key_data.len() != 85 {
            error!("[FMF-KEYDIST] STEP=key_export FAIL: {} bytes (expected 85)", key_data.len());
            return Err(PushError::KeyedArchiveError(format!("key export not 85 bytes: {}", key_data.len())));
        }

        // hashedAdvertisement = SHA256(pubkey_x); x = pub_key[1..29] (skip 0x04 prefix).
        let key_id = sha256(&pub_key[1..29]);

        info!("[FMF-KEYDIST] STEP=build key_id_b64={} (this is what the friend will fetch under)",
            base64_encode(&key_id));

        // Build the nested key record (single-element array), mirroring the inbound parser exactly.
        let record = plist::Dictionary::from_iter([
            ("hashedAdvertisement".to_string(), Value::Dictionary(plist::Dictionary::from_iter([
                ("key".to_string(), Value::Dictionary(plist::Dictionary::from_iter([
                    ("data".to_string(), Value::Data(key_id.to_vec())),
                ]))),
            ]))),
            ("entityIdentifier".to_string(), Value::String(find_my_id.clone())),
            ("identifier".to_string(), Value::String(Uuid::new_v4().to_string().to_uppercase())),
            ("privateKey".to_string(), Value::Dictionary(plist::Dictionary::from_iter([
                ("key".to_string(), Value::Dictionary(plist::Dictionary::from_iter([
                    ("data".to_string(), Value::Data(key_data)),
                ]))),
            ]))),
            ("index".to_string(), Value::Integer(0u32.into())),
        ]);
        let nested_bytes = plist_to_bin(&Value::Array(vec![Value::Dictionary(record)]))?;
        let nested_bytes_len = nested_bytes.len();

        // Outer envelope: { T: 10, V: 1, P: <nested bplist bytes> }.
        let outer = plist::Dictionary::from_iter([
            ("T".to_string(), Value::Integer(10u32.into())),
            ("V".to_string(), Value::Integer(1u32.into())),
            ("P".to_string(), Value::Data(nested_bytes)),
        ]);
        let payload_bytes = plist_to_bin(&Value::Dictionary(outer))?;

        // Normalize handle to IDS URI format (same logic as relay_mapping_packet).
        let uri_handle = if follower_handle.starts_with("tel:") || follower_handle.starts_with("mailto:") {
            follower_handle.to_string()
        } else if follower_handle.contains('@') {
            format!("mailto:{}", follower_handle)
        } else {
            format!("tel:{}", follower_handle)
        };

        // Transport: secure-locations rides on com.apple.private.alloy.fmd (proven via serviceIdentifier capture).
        let topic = "com.apple.private.alloy.fmd";
        let our_handles = self.identity.get_handles().await;
        if our_handles.is_empty() {
            error!("[FMF-KEYDIST] STEP=get_handles FAIL: no IDS handles registered — cannot send");
            return Err(PushError::KeyedArchiveError("no IDS handles available for key distribution".to_string()));
        }
        let handle = our_handles[0].clone();
        info!("[FMF-KEYDIST] STEP=prepared sender={} target={} payload={}B nested={}B",
            handle, uri_handle, payload_bytes.len(), nested_bytes_len);

        info!("[FMF-KEYDIST] STEP=cache_keys begin for {}", uri_handle);
        if let Err(e) = self.identity.cache_keys(
            topic,
            &[uri_handle.clone()],
            &handle,
            false,
            &QueryOptions { required_for_message: true, result_expected: true },
        ).await {
            error!("[FMF-KEYDIST] STEP=cache_keys FAIL for {}: {:?} — friend may not be iMessage/FMF-registered on this handle", uri_handle, e);
            return Err(e);
        }
        info!("[FMF-KEYDIST] STEP=cache_keys OK for {}", uri_handle);

        let targets = self.identity.cache.lock().await
            .get_participants_targets(topic, &handle, &[uri_handle.clone()]);
        info!("[FMF-KEYDIST] STEP=targets resolved {} target(s) for {}", targets.len(), uri_handle);
        if targets.is_empty() {
            error!("[FMF-KEYDIST] STEP=targets FAIL: no targets for {} — friend has no device registered on com.apple.private.alloy.fmd (secure-loc capability missing?)", uri_handle);
            // Return an error (not Ok) so the [FMF-SUMMARY] keyDist tally reflects that nothing was sent.
            return Err(PushError::KeyedArchiveError(format!("no secure-loc targets for {}", uri_handle)));
        }

        info!("[FMF-KEYDIST] STEP=send begin (command=242, no_response=true — NOTE: Ok only means dispatched to APNs, NOT delivered/accepted by friend)");
        match self.identity.send_message(topic, IDSSendMessage {
            sender: handle.clone(),
            raw: Raw::Body(payload_bytes),
            send_delivered: false,
            command: 242,
            no_response: true,
            id: Uuid::new_v4().to_string().to_uppercase(),
            scheduled_ms: None,
            queue_id: None,
            relay: None,
            extras: Dictionary::from_iter([
                ("wA".to_string(), Value::Boolean(true))
            ]),
        }, targets).await {
            Ok(_) => info!("[FMF-KEYDIST] STEP=send OK — secureLocationsKeyUpdate dispatched to {} (findMyId={}, key_id8={})",
                uri_handle, find_my_id, encode_hex(&key_id[..8])),
            Err(e) => {
                error!("[FMF-KEYDIST] STEP=send FAIL for {}: {:?}", uri_handle, e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Test function: calls offerLocation to get mapping packet tokens from Apple,
    /// then relays them via IDS to all followers. Then publishes our location.
    /// Returns a descriptive string for the UI snackbar.
    pub async fn test_send_mapping_packet(&self) -> Result<String, PushError> {
        info!("[FMF-OFFER-TEST] === Starting offerLocation + publish test ===");

        // Refresh the daemon to get current followers list
        let friend_handles: Vec<String> = {
            let mut daemon = self.daemon.lock().await;
            info!("[FMF-OFFER-TEST] Refreshing daemon to get followers...");
            daemon.refresh(self.config.as_ref()).await?;
            info!("[FMF-OFFER-TEST] Followers count: {}", daemon.followers.len());

            daemon.followers.iter()
                .filter_map(|f| {
                    f.invitation_from_handles.first()
                        .or_else(|| f.invitation_accepted_handles.first())
                        .cloned()
                })
                .collect()
        };

        if friend_handles.is_empty() {
            return Err(PushError::KeyedArchiveError("No followers found — need at least one person following us".to_string()));
        }

        info!("[FMF-OFFER-TEST] Calling offerLocation for {} followers (one per handle)", friend_handles.len());

        // Step 1: Call offerLocation per-handle (matching 6s behavior) to get tokens
        let mut request_tokens = HashMap::new();
        for handle in &friend_handles {
            match {
                let mut daemon = self.daemon.lock().await;
                daemon.offer_location(self.config.as_ref(), &[handle.clone()]).await
            } {
                Ok(tokens) => {
                    for (k, v) in tokens {
                        request_tokens.insert(k, v);
                    }
                },
                Err(e) => {
                    info!("[FMF-OFFER-TEST]   offerLocation failed for {}: {:?}", handle, e);
                }
            }
        }

        if request_tokens.is_empty() {
            return Ok("offerLocation returned no tokens".to_string());
        }

        // Step 2: Relay each token via IDS to the friend
        let mut sent_count = 0;
        for (handle_id, token) in &request_tokens {
            info!("[FMF-OFFER-TEST] Relaying token to: {} ({} chars)", handle_id, token.len());
            match self.relay_mapping_packet(handle_id, token).await {
                Ok(()) => { sent_count += 1; },
                Err(e) => {
                    info!("[FMF-OFFER-TEST]   Relay failed for {}: {:?}", handle_id, e);
                }
            }
        }

        info!("[FMF-OFFER-TEST] Relayed {}/{} tokens", sent_count, request_tokens.len());

        // Step 3: Distribute OUR private key to every follower via secureLocationsKeyUpdate (T:10)
        // BEFORE publishing. The real iOS capture (share-full.log) shows key-updates BEGIN before the
        // /findmyservice/submit (T:10 at 10:36:10/12, SUBMIT at 10:36:13, more T:10 after). Sending
        // keys first removes any server-side race where a submit lands under a key_id no follower has
        // registered yet. Order matters per the capture; we match iOS by distributing before submit.
        let mut key_sent = 0;
        for handle in &friend_handles {
            match self.distribute_secure_location_key(handle).await {
                Ok(()) => { key_sent += 1; },
                Err(e) => info!("[FMF-OFFER-TEST]   key distribution failed for {}: {:?}", handle, e),
            }
        }
        info!("[FMF-OFFER-TEST] Distributed key to {}/{} followers", key_sent, friend_handles.len());

        // Step 4: Claim me-device (source location) so our blob is the one served to followers.
        // Without this, the account's existing me-device (iPad/6s) shadows our publish.
        info!("[FMF-OFFER-TEST] Claiming me-device before publish...");
        match {
            let mut daemon = self.daemon.lock().await;
            daemon.claim_me_device(self.config.as_ref()).await
        } {
            Ok(_) => info!("[FMF-OFFER-TEST] claim_me_device OK"),
            Err(e) => info!("[FMF-OFFER-TEST] claim_me_device failed (continuing): {:?}", e),
        }

        // Step 5: Publish our location so friends (who now hold our key) can decrypt it.
        info!("[FMF-OFFER-TEST] Publishing location...");
        let publish_result = self.publish_secure_location(45.5017, -73.5673, 0.0, 10.0, 10.0, 0.0, 0.0).await;
        let publish_ok = publish_result.is_ok();

        // Step 5: SELF-FETCH verification — only meaningful if publish reported OK. Proves the
        // blob is actually stored + fetchable under our key_id + decryptable (catches silent
        // failures where a 200 stored nothing retrievable). Independent of friend delivery.
        let mut selffetch_ok = false;
        let mut selffetch_detail = String::from("skipped (publish failed)");
        if publish_ok {
            match self.verify_published_location().await {
                Ok(loc) => {
                    selffetch_ok = true;
                    let lat = loc.get("latitude").and_then(|v| v.as_f64());
                    let lon = loc.get("longitude").and_then(|v| v.as_f64());
                    selffetch_detail = format!("lat={:?} lon={:?}", lat, lon);
                    info!("[FMF-OFFER-TEST] self-fetch verified: {}", selffetch_detail);
                },
                Err(e) => {
                    selffetch_detail = format!("{}", e);
                    info!("[FMF-OFFER-TEST] self-fetch verification FAILED: {:?}", e);
                }
            }
        }

        // === SINGLE-LINE SUMMARY: tells you at a glance which step broke ===
        // Format: followers=N | offerTokens=N | relayed=N/N | keyDist=N/N | publish=OK|FAIL
        // Read this one line first; then grep [FMF-OFFER]/[FMF-RELAY]/[FMF-KEYDIST]/[FMF-SECURE]
        // for the failing step's detail.
        info!("[FMF-SUMMARY] followers={} | offerTokens={} | relayed={}/{} | keyDist={}/{} | publish={} | selfFetch={}",
            friend_handles.len(),
            request_tokens.len(),
            sent_count, request_tokens.len(),
            key_sent, friend_handles.len(),
            if publish_ok { "OK" } else { "FAIL" },
            if selffetch_ok { "OK" } else if publish_ok { "FAIL" } else { "SKIP" });
        if friend_handles.is_empty() { warn!("[FMF-SUMMARY] STEP0 followers=0 — nobody to share with"); }
        if request_tokens.is_empty() { warn!("[FMF-SUMMARY] STEP1 offerLocation produced 0 tokens — see [FMF-OFFER]"); }
        if sent_count < request_tokens.len() { warn!("[FMF-SUMMARY] STEP2 relay incomplete — see [FMF-RELAY]"); }
        if key_sent < friend_handles.len() { warn!("[FMF-SUMMARY] STEP3 key distribution incomplete — see [FMF-KEYDIST]"); }
        if !publish_ok { warn!("[FMF-SUMMARY] STEP4 publish failed — see [FMF-SECURE]"); }
        if publish_ok && !selffetch_ok { warn!("[FMF-SUMMARY] STEP5 self-fetch failed ({}) — 200 may be a silent store failure; see [FMF-SELFTEST]", selffetch_detail); }
        if !friend_handles.is_empty() && !request_tokens.is_empty()
            && sent_count == request_tokens.len() && key_sent == friend_handles.len() && publish_ok && selffetch_ok {
            info!("[FMF-SUMMARY] ALL STEPS OK + self-fetch VERIFIED ({}). Our blob is stored, fetchable under our \
                key_id, and decryptable. NOTE: key-update sends are no_response — final proof a friend SEES us \
                still requires friend-side confirmation.", selffetch_detail);
        }

        match publish_result {
            Ok(()) => {
                info!("[FMF-OFFER-TEST] publish_secure_location OK");
                Ok(format!("offerLocation: {} tokens. Relayed: {}. Key->{} followers. Published. SelfFetch: {} ({})",
                    request_tokens.len(), sent_count, key_sent,
                    if selffetch_ok { "VERIFIED" } else { "FAILED" }, selffetch_detail))
            },
            Err(e) => {
                info!("[FMF-OFFER-TEST] publish_secure_location failed: {:?}", e);
                Ok(format!("offerLocation: {} tokens. Relayed: {}. Key->{}. Publish failed: {}", request_tokens.len(), sent_count, key_sent, e))
            }
        }
    }

    /// Test function: attempt the fmip `identityV5` device registration so our
    /// device gains a `deviceDiscoveryId` and becomes electable as `meDeviceId`
    /// (the upstream gate for FindMy People publish — see IDENTITYV5_PLAN.md).
    ///
    /// Requires the relay bridge to implement the fmip signing endpoints; on any
    /// config that can't produce the PCRT + Sign1/2 material this returns
    /// `FmipBridgeUnsupported` and sends nothing. Returns a descriptive string for
    /// the UI snackbar (HTTP status + response body).
    pub async fn test_register_identity_v5(&self) -> Result<String, PushError> {
        info!("[FMF-IDV5] === Starting identityV5 registration test ===");

        let dsid = self.state.state.lock().await.dsid.clone();
        let client = fmip_register::FmipRegisterClient {
            dsid,
            // fmip server shard — same random range the device-locate client uses.
            server: rand::thread_rng().gen_range(101..=182),
            anisette: self.anisette.clone(),
            aps: self.conn.clone(),
            token_provider: self.token_provider.clone(),
        };

        // pscSUILastModified: the real captured identityV5 body carries a concrete
        // value (`1780027396090`, from quic-findmydeviced.log). Previously we sent
        // 0 (which omits the field). For the diagnostic fresh-UDID test we send the
        // known-good captured value so the request matches the real body shape and
        // we don't give the edge filter a reason to reject on a missing field.
        // (This is the 6s's PSC/Provenance pref timestamp; reused as a constant for
        // the test. If enrollment ever works, the relay bridge should supply the
        // device's live value instead.)
        let psc = 1780027396090u64;

        match client.register_identity_v5(self.config.as_ref(), psc).await {
            Ok(outcome) => {
                info!("[FMF-IDV5] identityV5 outcome: status={} uuid={}", outcome.http_status, outcome.request_uuid);
                Ok(format!(
                    "identityV5 status={} uuid={} body={}",
                    outcome.http_status,
                    outcome.request_uuid,
                    &outcome.response_body[..outcome.response_body.len().min(300)]
                ))
            },
            Err(PushError::FmipBridgeUnsupported) => {
                info!("[FMF-IDV5] Relay bridge does not support fmip signing (expected until Task 2 lands)");
                Ok("identityV5 unsupported: relay bridge missing fmip/pcrt + fmip/sign (Task 2)".to_string())
            },
            Err(e) => {
                error!("[FMF-IDV5] identityV5 registration failed: {:?}", e);
                Err(e)
            }
        }
    }

    /// READ-ONLY diagnostic: probe the relay bridge's fmip primitives and log the
    /// results, to verify the Task 2 low-risk half (PCRT + hardware descriptor)
    /// WITHOUT submitting anything to Apple. Fetches nothing that mutates state:
    /// it only reads the device-hardware descriptor and the (static, reusable)
    /// PCRT token. See IDENTITYV5_PLAN.md "VERIFICATION PROCEDURE".
    ///
    /// Returns a short summary string. On a config without the fmip bridge this
    /// reports "unsupported" rather than erroring.
    pub async fn test_probe_fmip_bridge(&self) -> Result<String, PushError> {
        info!("[FMF-IDV5] === Probing relay fmip bridge (read-only) ===");

        // 1. Hardware descriptor (from get-version-info, populated by the relay bridge).
        match self.config.get_fmip_device_hardware() {
            Some(hw) => {
                info!(
                    "[FMF-IDV5] hardware: serial={} imei={} imei2={} meid={} ecid={} chipId={} wifiMac={} btMac={}",
                    hw.serial_number, hw.imei, hw.imei2, hw.meid, hw.ecid, hw.chip_id, hw.wifi_mac, hw.bt_mac
                );
                // Flag any empty field — an empty ecid/chipId/MAC means the relay's
                // MobileGestalt key spelling needs adjusting (see plan open item).
                for (name, val) in [
                    ("serial", &hw.serial_number), ("imei", &hw.imei), ("meid", &hw.meid),
                    ("ecid", &hw.ecid), ("chipId", &hw.chip_id), ("wifiMac", &hw.wifi_mac), ("btMac", &hw.bt_mac),
                ] {
                    if val.is_empty() {
                        warn!("[FMF-IDV5]   hardware field '{}' is EMPTY — check the relay MobileGestalt key", name);
                    }
                }
            },
            None => info!("[FMF-IDV5] hardware descriptor unavailable (relay bridge not reporting fmip fields)"),
        }

        // 2. PCRT token (static/reusable; the identityV5 ifcReceipt).
        match self.config.get_fmip_pcrt_token().await {
            Ok(pcrt) => {
                let decoded_len = base64_decode(&pcrt).len();
                info!(
                    "[FMF-IDV5] PCRT: len={} chars, decodes to {} bytes (expect 32), value={}",
                    pcrt.len(), decoded_len, pcrt
                );
                if decoded_len != 32 {
                    warn!("[FMF-IDV5]   PCRT does not decode to 32 bytes — token may be malformed");
                }
                Ok(format!("fmip probe OK — PCRT {} chars ({} bytes decoded)", pcrt.len(), decoded_len))
            },
            Err(PushError::FmipBridgeUnsupported) => {
                info!("[FMF-IDV5] PCRT unsupported: relay bridge missing fmip/pcrt (Task 2 not deployed)");
                Ok("fmip probe: bridge unsupported (relay missing fmip/pcrt)".to_string())
            },
            Err(e) => {
                error!("[FMF-IDV5] PCRT fetch failed: {:?}", e);
                Err(e)
            }
        }
    }

    /// TEMPORARY DIAGNOSTIC — exercises the relay `fmip-sign` bridge command with a
    /// DUMMY 32-byte digest to reveal how the registration server maps an HTTP POST
    /// body into the relay websocket command `data` (IDENTITYV5_PLAN.md piece-1
    /// audit, Issue A). This is the caller needed to read the relay-side DIAG echo
    /// once the ffb239d relay .deb is deployed. It does NOT submit anything to Apple
    /// and does NOT mutate account state — it only asks the relay to sign a throwaway
    /// digest. The findmydeviced shim (piece 2) does not exist yet, so on a deployed
    /// ffb239d relay this is expected to return the DIAG error string (echoing the
    /// raw `data` shape) or FmipBridgeUnsupported on an older relay.
    ///
    /// Remove once Issue A (the body -> `data` mapping) is confirmed.
    pub async fn test_probe_fmip_sign(&self) -> Result<String, PushError> {
        info!("[FMF-IDV5] === Probing relay fmip-sign bridge (DIAG, dummy digest) ===");

        // A throwaway, clearly-recognizable 32-byte digest (0x00,0x01,...,0x1f).
        // Nothing is signed for real; this only drives the wire-shape DIAG.
        let digest: Vec<u8> = (0u8..32u8).collect();
        let request_uuid = Uuid::new_v4().to_string().to_uppercase();
        info!(
            "[FMF-IDV5] fmip-sign DIAG: sending {}-byte dummy digest, request_uuid={}",
            digest.len(), request_uuid
        );

        match self.config.get_fmip_signature(&digest, &request_uuid).await {
            Ok(sig) => {
                // Unexpected this early (piece 2 not built) — but log it fully if it happens.
                info!(
                    "[FMF-IDV5] fmip-sign returned a signature: sign1_len={} sign2_len={} sign5={} sign6={}",
                    sig.sign1.len(),
                    sig.sign2.len(),
                    sig.sign5.as_deref().map(|s| s.len().to_string()).unwrap_or_else(|| "none".to_string()),
                    sig.sign6.as_deref().map(|s| s.len().to_string()).unwrap_or_else(|| "none".to_string()),
                );
                Ok(format!(
                    "fmip-sign OK — sign1 {} chars, sign2 {} chars",
                    sig.sign1.len(), sig.sign2.len()
                ))
            },
            Err(PushError::FmipBridgeUnsupported) => {
                info!("[FMF-IDV5] fmip-sign unsupported: relay bridge missing fmip-sign (older relay / Task 2 not deployed)");
                Ok("fmip-sign: bridge unsupported (relay missing fmip-sign command)".to_string())
            },
            Err(PushError::RelayError(status, msg)) => {
                // On the deployed ffb239d relay this is the EXPECTED path: the DIAG
                // echo (or the shim-unreachable error) comes back here. Log verbatim
                // so we can read the raw `data=` shape (Issue A).
                info!("[FMF-IDV5] fmip-sign relay response (status={}): {}", status, msg);
                Ok(format!("fmip-sign DIAG (status={}): {}", status, msg))
            },
            Err(e) => {
                error!("[FMF-IDV5] fmip-sign probe failed: {:?}", e);
                Err(e)
            }
        }
    }

    pub async fn sync_item_positions(&self) -> Result<(), PushError> {
        // === TEMPORARY: Trigger an FMF (People surface) publish on every item-sync cycle.
        //     This is the corrected path using ECIES with the publisher's own pubkey.
        //     The previous code here called submit_own_location, which is the AirTag/Items
        //     surface (wrong protocol for "appear under People"). See INVESTIGATION.md §22.
        //     Throttled by FMF_AUTO_PUBLISH_MIN_INTERVAL_MS (see top of this file) so we
        //     don't hammer Apple on every item-sync; the manual UI button is unaffected.
        if fmf_auto_publish_should_fire() {
            info!("[FMF-SUBMIT] Triggering publish_secure_location (FMF People surface)");
            match self.publish_secure_location(
                45.5017,    // latitude
                -73.5673,   // longitude (Montreal — placeholder for testing)
                50.0,       // altitude (m)
                10.0,       // horizontal_accuracy (m)
                5.0,        // vertical_accuracy (m)
                0.0,        // speed (m/s)
                0.0,        // course (degrees)
            ).await {
                Ok(()) => info!("[FMF-SUBMIT] publish_secure_location returned Ok (HTTP status logged separately)"),
                Err(e) => error!("[FMF-SUBMIT] publish_secure_location failed: {:?}", e),
            }
        } else {
            debug!("[FMF-SUBMIT] Skipping auto-publish (within {} ms throttle window)", FMF_AUTO_PUBLISH_MIN_INTERVAL_MS);
        }
        // === END TEMPORARY TEST ===

        self.sync_items(true).await?;

        let mut state = self.state.state.lock().await;
        let mut bignum = BigNumContext::new()?;

        let range = SystemTime::now();
        let start = range - Duration::from_secs(60 * 60 * 24 * 7) - Duration::from_secs(60 * 60 * 12);
        let end = range + Duration::from_secs(60 * 60 * 12);
        let start_ts = start.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
        let end_ts = end.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();

        let mut key_map = HashMap::new();

        let mut search = vec![];
        for (id, device) in &mut state.accessories {
            let keys = device.get_current()?;
            let mut device_keys = vec![];
            for (idx, key) in keys {

                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                key.public_key().affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut bignum)?;

                let adv = base64_encode(&sha256(&x.to_vec_padded(28)?));
                key_map.insert(adv.clone(), (id.clone(), key, idx));
                device_keys.push(adv);
            
            }
            
            search.push(json!({
                "secondaryIds": [],
                "keyType": 1,
                "startDate": start_ts,
                "startDateSecondary": start_ts,
                "endDate": end_ts,
                "primaryIds": device_keys,
            }));
        }

        let state = &mut *state;

        let mut shared_search = vec![];
        for (id, shared) in &mut state.share_state.shared_beacons {
            let Some(share_id) = state.share_state.circles_member.values().find(|c| &c.beacon_identifier == id) else { continue };

            let Some(circle_root_key) = state.share_state.secrets.values().find_map(|v| {
                if v.sharing_circle_identifier != share_id.sharing_circle_identifier { return None }
                v.wild_root_key()
            }) else { continue };

            let Some(join_key) = state.share_state.secrets.iter().filter(|(_, a)| a.sharing_circle_identifier == share_id.sharing_circle_identifier)
                .find_map(|(_, a)| a.join_token()) else { continue };
            
            let Some(start_alignment) = state.share_state.shared_beacons_client.get(&share_id.beacon_identifier) else { continue };

            let start_time = SystemTime::UNIX_EPOCH + Duration::from_millis(start_alignment.start_date);
            let Ok(diff) = SystemTime::now().duration_since(start_time) else { continue };
            
            // round
            let days_elapsed = (diff.as_secs() + 43200) / 86400;
            // week range, start 6 days ago and one day in front;
            let range = days_elapsed - 6 .. days_elapsed + 1;

            shared_search.push(json!({
                "shareId": &share_id.sharing_circle_identifier,
                "type": "item",
                "memberToken": base64_encode(&join_key.member_token()),
                "shareBundles": range.map(|b| circle_root_key.get_bundle_data(b)).collect::<Vec<_>>(),
                "ownedDeviceIds": []
            }));
        }

        if search.is_empty() && shared_search.is_empty() {
            info!("Not searching, no item!");
            return Ok(())
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FetchLocationPayload {
            location_info: Vec<String>,
            id: String,
            loc_decrypt_key: Option<String>,
            share_id: Option<String>,
        }

        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct FetchLocations {
            location_payload: Vec<FetchLocationPayload>,
        }

        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct FetchPositionsResponse {
            #[serde(default)]
            acsn_locations: FetchLocations,
        }

        let data: FetchPositionsResponse = self.make_searchparty_request(&state.dsid, "https://gateway.icloud.com/findmyservice/v2/fetch", &json!({
            "clientContext": {
                "clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                "policy": "foregroundClient",
            },
            "sharedFetch": shared_search,
            "fetch": search,
        }), None).await?;

        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        let mut context = BigNumContext::new()?;

        let mut reports: HashMap<String, Vec<LocationReport>> = HashMap::new();
        let mut shared_reports: HashMap<String, Vec<LocationReport>> = HashMap::new();

        for payload in data.acsn_locations.location_payload {
            let (reports, key, idx) = if let Some(share_id) = &payload.share_id {
                let local_key = payload.loc_decrypt_key.as_ref().expect("No Local key??");

                let Some(circle_root_key) = state.share_state.secrets.values().find_map(|v| {
                    if &v.sharing_circle_identifier != share_id { return None }
                    v.circle_shared_secret()
                }) else {
                    warn!("Skipping shared payload due to missing circle secret");
                    continue
                };
                let decrypted_key = circle_root_key.decrypt(&base64_decode(&local_key))?;
                let (pub_key, priv_key) = decrypted_key.split_at(57);

                let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
                let public = EcPoint::from_bytes(&group, &pub_key, &mut context)?;
                let private_num = BigNum::from_slice(&priv_key)?;

                let priv_key = EcKey::from_private_components(&group, &private_num, &public)?;
                let reports = shared_reports.entry(share_id.clone()).or_default();
                (reports, priv_key, 0)
            } else {
                let (device, key, idx) = key_map.remove(&payload.id).expect("Not found in key map!");
                let reports = reports.entry(device).or_default();
                (reports, key, idx)
            };
            let pkey = PKey::from_ec_key(key)?;
            for location in payload.location_info {
                let payload = base64_decode(&location);
                let timestamp = apple_epoch + Duration::from_secs(u32::from_be_bytes(payload[..4].try_into().unwrap()) as u64);
                let confidence = if payload.len() == 88 { payload[4] } else { payload[5] };

                let encrypted_data = if payload.len() == 88 { &payload[5..] } else { &payload[6..] };

                let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
                let public = EcPoint::from_bytes(&group, &encrypted_data[..57], &mut context)?;
                let public = EcKey::from_public_key(&group, &public)?;
                
                let pkey_pub = PKey::from_ec_key(public)?;
                let mut deriver = Deriver::new(&pkey)?;
                deriver.set_peer(&pkey_pub)?;
                let secret = deriver.derive_to_vec()?;
                
                let symmetric = sha256(&[
                    &secret[..],
                    &[0x00, 0x00, 0x00, 0x01],
                    &encrypted_data[..57]
                ].concat());

                let cipher = AesGcm::<Aes128, U16>::new_from_slice(&symmetric[..16]).unwrap();
                let decrypted = cipher.decrypt(Nonce::from_slice(&symmetric[16..]), &encrypted_data[57..]).unwrap();

                let (_, decoded) = EncryptedReport::from_bytes((&decrypted, 0))?;
                
                reports.push(LocationReport {
                    lat: (decoded.lat as f32) / 10000000f32,
                    long: (decoded.long as f32) / 10000000f32,
                    horizontal_accuracy: decoded.horizontal_accuracy,
                    status: decoded.status,
                    confidence,
                    timestamp,
                    key_index: idx
                });
            }
        }

        let container = self.get_container().await?;
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;
        
        let mut update_records = vec![];
        for (device, reports) in reports {
            let newest_report = reports.into_iter().max_by_key(|i| i.timestamp).expect("no device?");
            info!("newest report for {device} {newest_report:?}");
            let accessory = state.accessories.get_mut(&device).expect("Accessory not found!");
            accessory.local_alignment.last_index_observed = newest_report.key_index as i64;
            accessory.local_alignment.last_index_observation_date = Some(newest_report.timestamp);

            if newest_report.key_index.saturating_sub(accessory.alignment.last_index_observed as usize) > 96 {
                accessory.alignment = accessory.local_alignment.clone();
                info!("We are behind with our stored alignment, let's update it!");
                let (op, id) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &accessory.alignment_id), 
                    &accessory.local_alignment, &key, accessory.aligment_prot_tag.take());
                accessory.aligment_prot_tag = Some(id);
                update_records.push(op);
            }
            accessory.last_report = Some(newest_report);
        }

        for (share, reports) in shared_reports {
            let newest_report = reports.into_iter().max_by_key(|i| i.timestamp).expect("no device?");

            let share_circle = state.share_state.circles_member.get(&share).expect("Shared Accessory not found circle!");

            let accessory = state.share_state.shared_beacons_client.get_mut(&share_circle.beacon_identifier).expect("Shared Accessory not found!");
            info!("newest report for {share} {newest_report:?}");

            accessory.last_report = Some(newest_report);
        }

        if !update_records.is_empty() {
            container.perform_operations_checked(&CloudKitSession::new(), &update_records, IsolationLevel::Operation).await?;
        }

        self.state.save(&state)?;

        Ok(())
    }

    pub async fn update_beacon_name(&self, new_name: &BeaconNamingRecord) -> Result<(), PushError> {
        let container = self.get_container().await?;
        
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
        let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;

        let mut state = self.state.state.lock().await;
        let accessory = state.accessories.get_mut(&new_name.associated_beacon).expect("No accessory??");

        let (op, id) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &accessory.naming_id), 
            &new_name, &key, accessory.naming_prot_tag.take());
        accessory.naming_prot_tag = Some(id);
        accessory.naming = new_name.clone();

        container.perform(&CloudKitSession::new(), op).await?;

        self.state.save(&state)?;
        Ok(())
    }

    pub async fn delete_shared_item(&self, id: &str, remove_beacon: bool) -> Result<(), PushError> {
        let container = self.get_container().await?;
        let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());

        let mut state = self.state.state.lock().await;
        
        if remove_beacon {
            state.share_state.send_circle_message(id, &self.identity, ItemSharingMessage::new(&vec![ShareIdObject {
                share_identifier: id.to_string(),
            }], 5 /* leave */)).await?;
        }

        let mut operations = vec![];
        operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), id)));

        let state = &mut *state;
        let Some(member_circle) = state.share_state.circles_member.get(id) else {
            warn!("Removing share {id} not found!");
            return Ok(())
        };



        for member in member_circle.get_members() {
            operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), &member)));
        }

        if remove_beacon {
            operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), &member_circle.beacon_identifier)));
        }

        for (inner_id, secret) in &state.share_state.secrets {
            if &secret.sharing_circle_identifier != id { continue };
            operations.push(DeleteRecordOperation::new(record_identifier(beacon_zone.clone(), &inner_id)));
        }
        
        container.perform_operations_checked(&CloudKitSession::new(), &operations, IsolationLevel::Zone).await?;

        for member in member_circle.get_members() {
            state.share_state.peer_trust_member.remove(&member);
        }
        state.share_state.tags.remove(id);
        
        if remove_beacon {
            state.share_state.shared_beacons_client.remove(&member_circle.beacon_identifier);
            state.share_state.shared_beacons.remove(&member_circle.beacon_identifier);
        }
        state.share_state.circles_member.remove(id);
        state.share_state.secrets.retain(|i, v| v.sharing_circle_identifier != id);

        self.state.save(&state)?;

        Ok(())
    }

    async fn add_shared_item(&self, payload_data: IDSSharedItem, sender: String, correlation_id: String, ns_since_epoch: u64) -> Result<Option<(String, BeaconAttributes)>, PushError> {        
        let owner = payload_data.trusted_peers.iter().find(|p| &p.display_identifier == "mailto:owner@localhost").expect("no owner??");
        let owner_shared_secret = CircleSecretKey(owner.shared_secret.key.data.clone().into());

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SharedBeaconName {
            version: u32,
            owner_beacon_identifier: String,
        }

        let mut decoded_token = DecodedCircleJoinToken::default();
        let mut secret_key = CircleSecretKey(vec![]);
        let key_packages: Vec<KeyPackage> = plist::from_bytes(payload_data.key_packages.as_ref())?;
        let mut secrets = HashMap::new();
        for package in key_packages {
            match package.r#type.as_str() {
                "joinToken" => {
                    let key = package.keys[0].decrypt(&owner_shared_secret)?;

                    decoded_token = plist::from_bytes(&key)?;
                    decoded_token.member_uuid = owner.identifier.clone();
                    
                    secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                        secret_data: plist_to_bin(&decoded_token)?,
                        sharing_circle_identifier: payload_data.share_identifier.clone(),
                        secret_type: "joinToken".to_string(),
                    });
                },
                "circleSharedSecret" => {
                    let key = package.keys[0].decrypt(&owner_shared_secret)?;
                    let secret: IDSTrustedPeerSharedSecret = plist::from_bytes(&key)?;

                    secret_key = CircleSecretKey(secret.key.data.clone().into());

                    secrets.insert(Uuid::new_v4().to_string().to_uppercase(), SharingCircleSecret {
                        secret_data: secret.key.data.into(),
                        sharing_circle_identifier: payload_data.share_identifier.clone(),
                        secret_type: "circleSharedSecret".to_string(),
                    });
                }
                _unk => {
                    warn!("Ignoring unknown secret {_unk}!");
                }
            }
        }

        
        let container = self.get_container().await?;
        self.sync_items(false).await?;
        
        // are we modifying an existing beacon (circle swapping)
        let mut is_modified = false;
        let mut was_accepted = 0;
        let state = self.state.state.lock().await;

        if let Some(old) = state.share_state.circles_member.values().find(|m| 
                m.beacon_identifier == payload_data.beacon_identifier && m.sharing_circle_identifier != payload_data.share_identifier) {
            let id = old.sharing_circle_identifier.clone();
            was_accepted = old.acceptance_state;
            drop(state);
            is_modified = true;
            self.delete_shared_item(&id, false).await?;
        } else { drop(state); }

        let communication_id = plist_to_bin(&CommunicationId {
            ids: CommunicationIdIds {
                correlation_identifier: correlation_id.clone(),
                destination: CommunicationIdIdsDestination {
                    r#type: 0,
                    destination: sender.clone(),
                }
            }
        })?;

        let shared_beacon = SharedBeaconRecord {
            product_id: payload_data.product_id,
            accepted: 1,
            owner_handle: sender.clone(),
            share_type: 2,
            correlation_identifier: correlation_id.clone(),
            share_identifier: payload_data.share_identifier.clone(),
            advertised_index: 1,
            system_version: payload_data.system_version.clone(),
            role: payload_data.role,
            share_date: Some(SystemTime::UNIX_EPOCH + Duration::from_millis(ns_since_epoch / 1000000)),
            model: payload_data.model.clone(),
            vendor_id: payload_data.vendor_id,
            name: plist_to_bin(&SharedBeaconName {
                version: 1,
                owner_beacon_identifier: payload_data.owner_beacon_identifier.unwrap_or_default(),
            })?,
        };

        let peer_entries = payload_data.trusted_peers.iter().map(|a| (a.identifier.clone(), MemberPeerTrust {
            display_identifier: if &a.display_identifier == "mailto:owner@localhost" {
                sender.clone().replace("mailto:", "").replace("tel:", "")
            } else { "".to_string() },
            communications_identifier: communication_id.clone(),
            peer_trust_shared_secret: a.shared_secret.key.data.clone().into(),
            peer_trust_type: 1,
        })).collect::<HashMap<_, _>>();

        let member_circle = MemberSharingCircle {
            owner: owner.identifier.clone(),
            sharing_circle_identifier: payload_data.share_identifier.clone(),
            acceptance_state: was_accepted,
            beacon_identifier: payload_data.beacon_identifier.clone(),
            members: plist_to_bin(&payload_data.trusted_peers.iter().flat_map(|p| {
                [
                    Value::String(p.identifier.clone()),
                    Value::Dictionary(Dictionary::from_iter([
                        ("acceptanceState", Value::Integer(1.into()))
                    ]))
                ]
            }).collect::<Vec<_>>())?,
        };

        let mut state = self.state.state.lock().await;
        // make sure the share still exists before adding it
        let queried_packages = self.query_share(&state.dsid, &member_circle, &decoded_token).await?;

        secrets.extend(Self::build_secrets(&payload_data.share_identifier, &secret_key, &queried_packages, &secrets)?);
        
        let attrs = BeaconAttributes {
            name: payload_data.beacon_name,
            role_id: payload_data.role,
            emoji: payload_data.emoji,
            system_version: payload_data.system_version,
            serial_number: "".to_string(),
        };

        // always update attributes, since these are client side.
        state.share_state.shared_beacons_client.entry(payload_data.beacon_identifier.clone()).or_default().attributes = attrs.clone();
        
        if !state.share_state.circles_member.contains_key(&payload_data.share_identifier) {
            let beacon_zone: cloudkit_proto::RecordZoneIdentifier = container.private_zone("BeaconStore".to_string());
            let key = container.get_zone_encryption_config(&beacon_zone, &self.keychain, &FIND_MY_SERVICE).await?;

            let (circle, circle_tag) = SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &payload_data.share_identifier), 
                    &member_circle, &key, None);

            let operations = [
                if !is_modified {
                    vec![SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &payload_data.beacon_identifier), 
                    &shared_beacon, &key, None).0]
                } else { vec![] },
                vec![circle],
                peer_entries.iter().map(|e| SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &e.0), 
                    &e.1, &key, None).0).collect(),
                secrets.iter().map(|e| SaveRecordOperation::new_protected(record_identifier(beacon_zone.clone(), &e.0), 
                    &e.1, &key, None).0).collect(),
            ].concat();

            container.perform_operations_checked(&CloudKitSession::new(), &operations, IsolationLevel::Zone).await?;
            state.share_state.secrets.extend(secrets);
            state.share_state.peer_trust_member.extend(peer_entries);
            state.share_state.circles_member.insert(payload_data.share_identifier.clone(), member_circle);
            if !is_modified {
                state.share_state.shared_beacons.insert(payload_data.beacon_identifier.clone(), shared_beacon);
            }
            state.share_state.tags.insert(payload_data.beacon_identifier.clone(), circle_tag);

            self.state.save(&state)?;
        }

        if is_modified {
            Ok(None)
        } else { Ok(Some((payload_data.share_identifier, attrs)))}
    }

    /// Parse an inbound `secureLocationsKeyUpdate` (T:10) message and store each friend's
    /// private key so we can fetch + decrypt their published locations.
    ///
    /// Wire format (proven from keyupdate-capture2.log):
    ///   outer bplist: { "T": 10, "V": 1, "P": <nested bplist> }
    ///   nested P bplist: [ { "hashedAdvertisement": {"key":{"data": <32B SHA256(pubkey_x)>}},
    ///                        "entityIdentifier": <findMyId = base64(friend DSID) = Follow.id>,
    ///                        "identifier": <UUID>,
    ///                        "privateKey": {"key":{"data": <85B = 04||x||y||priv>}},
    ///                        "index": <int> } ]
    ///
    /// Returns the number of friend keys stored/updated.
    async fn handle_secure_locations_key_update(&self, outer: &Value) -> Result<usize, PushError> {
        let Value::Dictionary(outer_dict) = outer else {
            return Err(PushError::KeyedArchiveError("key update: outer not a dict".to_string()));
        };

        // Only T:10 carries key material. T:7 (self-token expiration) and others are ignored.
        let msg_type = outer_dict.get("T").and_then(|v| v.as_unsigned_integer()).unwrap_or(0);
        if msg_type != 10 {
            info!("[FMF-KEYUPDATE] ignoring securelocations message T={}", msg_type);
            return Ok(0);
        }

        let Some(Value::Data(nested_bytes)) = outer_dict.get("P") else {
            return Err(PushError::KeyedArchiveError("key update: missing P payload".to_string()));
        };

        // Nested plist: array of key records.
        let nested: Value = plist::from_bytes(nested_bytes)?;
        let records = match &nested {
            Value::Array(a) => a.clone(),
            Value::Dictionary(_) => vec![nested.clone()],
            _ => return Err(PushError::KeyedArchiveError("key update: nested P not array/dict".to_string())),
        };

        let mut stored = 0usize;
        let mut state = self.state.state.lock().await;

        for rec in &records {
            let Value::Dictionary(rd) = rec else { continue };

            // findMyId = entityIdentifier (= friend's Follow.id).
            let find_my_id = rd.get("entityIdentifier").and_then(|v| v.as_string()).map(|s| s.to_string());
            let Some(find_my_id) = find_my_id else {
                info!("[FMF-KEYUPDATE]   record missing entityIdentifier, skipping");
                continue;
            };

            // privateKey.key.data = 85 bytes (04 || x(28) || y(28) || priv(28)).
            let key_data = rd.get("privateKey")
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("key"))
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("data"))
                .and_then(|v| v.as_data());
            let Some(key_data) = key_data else {
                info!("[FMF-KEYUPDATE]   record for {} missing privateKey.key.data", find_my_id);
                continue;
            };

            if key_data.len() != 85 {
                info!("[FMF-KEYUPDATE]   record for {} has key {} bytes (expected 85), skipping", find_my_id, key_data.len());
                continue;
            }
            if key_data[0] != 0x04 {
                info!("[FMF-KEYUPDATE]   record for {} key bad prefix {:#04x}, skipping", find_my_id, key_data[0]);
                continue;
            }

            let public_key = key_data[..57].to_vec();          // 04 || x || y
            let private_key = key_data[57..85].to_vec();        // priv scalar

            info!("[FMF-KEYUPDATE]   stored key for friend findMyId={} (pub first 8: {})",
                find_my_id, encode_hex(&public_key[..8]));

            state.friend_secure_keys.insert(find_my_id.clone(), FriendSecureLocationKeys {
                private_key,
                public_key,
                shared_secret: Vec::new(),
                find_my_id,
            });
            stored += 1;
        }

        if stored > 0 {
            self.state.save(&state)?;
        }
        Ok(stored)
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Vec<(String, String, BeaconAttributes)>, PushError> {
        if let Some(IDSRecvMessage { message_unenc: Some(message), topic, token: Some(token), target: Some(target), sender: Some(sender), uuid: Some(uuid), ns_since_epoch: Some(ns_since_epoch), .. }) = self.identity.receive_message(msg, &["com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd", "com.apple.private.alloy.findmy.itemsharing-crossaccount", "com.apple.icloud.searchpartyd.securelocations"]).await? {
            // Entry log: ALWAYS print which FMF/FMD message arrived so a missing receive can be
            // distinguished from "arrived but failed downstream". (No payload — names only.)
            info!("[FMF-RECV] inbound topic={} sender={} uuid={}", topic, sender, encode_hex(&uuid));
            let do_app_ack = || async {
                let targets = self.identity.cache.lock().await.get_targets(&topic, &target, &[sender.clone()], &[MessageTarget::Token(token)])?;
                self.identity.send_message(topic, IDSSendMessage {
                    sender: target.clone(),
                    raw: Raw::None,
                    send_delivered: false,
                    command: 244,
                    no_response: true,
                    id: Uuid::new_v4().to_string().to_uppercase(),
                    scheduled_ms: None,
                    queue_id: None,
                    relay: None,
                    extras: Dictionary::from_iter([
                        // response for
                        ("rI".to_string(), Value::Data(uuid.to_vec()))
                    ]),
                }, targets).await?;
                Ok::<(), PushError>(())
            };
            
            if topic == "com.apple.private.alloy.findmy.itemsharing-crossaccount" {
                let parsed: ItemSharingMessage = message.plist()?;

                let payload_data: Value = plist::from_bytes(parsed.payload.as_ref())?;
                debug!("Message came in {} {payload_data:?}", parsed.r#type);

                match parsed.r#type {
                    2 => {
                        let Some(correlation_id) = self.identity.cache.lock().await.get_correlation_id(&topic, &target, &sender) else {
                            warn!("Failed to get correlation id for sender!");
                            return Ok(vec![])
                        };
                        
                        let payload_data: Vec<IDSSharedItem> = plist::from_bytes(parsed.payload.as_ref())?;
                        let mut results = vec![];
                        for shared_item in payload_data {
                            let Some(item) = self.add_shared_item(shared_item, sender.clone(), correlation_id.clone(), ns_since_epoch).await? else { continue };
                            results.push((sender.clone(), item.0, item.1));
                        }
                        do_app_ack().await?;
                        return Ok(results)
                    },
                    7 => {
                        #[derive(Deserialize)]
                        #[serde(rename_all = "camelCase")]
                        struct DeleteItems {
                            circle_identifiers: Vec<String>
                        }

                        let payload_data: Vec<DeleteItems> = plist::from_bytes(parsed.payload.as_ref())?;
                        for payload in payload_data {
                            for circle in payload.circle_identifiers {
                                self.delete_shared_item(&circle, true).await?;
                            }
                        }
                    }
                    _ => {
                        
                    }
                }
                return Ok(vec![])
            }

            // === SECURE LOCATIONS: Log incoming location requests ===
            // Secure locations uses com.apple.private.alloy.fmd as its IDS channel.
            // We intercept fmd messages that fail to parse as FMFPayload.
            if topic == "com.apple.private.alloy.fmd" {
                // First try to parse as a generic plist Value to log it
                let raw_value: Value = match message.plist() {
                    Ok(val) => val,
                    Err(e) => {
                        info!("[FMF-SECURE-LOC] Message not parseable: {:?}", e);
                        do_app_ack().await?;
                        return Ok(vec![]);
                    }
                };

                // Always log the top-level structure of anything on fmd so we can see whether a
                // key-update (dict with T/V/P) vs a mapping packet (dict with p/v) vs something
                // unexpected arrived — even if it later takes a path that doesn't log.
                match &raw_value {
                    Value::Dictionary(d) => {
                        let keys: Vec<&String> = d.keys().collect();
                        info!("[FMF-RECV] fmd dict keys={:?}", keys);
                    },
                    other => info!("[FMF-RECV] fmd non-dict value: {:?}", &format!("{:?}", other)[..format!("{:?}", other).len().min(120)]),
                }

                // === SECURE LOCATIONS KEY UPDATE (inbound) ===
                // When a friend shares their location with us, they send a T:10 secureLocationsKeyUpdate
                // on com.apple.private.alloy.fmd (PROVEN transport — serviceIdentifier captured live)
                // containing THEIR private key. Detect the {T,V,P} envelope before the FMFPayload path.
                if let Value::Dictionary(d) = &raw_value {
                    if d.contains_key("T") && d.contains_key("P") {
                        let t = d.get("T").and_then(|v| v.as_unsigned_integer()).unwrap_or(0);
                        info!("[FMF-KEYUPDATE] securelocations envelope on fmd topic from {}: T={}", sender, t);
                        match self.handle_secure_locations_key_update(&raw_value).await {
                            Ok(stored) => info!("[FMF-KEYUPDATE] Stored/updated {} friend key(s)", stored),
                            Err(e) => info!("[FMF-KEYUPDATE] parse failed: {:?}", e),
                        }
                        do_app_ack().await?;
                        return Ok(vec![]);
                    }
                }

                // Try to interpret as FMFPayload (MappingPacket)
                let parsed_result: Result<FMFPayload, _> = plist::from_value(&raw_value);
                match parsed_result {
                    Ok(parsed) => {
                        // Regular FMF message — handle normally
                        debug!("Find my IDS message came in as {}", encode_hex(&uuid));
                        match parsed {
                            FMFPayload::MappingPacket { p } => {
                                info!("[FMF-MAPPING-RECV] MappingPacket on fmd topic from: {}", sender);
                                info!("[FMF-MAPPING-RECV]   p length: {}, first 40: {}", p.len(), &p[..p.len().min(40)]);
                                if p.starts_with('/') && p.len() > 100 {
                                    info!("[FMF-MAPPING-RECV]   Format: v1 (modified base64, 156-byte blob)");
                                    let b64 = p[1..].replace('~', "/");
                                    let decoded = base64_decode(&b64);
                                    info!("[FMF-MAPPING-RECV]   Decoded: {} bytes, byte[0]={:#04x}, is_156={}", decoded.len(), decoded.first().copied().unwrap_or(0), decoded.len() == 156);

                                    // Attempt to decrypt and extract friend's key material
                                    let mut state = self.state.state.lock().await;
                                    if let (Some(priv_key), Some(pub_key)) = (&state.secure_locations_private_key, &state.secure_locations_public_key) {
                                        let priv_arr: [u8; 28] = priv_key.clone().try_into().unwrap_or([0u8; 28]);
                                        let pub_arr: [u8; 57] = pub_key.clone().try_into().unwrap_or([0u8; 57]);
                                        match Self::decrypt_inbound_mapping_packet(&priv_arr, &pub_arr, &p) {
                                            Ok(friend_keys) => {
                                                info!("[FMF-MAPPING-RECV]   DECRYPT SUCCESS! Stored keys for sender: {}", sender);
                                                state.friend_secure_keys.insert(sender.clone(), friend_keys);
                                                let _ = self.state.save(&state);
                                            },
                                            Err(e) => {
                                                info!("[FMF-MAPPING-RECV]   Decrypt failed (need friend's pubkey): {:?}", e);
                                            }
                                        }
                                    } else {
                                        info!("[FMF-MAPPING-RECV]   No secure location keys yet, can't attempt decrypt");
                                    }
                                    drop(state);
                                } else if p.len() == 36 && p.chars().filter(|c| *c == '-').count() == 4 {
                                    info!("[FMF-MAPPING-RECV]   Format: v5 UUID: {}", p);
                                } else {
                                    info!("[FMF-MAPPING-RECV]   Format: unknown (len={})", p.len());
                                }
                                do_app_ack().await?;
                                match self.daemon.lock().await.import(self.config.as_ref(), &p).await {
                                    Ok(()) => info!("[FMF-MAPPING-RECV]   import() succeeded"),
                                    Err(e) => info!("[FMF-MAPPING-RECV]   import() failed: {:?}", e),
                                }
                            }
                        }
                        return Ok(vec![])
                    },
                    Err(_) => {
                        // NOT a MappingPacket — likely a secure location payload or key update
                        info!("[FMF-SECURE-LOC] Received non-FMF message on fmd topic!");
                        info!("[FMF-SECURE-LOC] Sender: {}", sender);
                        info!("[FMF-SECURE-LOC] Target: {}", target);
                        info!("[FMF-SECURE-LOC] Plist value: {:?}", &format!("{:?}", raw_value)[..format!("{:?}", raw_value).len().min(1000)]);
                        // Extract known v5 fields from the plist dictionary if present
                        if let Value::Dictionary(ref dict) = raw_value {
                            if let Some(p_val) = dict.get("p") {
                                info!("[FMF-SECURE-LOC]   p = {:?}", &format!("{:?}", p_val)[..format!("{:?}", p_val).len().min(200)]);
                            }
                            if let Some(v_val) = dict.get("v") {
                                info!("[FMF-SECURE-LOC]   v = {:?}", v_val);
                            }
                            if let Some(c_val) = dict.get("c") {
                                info!("[FMF-SECURE-LOC]   c = {:?}", &format!("{:?}", c_val)[..format!("{:?}", c_val).len().min(200)]);
                            }
                            if let Some(s_val) = dict.get("s") {
                                info!("[FMF-SECURE-LOC]   s = {:?}", &format!("{:?}", s_val)[..format!("{:?}", s_val).len().min(200)]);
                            }
                            // Log all top-level keys for discovery
                            let keys: Vec<&String> = dict.keys().collect();
                            info!("[FMF-SECURE-LOC]   All keys: {:?}", keys);
                        }
                        do_app_ack().await?;
                        return Ok(vec![])
                    }
                }
            }
            // === END SECURE LOCATIONS ===

            let parsed: FMFPayload = message.plist()?;
            debug!("Find my IDS message came in as {}", encode_hex(&uuid));
            match parsed {
                FMFPayload::MappingPacket { p } => {
                    info!("[FMF-MAPPING-RECV] MappingPacket on fmf topic from: {}", sender);
                    info!("[FMF-MAPPING-RECV]   p length: {}, first 40: {}", p.len(), &p[..p.len().min(40)]);
                    if p.starts_with('/') && p.len() > 100 {
                        info!("[FMF-MAPPING-RECV]   Format: v1 (modified base64, 156-byte blob)");
                        let b64 = p[1..].replace('~', "/");
                        let decoded = base64_decode(&b64);
                        info!("[FMF-MAPPING-RECV]   Decoded: {} bytes, byte[0]={:#04x}, is_156={}", decoded.len(), decoded.first().copied().unwrap_or(0), decoded.len() == 156);

                        // Attempt to decrypt and extract friend's key material
                        let mut state = self.state.state.lock().await;
                        if let (Some(priv_key), Some(pub_key)) = (&state.secure_locations_private_key, &state.secure_locations_public_key) {
                            let priv_arr: [u8; 28] = priv_key.clone().try_into().unwrap_or([0u8; 28]);
                            let pub_arr: [u8; 57] = pub_key.clone().try_into().unwrap_or([0u8; 57]);
                            match Self::decrypt_inbound_mapping_packet(&priv_arr, &pub_arr, &p) {
                                Ok(friend_keys) => {
                                    info!("[FMF-MAPPING-RECV]   DECRYPT SUCCESS! Stored keys for sender: {}", sender);
                                    state.friend_secure_keys.insert(sender.clone(), friend_keys);
                                    let _ = self.state.save(&state);
                                },
                                Err(e) => {
                                    info!("[FMF-MAPPING-RECV]   Decrypt failed (need friend's pubkey): {:?}", e);
                                }
                            }
                        } else {
                            info!("[FMF-MAPPING-RECV]   No secure location keys yet, can't attempt decrypt");
                        }
                        drop(state);
                    } else if p.len() == 36 && p.chars().filter(|c| *c == '-').count() == 4 {
                        info!("[FMF-MAPPING-RECV]   Format: v5 UUID: {}", p);
                    } else {
                        info!("[FMF-MAPPING-RECV]   Format: unknown (len={})", p.len());
                    }
                    do_app_ack().await?;
                    match self.daemon.lock().await.import(self.config.as_ref(), &p).await {
                        Ok(()) => info!("[FMF-MAPPING-RECV]   import() succeeded"),
                        Err(e) => info!("[FMF-MAPPING-RECV]   import() failed: {:?}", e),
                    }
                }
            }
        }
        Ok(vec![])
    }
}

#[derive(Serialize, Deserialize)]
pub struct LocateInProgress {
    pub id: String,
    pub status: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindMyFriendsStateUpdate {
    followers: Option<Vec<Follow>>,
    following: Option<Vec<Follow>>,
    locations: Option<Vec<LocationElement>>,
    locate_in_progress: Option<Vec<LocateInProgress>>,
    data_context: serde_json::Value,
    server_context: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct LocationElement {
    pub id: String,
    pub location: Option<Location>,
}


#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Follow {
    pub create_timestamp: i64,
    pub expires: i64,
    pub id: String,
    pub invitation_accepted_handles: Vec<String>,
    pub invitation_from_handles: Vec<String>,
    pub is_from_messages: bool,
    pub offer_id: Option<String>,
    pub only_in_event: bool,
    pub person_id_hash: String,
    pub secure_locations_capable: bool,
    pub shallow_or_live_secure_locations_capable: bool,
    pub source: String,
    pub tk_permission: bool,
    pub update_timestamp: i64,
    pub fallback_to_legacy_allowed: Option<bool>,
    pub opted_not_to_share: Option<bool>,
    #[serde(skip)]
    pub last_location: Option<Location>,
    #[serde(skip)]
    pub locate_in_progress: bool,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub address: Option<Address>,
    pub altitude: f64,
    pub floor_level: i64,
    pub horizontal_accuracy: f64,
    pub is_inaccurate: bool,
    pub latitude: f64,
    pub location_id: Option<String>,
    pub location_timestamp: Option<i64>,
    pub longitude: f64,
    pub secure_location_ts: i64,
    #[serde(alias = "timeStamp")]
    pub timestamp: i64,
    pub vertical_accuracy: f64,
    pub position_type: Option<String>,
    pub is_old: Option<bool>,
    pub location_finished: Option<bool>,
}

/// Convert a decrypted secure-location JSON payload (from findmyservice/fetch) into a
/// `Location`. The plaintext schema matches what `publish_secure_location` produces:
/// `latitude`, `longitude`, `altitude`, `horizontalAccuracy`, `verticalAccuracy`,
/// `timestamp` (Cocoa epoch seconds since 2001-01-01), etc.
pub fn location_from_secure_json(j: &serde_json::Value) -> Option<Location> {
    let latitude = j.get("latitude").and_then(|v| v.as_f64())?;
    let longitude = j.get("longitude").and_then(|v| v.as_f64())?;

    // timestamp is Cocoa epoch (seconds since 2001-01-01). Convert to Unix ms.
    let cocoa_secs = j.get("timestamp").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let unix_ms = ((cocoa_secs + 978307200.0) * 1000.0) as i64;

    Some(Location {
        address: None,
        altitude: j.get("altitude").and_then(|v| v.as_f64()).unwrap_or(0.0),
        floor_level: j.get("floor").and_then(|v| v.as_i64()).unwrap_or(0),
        horizontal_accuracy: j.get("horizontalAccuracy").and_then(|v| v.as_f64()).unwrap_or(0.0),
        is_inaccurate: false,
        latitude,
        location_id: None,
        location_timestamp: Some(unix_ms),
        longitude,
        secure_location_ts: unix_ms,
        timestamp: unix_ms,
        vertical_accuracy: j.get("verticalAccuracy").and_then(|v| v.as_f64()).unwrap_or(0.0),
        position_type: Some("secure".to_string()),
        is_old: Some(false),
        location_finished: Some(true),
    })
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub administrative_area: Option<String>,
    pub country: String,
    pub country_code: String,
    pub formatted_address_lines: Option<Vec<String>>,
    pub locality: Option<String>,
    pub state_code: Option<String>,
    pub street_address: Option<String>,
    pub street_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FoundDevice {
    pub device_model: Option<String>,
    pub low_power_mode: Option<bool>,
    pub passcode_length: Option<i64>,
    pub id: Option<String>,
    pub battery_status: Option<String>,
    pub lost_mode_capable: Option<bool>,
    pub battery_level: Option<f64>,
    pub location_enabled: Option<bool>,
    pub is_considered_accessory: Option<bool>,
    pub location: Option<Location>,
    pub model_display_name: Option<String>,
    pub device_color: Option<String>,
    pub activation_locked: Option<bool>,
    pub rm2_state: Option<i64>,
    pub loc_found_enabled: Option<bool>,
    pub nwd: Option<bool>,
    pub device_status: Option<String>,
    pub fmly_share: Option<bool>,
    pub features: HashMap<String, bool>,
    pub this_device: Option<bool>,
    pub lost_mode_enabled: Option<bool>,
    pub device_display_name: Option<String>,
    pub name: Option<String>,
    pub can_wipe_after_lock: Option<bool>,
    pub is_mac: Option<bool>,
    pub raw_device_model: Option<String>,
    #[serde(rename = "baUUID")]
    pub ba_uuid: Option<String>,
    pub device_discovery_id: Option<String>,
    pub scd: Option<bool>,
    pub location_capable: Option<bool>,
    pub wipe_in_progress: Option<bool>,
    pub dark_wake: Option<bool>,
    pub device_with_you: Option<bool>,
    pub max_msg_char: Option<i64>,
    pub device_class: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindMyPhoneStateUpdate {
    server_context: Option<serde_json::Value>,
    content: Vec<FoundDevice>,
}

pub struct FindMyPhoneClient<P: AnisetteProvider> {
    server_context: Option<serde_json::Value>,
    dsid: String,
    anisette: ArcAnisetteClient<P>,
    server: u8,
    pub devices: Vec<FoundDevice>,
    aps: APSConnection,
    token_provider: Arc<TokenProvider<P>>,
}

impl<P: AnisetteProvider> FindMyPhoneClient<P> {
    async fn make_request<T: for<'a> Deserialize<'a>>(&mut self, config: &dyn OSConfig, path: &str) -> Result<T, PushError> {
        let token = self.token_provider.get_mme_token("mmeFMIPAppToken").await?;

        let request = REQWEST.post(format!("https://p{}-fmipmobile.icloud.com/fmipservice/device/{}/{}", self.server, self.dsid, path))
            .headers(get_find_my_headers(config, "3.0", &mut *self.anisette.lock().await, "Find%20My/375.20").await?)
            .basic_auth(&self.dsid, Some(&token));

        let ms_since_epoch = duration_since_epoch().as_millis() as f64 / 1000f64;
        let meta = config.get_debug_meta();

        let token = self.aps.get_token().await;

        let client_context = json!({
            "appVersion": "7.0",
            "apsToken": encode_hex(&token).to_uppercase(),
            "clientTimestamp": ms_since_epoch,
            "deviceListVersion": 1,
            "deviceUDID": config.get_udid().to_lowercase(),
            "fmly": true,
            "inactiveTime": 0,
            "frontMostWindow": false,
            "osVersion": meta.user_version,
            "productType": meta.hardware_version,
            "push": true,
            "windowVisible": false
        });

        let raw_request: serde_json::Value = request.json(&json!({
            "clientContext": client_context,
            "tapContext": [],
            "serverContext": self.server_context,
        })).send().await?.json().await?;

        let request: FindMyPhoneStateUpdate = serde_json::from_value(raw_request.clone())?;

        self.server_context = request.server_context;
        self.devices = request.content;

        Ok(serde_json::from_value(raw_request)?)
    }


    pub async fn new(config: &dyn OSConfig, dsid: String, aps: APSConnection, anisette: ArcAnisetteClient<P>, token_provider: Arc<TokenProvider<P>>) -> Result<FindMyPhoneClient<P>, PushError> {
        let mut client = FindMyPhoneClient {
            server_context: None,
            dsid,
            anisette,
            server: rand::thread_rng().gen_range(101..=182),
            devices: vec![],
            aps,
            token_provider
        };

        let _ = client.make_request::<serde_json::Value>(config, "initClient").await?;

        Ok(client)
    }

    pub async fn refresh(&mut self, config: &dyn OSConfig) -> Result<(), PushError> {
        let _ = self.make_request::<serde_json::Value>(config, "refreshClient").await?;
        Ok(())
    }
}


pub struct FindMyFriendsClient<P: AnisetteProvider> {
    data_context: serde_json::Value,
    server_context: serde_json::Value,
    dsid: String,
    anisette: ArcAnisetteClient<P>,
    server: u8,
    pub selected_friend: Option<String>,
    pub followers: Vec<Follow>,
    pub following: Vec<Follow>,
    aps: APSConnection,
    daemon: bool,
    has_init: bool,
    token_provider: Arc<TokenProvider<P>>,
}

impl<P: AnisetteProvider> FindMyFriendsClient<P> {
    async fn make_request<T: for<'a> Deserialize<'a>>(&mut self, config: &dyn OSConfig, path: &str, data: serde_json::Value) -> Result<T, PushError> {
        let token = self.token_provider.get_mme_token("mmeFMFAppToken").await?;

        let request = REQWEST.post(format!("https://p{}-fmfmobile.icloud.com/fmipservice/friends/{}/{}/{}", self.server, 
                if self.daemon { format!("fmfd/{}", self.dsid) } else { self.dsid.clone() }, config.get_udid().to_uppercase(), path))
            .headers(get_find_my_headers(config, "2.0", &mut *self.anisette.lock().await, if self.daemon { "FMFD/1.0" } else { "Find%20My/375.20" }).await?)
            .header("X-FMF-Model-Version", "1")
            .basic_auth(&self.dsid, Some(&token));

        let ms_since_epoch = duration_since_epoch().as_millis() as f64 / 1000f64;
        let meta = config.get_debug_meta();
        let reg = config.get_register_meta();

        let token = self.aps.get_token().await;

        let client_context = if self.daemon {
            json!({
                "appName": "fmfd",
                "appVersion": "7.0",
                "apsToken": encode_hex(&token).to_uppercase(),
                "buildVersion": reg.software_version,
                "countryCode": "CA",
                "currentTime": ms_since_epoch,
                "deviceClass": "Mac",
                "deviceHasPasscode": true,
                "deviceUDID": config.get_udid().to_lowercase(),
                "fencingEnabled": true,
                "isFMFAppRemoved": false,
                "osVersion": meta.user_version,
                "platform": "macosx",
                "processId": rand::thread_rng().gen_range(600..2000u32).to_string(),
                "productType": meta.hardware_version,
                "selectedFriend": self.selected_friend,
                "regionCode": "US",
                "signedInAs": "tag3@copper.jjtech.dev",
                "timezone": "EST, -18000",
                "unlockState": 0,
            })
        } else {
            json!({
                "appPushModeAllowed": true,
                "appVersion": "7.0",
                "apsToken": encode_hex(&token).to_uppercase(),
                "countryCode": "US",
                "currentTime": ms_since_epoch,
                "deviceClass": "Mac",
                "deviceUDID": config.get_udid().to_lowercase(),
                "frontMostWindow": false,
                "legacyFallbackData": {},
                "limitedPrecision": false,
                "liveSessionStatistics": {},
                "osVersion": meta.user_version,
                "productType": meta.hardware_version,
                "pushMode": true,
                "regionCode": "US",
                "selectedFriend": self.selected_friend,
                "tabs": {
                    "currentTab": [],
                    "lastVisitedTime": [],
                    "timeSpent": []
                },
                "windowVisible": false
            })
        };

        let mut req = json!({
            "clientContext": client_context,
            "dataContext": self.data_context,
            "serverContext": self.server_context,
        });

        let serde_json::Value::Object(obj) = &mut req else { panic!() };
        let serde_json::Value::Object(data) = data else { panic!() };
        obj.extend(data.into_iter());

        let response = request.json(&req).send().await?;

        if self.daemon {
            info!("[FMF-TEST] HTTP status: {}", response.status().as_u16());
        }

        if response.status().as_u16() == 401 {
            self.token_provider.refresh_mme().await?;
        }

        let raw_request: serde_json::Value = response.json().await?;

        if self.daemon {
            info!("[FMF-TEST] Raw response body: {}", 
                serde_json::to_string(&raw_request).unwrap_or_else(|_| "parse error".to_string()));
        }

        let request: FindMyFriendsStateUpdate = serde_json::from_value(raw_request.clone())?;

        self.data_context = request.data_context;
        self.server_context = request.server_context;

    
        if let Some(followers) = request.followers {
            self.followers = followers;
        }

        if let Some(mut following) = request.following {
            for follow in &mut following {
                let Some(existing) = self.following.iter_mut().find(|i| i.id == follow.id) else { continue };
                follow.last_location = existing.last_location.take();
            }
            self.following = following;
        }

        if let Some(locations) = request.locations {
            for location in locations {
                let Some(follow) = self.following.iter_mut().find(|f| f.id == location.id) else { continue };
                follow.last_location = location.location;
            }
        }

        if let Some(locate) = request.locate_in_progress {
            for item in &mut self.following {
                item.locate_in_progress = false;
            }
            for location in locate {
                let Some(follow) = self.following.iter_mut().find(|f| f.id == location.id) else { continue };
                follow.locate_in_progress = true;
            }
        }

        Ok(serde_json::from_value(raw_request)?)
    }

    pub async fn new(config: &dyn OSConfig, dsid: String, token_provider: Arc<TokenProvider<P>>, aps: APSConnection, anisette: ArcAnisetteClient<P>, daemon: bool) -> Result<FindMyFriendsClient<P>, PushError> {
        let mut client = FindMyFriendsClient {
            data_context: json!({}),
            server_context: json!({}),
            dsid,
            anisette,
            server: rand::thread_rng().gen_range(101..=182),
            selected_friend: None,
            followers: vec![],
            following: vec![],
            aps,
            daemon,
            has_init: false,
            token_provider,
        };
        
        if !daemon {
            let _ = client.make_request::<serde_json::Value>(config, "first/initClient", json!({})).await?;
            client.has_init = true;
        }

        Ok(client)
    }   

    pub async fn refresh(&mut self, config: &dyn OSConfig) -> Result<(), PushError> {
        if !self.has_init {
            let _ = self.make_request::<serde_json::Value>(config, if self.daemon { "initClient" } else { "first/initClient" }, json!({})).await?;
            self.has_init = true;
        } else {
            // The submit_location_standalone path used to fire here as a one-shot test.
            // It's been removed because it targets the legacy /fmipservice REST endpoint
            // which Apple silently ignores (see INVESTIGATION.md §1b). The corrected
            // FMF People-surface publish path now goes through publish_secure_location,
            // triggered from sync_item_positions and refresh_background_following.
            let path = if self.selected_friend.is_some() { "minCallback/selFriend/refreshClient" } else { "minCallback/refreshClient" };
            match self.make_request::<serde_json::Value>(config, path, json!({})).await {
                Ok(response) => {
                    // Only log occasionally to avoid spam
                },
                Err(e) => {
                    log::error!("[FMF-TEST] refreshClient FAILED: {:?}", e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub async fn import(&mut self, config: &dyn OSConfig, url: &str) -> Result<(), PushError> {
        let response = self.make_request::<serde_json::Value>(config, "import", json!({"url": url})).await?;
        info!("[FMF-SECURE] Import response: {:?}", response);
        Ok(())
    }

    /// "Use this as my location" equivalent — claims the relay device as the account's location source.
    ///
    /// PROVEN via Ghidra (2026-07-16) — the actual button flow:
    ///   FMFClientSession setActiveDevice:completion:  (@ 1000209b8)
    ///     -> FMFCommandManager setActiveDevice:forSession:completion:  (@ 10004c7c4)
    ///        (note: forSession is passed NULL — no per-call session is bound)
    ///        -> alloc FMFSavePrefsCommand initWithClientSession:device:
    ///           -> sendCommand:completionBlock:
    /// FMFSavePrefsCommand:
    ///   - pathSuffix        = "savePrefs"                      (CFString @ 0x10008f500)
    ///   - jsonBodyDictionary = { meDeviceId: activeDevice.deviceId }  (@ 100014cec)
    ///
    /// This is a DIFFERENT command from FMFSaveMeCommand (pathSuffix "saveme/savePrefs",
    /// body { meDeviceId: self.deviceId }). We previously targeted saveme/savePrefs by
    /// mistake — the button never uses it.
    ///
    /// Without this call, the account's me-device stays as whatever Apple last saw (iPad/6s), and our
    /// published blob gets shadowed — followers fetch the me-device's blob, not ours.
    pub async fn claim_me_device(&mut self, config: &dyn OSConfig) -> Result<serde_json::Value, PushError> {
        // Strategy: first establish an fmfd session (refreshClient), then send the
        // savePrefs / saveme A/B.
        //
        // IDENTITY FIX (proven from logs 2026-07-16): the account's device list (the
        // `devices` array in the initClient response) contains OUR device as the 64-char
        // config.get_udid() hash — this is exactly what the server echoes as
        // myInfo.deviceId ("5b1f4f4f...c03466"). The relay's 40-char *hardware* UDID
        // (f343dd29...) is NOT in the device list at all. When we sent the hardware UDID
        // as meDeviceId, the server could not match it to any listed device and silently
        // dropped it (prefs-only response, no myInfo). So meDeviceId MUST be the
        // base64-tilde of config.get_udid(), not get_hardware_udid().
        //
        // NOTE: this UDID is a random per-install hash (generate_udid), but it is the
        // identity the server has on file for this device, so it is the correct value.
        let dev_udid = config.get_udid();
        let hw_udid_lower = dev_udid.to_lowercase();
        let hw_udid_upper = dev_udid.to_uppercase();
        let hw_id_b64 = base64_encode(hw_udid_lower.as_bytes()).replace('=', "~");
        
        info!("[FMF-MEDEVICE] Step 1: Establishing fmfd session via refreshClient (registered device UDID)");
        info!("[FMF-MEDEVICE]   dev_udid={} | meDeviceId will be base64-tilde of this (matches myInfo.deviceId)",
            hw_udid_lower);
        
        let token = self.token_provider.get_mme_token("mmeFMFAppToken").await?;
        let ms_since_epoch = duration_since_epoch().as_millis() as f64 / 1000f64;
        let meta = config.get_debug_meta();
        let reg = config.get_register_meta();
        let aps_token = encode_hex(&self.aps.get_token().await).to_uppercase();
        
        // Step 1: refreshClient (clientSessionCreated) — establishes the session
        let refresh_url = format!("https://p{}-fmfmobile.icloud.com/fmipservice/friends/fmfd/{}/{}/clientSessionCreated/refreshClient",
            self.server, self.dsid, hw_udid_upper);
        
        let refresh_body = json!({
            "clientContext": {
                "appName": "fmfd",
                "appVersion": "7.0",
                "apsToken": aps_token,
                "buildVersion": reg.software_version,
                "countryCode": "US",
                "currentTime": ms_since_epoch,
                "deviceClass": "iPhone",
                "deviceHasPasscode": false,
                "deviceUDID": hw_udid_lower,
                "fencingEnabled": true,
                "isFMFAppRemoved": false,
                "osVersion": meta.user_version,
                "platform": "iphoneos",
                "productType": meta.hardware_version,
                "selectedFriend": self.selected_friend,
                "regionCode": "US",
                "timezone": "EST, -18000",
                "unlockState": 0,
            },
            "dataContext": self.data_context,
            "serverContext": self.server_context,
        });
        
        let refresh_response = REQWEST.post(&refresh_url)
            .headers(get_find_my_headers(config, "2.0", &mut *self.anisette.lock().await, "FMFD/1.0").await?)
            .header("X-FMF-Model-Version", "1")
            .basic_auth(&self.dsid, Some(&token))
            .json(&refresh_body)
            .send().await?;
        
        let refresh_status = refresh_response.status();
        let refresh_result: serde_json::Value = refresh_response.json().await?;
        info!("[FMF-MEDEVICE] Step 1 refreshClient: HTTP {} | myInfo.meDeviceId={}",
            refresh_status,
            refresh_result.get("myInfo").and_then(|m| m.get("meDeviceId")).and_then(|v| v.as_str()).unwrap_or("<none>"));
        
        // Update our session context from the refresh response
        if let Ok(update) = serde_json::from_value::<FindMyFriendsStateUpdate>(refresh_result.clone()) {
            self.data_context = update.data_context;
            self.server_context = update.server_context;
        }
        
        // Step 2: A/B TEST of the two me-device endpoints (proven via Ghidra 2026-07-16).
        //
        // There are two sibling command classes that both set meDeviceId, triggered by
        // DIFFERENT UI flows:
        //   FMFSavePrefsCommand -> pathSuffix "savePrefs"        (user picker, body { meDeviceId: chosenDevice })
        //   FMFSaveMeCommand    -> pathSuffix "saveme/savePrefs" (server SAVEME alert, body { meDeviceId: thisDevice })
        //
        // A real device in our situation (account already has a me-device) uses the
        // picker path -> "savePrefs". But saveme/savePrefs is not inherently wrong since
        // we pass our own device id, which is what SaveMe expects too. We try savePrefs
        // FIRST, and only fall back to saveme/savePrefs if the switch didn't take, so a
        // single rebuild gives a clean A/B in the logs.
        let candidate_suffixes = ["savePrefs", "saveme/savePrefs"];
        let mut last_result = serde_json::Value::Null;

        for (idx, suffix) in candidate_suffixes.iter().enumerate() {
            info!("[FMF-MEDEVICE] Step 2.{}: POST {} with meDeviceId={}", idx, suffix, hw_id_b64);

            let url = format!("https://p{}-fmfmobile.icloud.com/fmipservice/friends/fmfd/{}/{}/{}",
                self.server, self.dsid, hw_udid_upper, suffix);

            let body = json!({
                "clientContext": {
                    "appName": "fmfd",
                    "appVersion": "7.0",
                    "apsToken": aps_token,
                    "buildVersion": reg.software_version,
                    "countryCode": "US",
                    "currentTime": duration_since_epoch().as_millis() as f64 / 1000f64,
                    "deviceClass": "iPhone",
                    "deviceHasPasscode": false,
                    "deviceUDID": hw_udid_lower,
                    "fencingEnabled": true,
                    "isFMFAppRemoved": false,
                    "osVersion": meta.user_version,
                    "platform": "iphoneos",
                    "productType": meta.hardware_version,
                    "selectedFriend": self.selected_friend,
                    "regionCode": "US",
                    "timezone": "EST, -18000",
                    "unlockState": 0,
                },
                "dataContext": self.data_context,
                "serverContext": self.server_context,
                "meDeviceId": hw_id_b64,
            });

            let response = REQWEST.post(&url)
                .headers(get_find_my_headers(config, "2.0", &mut *self.anisette.lock().await, "FMFD/1.0").await?)
                .header("X-FMF-Model-Version", "1")
                .basic_auth(&self.dsid, Some(&token))
                .json(&body)
                .send().await?;

            let status = response.status();
            let result: serde_json::Value = response.json().await?;
            let resp_str = serde_json::to_string(&result).unwrap_or_default();
            info!("[FMF-MEDEVICE] Step 2.{} [{}]: HTTP {} ({}B): {}",
                idx, suffix, status, resp_str.len(), resp_str.chars().take(800).collect::<String>());

            // Update session context from each response so the fallback uses fresh context.
            if let Ok(update) = serde_json::from_value::<FindMyFriendsStateUpdate>(result.clone()) {
                self.data_context = update.data_context;
                self.server_context = update.server_context;
            }

            let switched = result.get("myInfo")
                .and_then(|m| m.get("meDeviceId"))
                .and_then(|v| v.as_str())
                .map(|id| id == hw_id_b64)
                .unwrap_or(false);

            if let Some(my_info) = result.get("myInfo") {
                let resp_me_device_id = my_info.get("meDeviceId").and_then(|v| v.as_str()).unwrap_or("<missing>");
                info!("[FMF-MEDEVICE] Step 2.{} [{}] response myInfo.meDeviceId={}", idx, suffix, resp_me_device_id);
            } else {
                info!("[FMF-MEDEVICE] Step 2.{} [{}] ⚠ No myInfo in response", idx, suffix);
            }

            last_result = result;

            if switched {
                info!("[FMF-MEDEVICE] ✓ SUCCESS via '{}' — relay is now the me-device!", suffix);
                return Ok(last_result);
            }

            info!("[FMF-MEDEVICE] ✗ '{}' did not switch meDeviceId; {}",
                suffix,
                if idx + 1 < candidate_suffixes.len() { "trying next endpoint" } else { "no more endpoints" });
        }

        info!("[FMF-MEDEVICE] ✗ Neither endpoint switched the me-device — blocker is likely server-side device eligibility policy, not the endpoint.");
        Ok(last_result)
    }

    /// Call offerLocation endpoint to get mapping packet tokens for followers.
    /// Apple returns `commandResponse.requestTokens`: a dict of {handleId: p_blob_string}.
    /// These tokens must be relayed via IDS to each friend for them to see our location.
    /// Idempotent — safe to call for existing followers (no notification spam).
    pub async fn offer_location(&mut self, config: &dyn OSConfig, handles: &[String]) -> Result<HashMap<String, String>, PushError> {
        info!("[FMF-OFFER] Calling offerLocation for {} handles", handles.len());

        // Build idsValidatedHandles dict: {handle: 1, handle: 1, ...}
        let ids_validated: serde_json::Map<String, serde_json::Value> = handles.iter()
            .map(|h| (h.clone(), serde_json::Value::Number(1.into())))
            .collect();

        let response: serde_json::Value = self.make_request(config, "offerLocation", json!({
            "idsValidatedHandles": ids_validated,
            "groupId": "kFMFGroupIdOneToOne",
            "expires": 0,
        })).await?;

        info!("[FMF-OFFER] Raw response keys: {:?}", response.as_object().map(|o| o.keys().collect::<Vec<_>>()));

        // Extract commandResponse.requestTokens
        let tokens = response.get("commandResponse")
            .and_then(|cr| {
                info!("[FMF-OFFER] commandResponse keys: {:?}", cr.as_object().map(|o| o.keys().collect::<Vec<_>>()));
                cr.get("requestTokens")
            })
            .and_then(|rt| rt.as_object());

        let mut result = HashMap::new();
        if let Some(token_map) = tokens {
            for (handle_id, token_value) in token_map {
                if let Some(token_str) = token_value.as_str() {
                    info!("[FMF-OFFER]   token for {}: {} chars", handle_id, token_str.len());
                    result.insert(handle_id.clone(), token_str.to_string());
                }
            }
        }
        info!("[FMF-OFFER] Got {} requestTokens", result.len());
        Ok(result)
    }

    /// Ask a friend to share their location with us (invite).
    /// No requestTokens returned — the friend gets a notification to accept.
    pub async fn invite_friend(&mut self, config: &dyn OSConfig, handle: &str) -> Result<(), PushError> {
        info!("[FMF-INVITE] Inviting {} to share their location", handle);
        let response: serde_json::Value = self.make_request(config, "invite", json!({
            "emails": [handle],
            "groupId": "kFMFGroupIdOneToOne",
            "expires": 0,
        })).await?;
        info!("[FMF-INVITE] Invite sent to {}. Response keys: {:?}", handle, response.as_object().map(|o| o.keys().collect::<Vec<_>>()));
        Ok(())
    }

    /// Stop sharing our location with specific friends.
    pub async fn stop_sharing(&mut self, config: &dyn OSConfig, handles: &[String]) -> Result<(), PushError> {
        info!("[FMF-STOP] Stopping sharing with {} handles", handles.len());
        let response: serde_json::Value = self.make_request(config, "stopOffer", json!({
            "handles": handles,
            "groupId": "kFMFGroupIdOneToOne",
        })).await?;
        info!("[FMF-STOP] Stopped sharing. Response keys: {:?}", response.as_object().map(|o| o.keys().collect::<Vec<_>>()));
        Ok(())
    }

    /// Attempt to post location by impersonating the meDeviceId (iPad) in the FMF daemon request.
    /// Uses the existing mmeFMFAppToken but sends the request as if from the iPad.
    pub async fn submit_location_standalone(
        &self,
        config: &dyn OSConfig,
        latitude: f64,
        longitude: f64,
        _altitude: f64,
        _horizontal_accuracy: f64,
    ) -> Result<(), PushError> {
        let token = self.token_provider.get_mme_token("mmeFMFAppToken").await?;
        info!("[FMF-SUBMIT] Got mmeFMFAppToken, attempting iPad impersonation");

        // The iPad ECID (current meDeviceId from the FMF response)
        let ipad_ecid = "00008112-0001253C0A3BA01E";
        
        let ms_since_epoch = duration_since_epoch().as_millis() as f64 / 1000f64;
        let aps_token = encode_hex(&self.aps.get_token().await).to_uppercase();

        // Build the request as if from the iPad fmfd daemon
        let body = json!({
            "clientContext": {
                "appName": "fmfd",
                "appVersion": "7.0",
                "apsToken": aps_token,
                "countryCode": "US",
                "currentTime": ms_since_epoch,
                "deviceClass": "iPad",
                "deviceHasPasscode": true,
                "deviceUDID": ipad_ecid.to_lowercase(),
                "fencingEnabled": true,
                "isFMFAppRemoved": false,
                "osVersion": "17.7.6",
                "platform": "iphoneos",
                "productType": "iPad8,3",
                "regionCode": "US",
                "timezone": "PST, -28800",
                "unlockState": 0,
            },
            "myLocation": {
                "latitude": latitude,
                "longitude": longitude,
                "altitude": _altitude,
                "horizontalAccuracy": _horizontal_accuracy,
                "verticalAccuracy": 5.0,
                "timestamp": duration_since_epoch().as_millis() as i64,
                "floorLevel": 0,
                "isInaccurate": false,
                "positionType": "GPS",
                "isOld": false,
                "locationFinished": true,
            },
            "serverContext": self.server_context.clone(),
            "dataContext": self.data_context.clone(),
        });

        // Use the iPad ECID in the URL path
        let url = format!("https://p{}-fmfmobile.icloud.com/fmipservice/friends/fmfd/{}/{}/minCallback/refreshClient", 
            self.server, self.dsid, ipad_ecid.to_uppercase());

        info!("[FMF-SUBMIT] URL: {}", url);
        info!("[FMF-SUBMIT] myLocation: lat={}, lon={}", latitude, longitude);

        let response = REQWEST.post(&url)
            .header("X-FMF-Model-Version", "1")
            .header("Content-Type", "application/json")
            .basic_auth(&self.dsid, Some(&token))
            .json(&body)
            .send().await?;

        let status = response.status().as_u16();
        let response_body = response.text().await.unwrap_or_else(|_| "failed to read body".to_string());
        info!("[FMF-SUBMIT] Response status: {}", status);
        info!("[FMF-SUBMIT] Response body (first 500): {}", &response_body[..response_body.len().min(500)]);

        Ok(())
    }

    /// Post the device's current GPS coordinates to Apple's FMF server (LEGACY).
    /// This uses the old REST-based refreshClient endpoint which Apple may silently ignore.
    /// Prefer publish_secure_location() for the modern People surface.
    ///
    /// Requires daemon mode to be enabled (the client must be initialized with daemon=true).
    pub async fn post_location(
        &mut self,
        config: &dyn OSConfig,
        latitude: f64,
        longitude: f64,
        altitude: f64,
        horizontal_accuracy: f64,
        vertical_accuracy: f64,
    ) -> Result<(), PushError> {
        if !self.daemon {
            return Err(PushError::KeyedArchiveError("Location posting requires daemon mode".to_string()));
        }

        // Ensure we've initialized the daemon session first
        if !self.has_init {
            let _ = self.make_request::<serde_json::Value>(config, "initClient", json!({})).await?;
            self.has_init = true;
        }

        let ms_since_epoch = duration_since_epoch().as_millis() as i64;

        // Construct the location payload matching the Location struct format
        // that Apple's server returns for friends' locations.
        // Field name "myLocation" is an educated guess — alternatives:
        // "currentLocation", "location", or embedded in clientContext.
        let location_data = json!({
            "myLocation": {
                "latitude": latitude,
                "longitude": longitude,
                "altitude": altitude,
                "horizontalAccuracy": horizontal_accuracy,
                "verticalAccuracy": vertical_accuracy,
                "timestamp": ms_since_epoch,
                "floorLevel": 0,
                "isInaccurate": vertical_accuracy+horizontal_accuracy > 100.0,
                "positionType": "GPS",
                "isOld": false,
                "locationFinished": true,
            }
        });

        let _ = self.make_request::<serde_json::Value>(
            config,
            "minCallback/refreshClient",
            location_data,
        ).await?;

        Ok(())
    }
}
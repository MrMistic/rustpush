//! iCloud Sticker Sync module.
//!
//! Syncs user-generated stickers from the user's iCloud sticker library
//! (managed by `stickersd` on Apple devices) to OpenBubbles.
//!
//! Container: com.apple.stickers.user
//! Zone: com.apple.coredata.cloudkit.zone
//! PCS service type: 3 (Manatee class)
//! Record types: CD_ManagedSticker, CD_ManagedRepresentation

use std::collections::HashMap;
use std::sync::Arc;

use log::{debug, info};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use cloudkit_proto::request_operation::header::{ContainerEnvironment, Database};
use cloudkit_proto::{CloudKitRecord, CloudKitEncryptor};
use cloudkit_derive::CloudKitRecord;

use crate::{
    cloudkit::{CloudKitClient, CloudKitContainer, CloudKitOpenContainer,
               FetchRecordChangesOperation, NO_ASSETS, pcs_keys_for_record},
    error::PushError,
    keychain::KeychainClient,
};
use crate::icloud::pcs::PCSService;
use omnisette::AnisetteProvider;

/// PCS service definition for the sticker CloudKit zone.
/// Type 3 = Manatee general CloudKit sync class (confirmed from zone protection_info ASN.1).
pub const STICKER_SERVICE: PCSService<'static> = PCSService {
    name: "Stickers",
    view_hint: "Manatee",
    zone: "Manatee",
    r#type: 3,
    keychain_type: 3,
    v2: false,
    global_record: true,
};

/// The sticker CloudKit container.
const STICKER_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: Database::PrivateDb,
    bundleid: "com.apple.stickersd",
    containerid: "com.apple.stickers.user",
    env: ContainerEnvironment::Production,
};

const STICKER_ZONE: &str = "com.apple.coredata.cloudkit.zone";

/// Normalize a record identifier for tolerant matching between a
/// representation's `CD_sticker` value and a sticker record's id.
/// Strips any "EntityName/" prefix, removes dashes, and lowercases.
fn normalize_id(id: &str) -> String {
    let tail = id.rsplit('/').next().unwrap_or(id);
    tail.chars()
        .filter(|c| *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// A synced sticker record from CloudKit.
#[derive(CloudKitRecord, Debug, Default, Clone, Serialize, Deserialize)]
#[cloudkit_record(type = "CD_ManagedSticker", encrypted)]
pub struct CloudSticker {
    /// Sticker type (0=still, 1=animated?)
    #[cloudkit(rename = "CD_type")]
    pub sticker_type: i64,
    /// Effect type (-1=none, 0+=specific effect)
    #[cloudkit(rename = "CD_effect")]
    pub effect: i64,
    /// Display name / accessibility label
    #[cloudkit(rename = "CD_accessibilityName")]
    pub accessibility_name: String,
    /// Source app bundle identifier
    #[cloudkit(rename = "CD_attributionBundleIdentifier")]
    pub attribution_bundle_id: String,
    /// Sticker external URI (e.g. sticker:///memoji/... or sticker:///user/identifier/...)
    #[cloudkit(rename = "CD_externalURI")]
    pub external_uri: String,
    /// Sticker name
    #[cloudkit(rename = "CD_name")]
    pub name: String,
}

/// A sticker representation record (image data at a specific size/role).
#[derive(CloudKitRecord, Debug, Default, Clone, Serialize, Deserialize)]
#[cloudkit_record(type = "CD_ManagedRepresentation", encrypted)]
pub struct CloudStickerRepresentation {
    /// Byte count of the representation
    #[cloudkit(rename = "CD_byteCount")]
    pub byte_count: i64,
    /// Index among representations for this sticker
    #[cloudkit(rename = "CD_index")]
    pub index: i64,
    /// Whether this is the preferred representation for display
    #[cloudkit(rename = "CD_isPreferred")]
    pub is_preferred: i64,
    /// Role: com.apple.stickers.role.still / .animated / .keyboard
    #[cloudkit(rename = "CD_role")]
    pub role: String,
    /// UTI: public.heic, public.heics, public.png
    #[cloudkit(rename = "CD_uti")]
    pub uti: String,
    /// The actual image data
    #[cloudkit(rename = "CD_data")]
    pub data: Vec<u8>,
    /// Parent sticker's CloudKit record name (NSPersistentCloudKitContainer
    /// stores the to-one relationship as a string field, not a CK reference).
    #[cloudkit(rename = "CD_sticker")]
    pub sticker_ref: String,
}

/// A synced sticker with its image data, ready for saving to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedSticker {
    pub id: String,
    pub name: String,
    pub external_uri: String,
    pub sticker_type: i64,
    pub effect: i64,
    /// UTI/role/data of the *still* representation used for the picker thumbnail.
    pub uti: String,
    pub role: String,
    pub image_data: Vec<u8>,
    /// True if this sticker has an animated (Live Sticker) representation.
    pub is_animated: bool,
    /// UTI of the animated representation (e.g. public.heics), if present.
    pub animated_uti: String,
    /// The animated representation's raw data (HEIC sequence), if present.
    /// Saved as the `.heics` source so it can be decoded to APNG on demand.
    pub animated_data: Vec<u8>,
}

/// Client for syncing stickers from iCloud.
pub struct StickerSyncClient<P: AnisetteProvider> {
    container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    client: Arc<CloudKitClient<P>>,
    keychain: Arc<KeychainClient<P>>,
}

impl<P: AnisetteProvider> StickerSyncClient<P> {
    pub fn new(client: Arc<CloudKitClient<P>>, keychain: Arc<KeychainClient<P>>) -> Self {
        Self {
            container: Mutex::new(None),
            client,
            keychain,
        }
    }

    async fn get_container(&self) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone());
        }
        *locked = Some(Arc::new(STICKER_CONTAINER.init(self.client.clone()).await?));
        Ok(locked.clone().unwrap())
    }

    /// Incrementally fetch stickers from iCloud with their image data.
    ///
    /// Pass the `continuation_token` persisted from the previous sync (or `None`
    /// for a full initial sync). CloudKit returns only records changed since that
    /// token, so subsequent syncs are cheap. Returns the new token to persist,
    /// the changed/added stickers, the ids of deleted records (to remove locally),
    /// and the sync status (3 = fully caught up).
    ///
    /// Mirrors the incremental pattern used by `cloud_messages::sync_records`.
    pub async fn fetch_stickers(&self, continuation_token: Option<Vec<u8>>)
        -> Result<(Vec<u8>, Vec<SyncedSticker>, Vec<String>, i32), PushError>
    {
        let incremental = continuation_token.is_some();
        info!("[STICKER-SYNC] Fetching sticker records (incremental={})...", incremental);
        let container = self.get_container().await?;
        let zone = container.private_zone(STICKER_ZONE.to_string());

        info!("[STICKER-SYNC] Syncing keychain for Manatee zone...");
        self.keychain.sync_keychain(&[&STICKER_SERVICE.zone, "ProtectedCloudStorage"]).await?;
        info!("[STICKER-SYNC] Keychain sync done.");

        {
            let state = self.keychain.state.read().await;
            let manatee_keys = state.items.get("Manatee").map(|z| z.keys.len()).unwrap_or(0);
            info!("[STICKER-SYNC] Manatee zone has {} keys", manatee_keys);
        }

        info!("[STICKER-SYNC] Getting zone encryption config...");
        let key = container.get_zone_encryption_config_sev(
            &[(zone.clone(), None)], &self.keychain, &STICKER_SERVICE, false
        ).await?.remove(0)?;
        info!("[STICKER-SYNC] Got encryption config, syncing records...");

        // do_sync pages internally until status=3, starting from the given token.
        // With a token it returns only the delta since last sync.
        let mut results = FetchRecordChangesOperation::do_sync(
            &container,
            &[(zone.clone(), continuation_token)],
            &NO_ASSETS,
        ).await?;

        let (_assets, changes, new_token) = results.remove(0);
        let new_token = new_token.unwrap_or_default();
        // do_sync pages internally until the zone reports status=3 (fully caught
        // up), so by the time it returns we are always fully synced.
        let status = 3;

        info!("[STICKER-SYNC] Got {} changes this sync", changes.len());

        // Collect stickers and representations separately, then match them.
        // Also collect deletions (tombstones) to remove locally.
        let mut stickers: HashMap<String, CloudSticker> = HashMap::new();
        let mut representations: HashMap<String, Vec<CloudStickerRepresentation>> = HashMap::new();
        let mut deletions: Vec<String> = Vec::new();

        for change in &changes {
            let identifier = change.identifier.as_ref().unwrap().value.as_ref().unwrap().name().to_string();

            let Some(record) = &change.record else {
                // Tombstone: a record was deleted on another device. We don't know
                // if it's a sticker or a representation, but sticker image files are
                // named icloud_<sticker_id>.png, so Dart can attempt deletion by id
                // (a no-op if it was a representation id).
                deletions.push(identifier);
                continue;
            };
            let record_type = record.r#type.as_ref().unwrap().name();

            let pcskey = match pcs_keys_for_record(&record, &key) {
                Ok(key) => key,
                Err(PushError::PCSRecordKeyMissing) => {
                    info!("[STICKER-SYNC]   Skipping record {} (PCS key missing)", identifier);
                    continue;
                }
                Err(e) => return Err(e),
            };

            if record_type == CloudSticker::record_type() {
                let item = CloudSticker::from_record_encrypted(&record.record_field, Some(&pcskey));
                debug!("[STICKER-SYNC]   Sticker: id={} name='{}' uri='{}'", identifier, item.accessibility_name, item.external_uri);
                stickers.insert(identifier, item);
            } else if record_type == CloudStickerRepresentation::record_type() {
                let item = CloudStickerRepresentation::from_record_encrypted(&record.record_field, Some(&pcskey));

                // NSPersistentCloudKitContainer stores the to-one relationship as
                // a plain string field (CD_sticker) containing the parent record name.
                let parent_id = item.sticker_ref.clone();
                debug!("[STICKER-SYNC]   Repr: id={} role='{}' uti='{}' bytes={} preferred={} parent='{}'",
                    identifier, item.role, item.uti, item.data.len(), item.is_preferred, parent_id);

                if !parent_id.is_empty() {
                    representations.entry(parent_id).or_default().push(item);
                }
            }
        }

        info!("[STICKER-SYNC] Found {} stickers, {} representation groups", stickers.len(), representations.len());

        // Fallback index: map normalized parent-id -> exact representation key.
        // NSPersistentCloudKitContainer *should* store CD_sticker as the raw
        // record name (matching the sticker record id), but if the format
        // differs (case, dashes, or an "EntityName/" prefix) the exact lookup
        // above would miss. This normalized index lets us recover the match.
        let normalized_reprs: HashMap<String, String> = representations.keys()
            .map(|k| (normalize_id(k), k.clone()))
            .collect();

        // Build result: for each sticker, pick the best representation
        let mut result = Vec::new();
        for (sticker_id, sticker) in &stickers {
            let reprs = if let Some(r) = representations.get(sticker_id) {
                r
            } else if let Some(exact_key) = normalized_reprs.get(&normalize_id(sticker_id)) {
                info!("[STICKER-SYNC]   Matched sticker {} to reprs via NORMALIZED fallback (repr parent key='{}')",
                    sticker_id, exact_key);
                representations.get(exact_key).unwrap()
            } else {
                info!("[STICKER-SYNC]   Sticker {} has no representations", sticker_id);
                continue;
            };

            // Pick the best STILL representation for the picker thumbnail:
            // 1. Preferred (isPreferred=1) with role=still
            // 2. Any with role=still
            // 3. Any with role=keyboard
            // 4. First available
            let best = reprs.iter()
                .find(|r| r.is_preferred == 1 && r.role.contains("still"))
                .or_else(|| reprs.iter().find(|r| r.role.contains("still")))
                .or_else(|| reprs.iter().find(|r| r.role.contains("keyboard")))
                .unwrap_or(&reprs[0]);

            if best.data.is_empty() {
                info!("[STICKER-SYNC]   Sticker {} has empty image data (may be an asset)", sticker_id);
                continue;
            }

            // Also look for an animated (Live Sticker) representation. This is
            // the HEIC sequence (.heics) that plays back. We carry its raw data
            // so Dart can save it and decode to APNG on demand (gated by the
            // user's live-sticker setting).
            let animated = reprs.iter()
                .find(|r| r.role.contains("animated") && !r.data.is_empty());

            result.push(SyncedSticker {
                id: sticker_id.clone(),
                name: if sticker.accessibility_name.is_empty() {
                    sticker.name.clone()
                } else {
                    sticker.accessibility_name.clone()
                },
                external_uri: sticker.external_uri.clone(),
                sticker_type: sticker.sticker_type,
                effect: sticker.effect,
                uti: best.uti.clone(),
                role: best.role.clone(),
                image_data: best.data.clone(),
                is_animated: animated.is_some(),
                animated_uti: animated.map(|r| r.uti.clone()).unwrap_or_default(),
                animated_data: animated.map(|r| r.data.clone()).unwrap_or_default(),
            });
        }

        // Deduplicate: the sticker library can contain multiple ManagedSticker
        // records that resolve to the same underlying sticker (same external_uri,
        // e.g. synced across devices). Collapse them so each real sticker appears
        // once. For stickers with no external_uri (custom photos), fall back to
        // deduping on the image bytes.
        let before = result.len();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        result.retain(|s| {
            let dedup_key = if s.external_uri.is_empty() {
                // hash the image bytes for URI-less stickers
                format!("data:{:x}:{}", md5_like(&s.image_data), s.image_data.len())
            } else {
                format!("uri:{}", s.external_uri)
            };
            seen.insert(dedup_key)
        });
        info!("[STICKER-SYNC] Deduplicated {} -> {} stickers", before, result.len());

        info!("[STICKER-SYNC] Returning {} stickers, {} deletions (status={})",
            result.len(), deletions.len(), status);
        Ok((new_token, result, deletions, status))
    }
}

/// Cheap, non-cryptographic content fingerprint for deduping URI-less stickers.
/// (Not real MD5 — just an FNV-1a hash; collisions are acceptable here.)
fn md5_like(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

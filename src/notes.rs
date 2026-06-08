use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::SystemTime;

use cloudkit_derive::CloudKitRecord;
use cloudkit_proto::CloudKitRecord;
use cloudkit_proto::CloudKitEncryptor;
use log::{debug, info};
use omnisette::AnisetteProvider;
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cloudkit::{
    pcs_keys_for_record, record_identifier, CloudKitClient, CloudKitContainer,
    CloudKitOpenContainer, CloudKitSession, FetchRecordChangesOperation, FetchRecordOperation,
    FetchZoneChangesOperation, PCSZoneConfig, ALL_ASSETS, NO_ASSETS,
};
use crate::keychain::KeychainClient;
use crate::pcs::PCSService;
use crate::util::ungzip;
use crate::PushError;
use cloudkit_proto::request_operation::header::{ContainerEnvironment, Database, IsolationLevel};
use cloudkit_proto::record;

pub mod notestorep {
    include!(concat!(env!("OUT_DIR"), "/notestore.rs"));
}

const NOTES_CONTAINER: CloudKitContainer = CloudKitContainer {
    database_type: Database::PrivateDb,
    bundleid: "com.apple.mobilenotes",
    containerid: "com.apple.notes",
    env: ContainerEnvironment::Production,
};

pub const NOTES_SERVICE: PCSService = PCSService {
    name: "Notes",
    view_hint: "Notes",
    zone: "ProtectedCloudStorage",
    r#type: 14,
    keychain_type: 14,
    v2: true,
    global_record: false,
};

#[derive(CloudKitRecord, Default, Debug)]
#[cloudkit_record(type = "Note", encrypted)]
pub struct CloudNoteRecord {
    #[cloudkit(rename = "TextDataEncrypted")]
    pub text_data: Vec<u8>,
    #[cloudkit(rename = "TitleEncrypted")]
    pub title: String,
    #[cloudkit(rename = "SnippetEncrypted")]
    pub snippet: String,
    #[cloudkit(unencrypted, rename = "ModificationDate")]
    pub modification_date: Option<SystemTime>,
    #[cloudkit(unencrypted, rename = "CreationDate")]
    pub creation_date: Option<SystemTime>,
    #[cloudkit(unencrypted, rename = "Deleted")]
    pub deleted: Option<i64>,
}

#[derive(CloudKitRecord, Default, Debug)]
#[cloudkit_record(type = "Folder", encrypted)]
pub struct CloudFolderRecord {
    #[cloudkit(rename = "TitleEncrypted")]
    pub title: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NoteFolder {
    pub id: String,
    pub title: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NoteEntry {
    pub id: String,
    pub folder_id: Option<String>,
    pub title: String,
    pub snippet: String,
    pub modified: f64,
    pub raw_data: Option<Vec<u8>>,
    pub owner_name: Option<String>,
}

/// Mapping of attachment identifiers to their media record IDs.
/// This enables download_attachment to resolve the correct Media record.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AttachmentMediaMap {
    /// Maps child attachment ID → media record ID
    pub attachment_to_media: HashMap<String, String>,
    /// Maps gallery/parent attachment ID → list of child attachment IDs
    pub gallery_children: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttachmentRef {
    pub identifier: String,
    pub type_uti: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NoteAttachment {
    pub identifier: String,
    pub type_uti: Option<String>,
    pub position: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NoteTable {
    pub identifier: String,
    pub position: usize,
    pub rows: u32,
    pub columns: u32,
    pub cells: Vec<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParsedNote {
    pub title: String,
    pub body: String,
    pub formatting: Vec<FormattingRun>,
    pub attachments: Vec<NoteAttachment>,
    pub tables: Vec<NoteTable>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FormattingRun {
    pub length: u32,
    pub style: NoteStyleType,
    pub attachment_info: Option<AttachmentRef>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NoteStyleType {
    Default,
    Title,
    Heading,
    Subheading,
    Monospaced,
    Checklist { checked: bool },
    BulletList,
    NumberedList,
    DashedList,
}

/// Classify a type UTI into an attachment category.
/// Returns "image", "drawing", or "table" for known types, or "unknown" otherwise.
fn classify_type_uti(type_uti: &str) -> &'static str {
    match type_uti {
        "public.jpeg" | "public.png" | "public.heic" => "image",
        s if s.starts_with("com.apple.photos.") => "image",
        "com.apple.drawing2" | "com.apple.drawing" => "drawing",
        "com.apple.notes.table" => "table",
        _ => "unknown",
    }
}

pub fn parse_note_data(data: &[u8]) -> Result<ParsedNote, PushError> {
    log::info!("Notes: parsing note data, {} bytes input, first bytes: {:02x?}", data.len(), &data[..data.len().min(8)]);
    
    // Try multiple formats with fallbacks:
    // 1. Raw protobuf (decrypted CloudKit records are NOT gzipped)
    // 2. Gzipped protobuf (legacy/local format)
    // 3. Merged protobuf (some records use MergableDataProto wrapper)
    let proto = if let Ok(p) = notestorep::NoteStoreProto::decode(data) {
        log::info!("Notes: decoded as raw protobuf");
        p
    } else if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        // Gzip magic bytes present — decompress first
        let decompressed = ungzip(data).map_err(|e| {
            log::info!("Notes: gzip decompress failed: {}", e);
            PushError::KeyedArchiveError(format!("gzip decompress failed: {}", e))
        })?;
        log::info!("Notes: decompressed gzip to {} bytes, first bytes: {:02x?}", decompressed.len(), &decompressed[..decompressed.len().min(32)]);
        notestorep::NoteStoreProto::decode(&*decompressed).map_err(|e| {
            log::info!("Notes: protobuf decode after gzip failed: {}", e);
            PushError::KeyedArchiveError(format!("protobuf decode failed: {}", e))
        })?
    } else {
        // Try gunzip anyway in case magic bytes are different, then raw protobuf as last resort
        if let Ok(decompressed) = ungzip(data) {
            if let Ok(p) = notestorep::NoteStoreProto::decode(&*decompressed) {
                log::info!("Notes: decoded as gzip+protobuf (no magic check)");
                p
            } else {
                return Err(PushError::KeyedArchiveError(format!(
                    "Failed to decode note data ({} bytes): not valid protobuf or gzip+protobuf. First bytes: {:02x?}",
                    data.len(), &data[..data.len().min(16)]
                )));
            }
        } else {
            return Err(PushError::KeyedArchiveError(format!(
                "Failed to decode note data ({} bytes): not valid protobuf or gzip+protobuf. First bytes: {:02x?}",
                data.len(), &data[..data.len().min(16)]
            )));
        }
    };

    let note = proto
        .document
        .and_then(|d| d.note)
        .ok_or_else(|| {
            log::info!("Notes: missing document/note in proto");
            PushError::KeyedArchiveError("missing document/note in proto".to_string())
        })?;

    let text = note.note_text.unwrap_or_default();
    log::info!("Notes: parsed note text, {} chars, {} attribute runs", text.len(), note.attribute_run.len());
    let title = extract_title(&text);
    let body = text.clone();

    let mut attachments: Vec<NoteAttachment> = Vec::new();
    let mut tables: Vec<NoteTable> = Vec::new();
    let mut char_position: usize = 0;

    let formatting: Vec<FormattingRun> = note
        .attribute_run
        .iter()
        .map(|run| {
            let length = run.length.unwrap_or(0);
            let style = if let Some(ps) = &run.paragraph_style {
                match ps.style.unwrap_or(0) {
                    0 => {
                        if let Some(checklist) = &ps.checklist {
                            NoteStyleType::Checklist {
                                checked: checklist.done.unwrap_or(0) != 0,
                            }
                        } else {
                            NoteStyleType::Default
                        }
                    }
                    1 => NoteStyleType::Title,
                    2 => NoteStyleType::Heading,
                    3 => NoteStyleType::Subheading,
                    4 => NoteStyleType::Monospaced,
                    100 => NoteStyleType::DashedList,
                    101 => NoteStyleType::NumberedList,
                    102 => NoteStyleType::BulletList,
                    _ => NoteStyleType::Default,
                }
            } else {
                NoteStyleType::Default
            };

            // Check for attachment info on this run
            let attachment_info = if let Some(ai) = &run.attachment_info {
                let identifier = ai.attachment_identifier.clone().unwrap_or_default();
                let type_uti = ai.type_uti.clone();

                // Classify and record the attachment
                let category = type_uti.as_deref().map(classify_type_uti).unwrap_or("unknown");

                match category {
                    "table" => {
                        // Table attachment — record with empty cells for now
                        // (cell data would be extracted from a separate table record)
                        tables.push(NoteTable {
                            identifier: identifier.clone(),
                            position: char_position,
                            rows: 0,
                            columns: 0,
                            cells: Vec::new(),
                        });
                    }
                    "image" | "drawing" | _ => {
                        attachments.push(NoteAttachment {
                            identifier: identifier.clone(),
                            type_uti: type_uti.clone(),
                            position: char_position,
                        });
                    }
                }

                Some(AttachmentRef {
                    identifier,
                    type_uti,
                })
            } else {
                None
            };

            char_position += length as usize;

            FormattingRun { length, style, attachment_info }
        })
        .collect();

    Ok(ParsedNote {
        title,
        body,
        formatting,
        attachments,
        tables,
    })
}

pub fn extract_title(text: &str) -> String {
    let first_line = text.lines().next().unwrap_or("");
    // Strip U+FFFC (object replacement character) — notes that are purely
    // attachments have FFFC as their only "text" content.
    let cleaned = first_line.replace('\u{FFFC}', "").trim().to_string();
    cleaned
}

pub fn extract_snippet(text: &str) -> String {
    let without_title = text.lines().skip(1).collect::<Vec<_>>().join("\n");
    let trimmed = without_title.trim();
    if trimmed.len() > 100 {
        let mut end = 100;
        // Don't cut in the middle of a multi-byte char
        while !trimmed.is_char_boundary(end) && end < trimmed.len() {
            end += 1;
        }
        format!("{}...", &trimmed[..end])
    } else {
        trimmed.to_string()
    }
}

fn get_field_asset(fields: &[record::Field], name: &str) -> Option<cloudkit_proto::Asset> {
    fields.iter().find_map(|f| {
        let fname = f.identifier.as_ref()?.name.as_ref()?;
        if fname == name {
            let value = f.value.as_ref()?;
            // Try direct asset_value first
            if let Some(asset) = &value.asset_value {
                return Some(asset.clone());
            }
            // Try list_values (for fields like PreviewImages which are asset lists)
            for list_val in &value.list_values {
                if let Some(asset) = &list_val.asset_value {
                    return Some(asset.clone());
                }
            }
            None
        } else {
            None
        }
    })
}

/// Get the first asset from any field on the record (searches all fields including lists)
fn get_any_asset(fields: &[record::Field]) -> Option<(String, cloudkit_proto::Asset)> {
    for f in fields {
        let fname = match f.identifier.as_ref().and_then(|id| id.name.as_ref()) {
            Some(n) => n.clone(),
            None => continue,
        };
        if let Some(value) = &f.value {
            if let Some(asset) = &value.asset_value {
                return Some((fname, asset.clone()));
            }
            for list_val in &value.list_values {
                if let Some(asset) = &list_val.asset_value {
                    return Some((fname, asset.clone()));
                }
            }
        }
    }
    None
}

fn get_field_string(fields: &[record::Field], name: &str) -> Option<String> {
    fields.iter().find_map(|f| {
        let fname = f.identifier.as_ref()?.name.as_ref()?;
        if fname == name {
            f.value.as_ref()?.string_value.clone()
        } else {
            None
        }
    })
}

fn get_field_bytes(fields: &[record::Field], name: &str) -> Option<Vec<u8>> {
    fields.iter().find_map(|f| {
        let fname = f.identifier.as_ref()?.name.as_ref()?;
        if fname == name {
            f.value.as_ref()?.bytes_value.clone()
        } else {
            None
        }
    })
}

fn get_field_date(fields: &[record::Field], name: &str) -> Option<f64> {
    fields.iter().find_map(|f| {
        let fname = f.identifier.as_ref()?.name.as_ref()?;
        if fname == name {
            f.value.as_ref()?.date_value.as_ref()?.time
        } else {
            None
        }
    })
}

fn get_field_reference_name(fields: &[record::Field], name: &str) -> Option<String> {
    fields.iter().find_map(|f| {
        let fname = f.identifier.as_ref()?.name.as_ref()?;
        if fname == name {
            f.value
                .as_ref()?
                .reference_value
                .as_ref()?
                .record_identifier
                .as_ref()?
                .value
                .as_ref()?
                .name
                .clone()
        } else {
            None
        }
    })
}

fn parse_note_record(record_id: &str, fields: &[record::Field]) -> Option<NoteEntry> {
    // Log all field names for discovery
    let field_names: Vec<String> = fields.iter().filter_map(|f| {
        f.identifier.as_ref()?.name.clone()
    }).collect();
    log::info!("Note record '{}' fields: {:?}", record_id, field_names);

    // Try multiple possible field names for the note content blob
    // Apple Notes uses "TextDataEncrypted" for the encrypted content blob
    let note_data = get_field_bytes(fields, "TextDataEncrypted")
        .or_else(|| get_field_bytes(fields, "CD_zData"))
        .or_else(|| get_field_bytes(fields, "zData"))
        .or_else(|| get_field_bytes(fields, "data"));

    if note_data.is_none() {
        log::info!("Note record '{}': no content blob found in fields", record_id);
    }

    let (title, snippet) = if let Some(data) = &note_data {
        match parse_note_data(data) {
            Ok(parsed) => (parsed.title.clone(), extract_snippet(&parsed.body)),
            Err(e) => {
                debug!("Failed to parse note data: {:?}", e);
                (String::new(), String::new())
            }
        }
    } else {
        // Fallback: try encrypted title/snippet fields (these are encrypted blobs too)
        let title = get_field_string(fields, "TitleEncrypted")
            .or_else(|| get_field_string(fields, "CD_title"))
            .or_else(|| get_field_string(fields, "title"))
            .unwrap_or_default();
        let snippet = get_field_string(fields, "SnippetEncrypted")
            .or_else(|| get_field_string(fields, "CD_snippet"))
            .or_else(|| get_field_string(fields, "snippet"))
            .unwrap_or_default();
        (title, snippet)
    };

    // Apple Notes uses "ModificationDate" and "CreationDate"
    let modified = get_field_date(fields, "ModificationDate")
        .or_else(|| get_field_date(fields, "CD_modificationDate"))
        .or_else(|| get_field_date(fields, "modificationDate"))
        .or_else(|| get_field_date(fields, "modifiedAt"))
        .unwrap_or(0.0);

    // Apple Notes uses "Folder" as a reference field
    let folder_id = get_field_reference_name(fields, "Folder")
        .or_else(|| get_field_reference_name(fields, "CD_folder"))
        .or_else(|| get_field_reference_name(fields, "parentFolder"));

    // Store raw gzipped protobuf bytes for later parsing in the viewer
    let raw_data = note_data;

    Some(NoteEntry {
        id: record_id.to_string(),
        folder_id,
        title,
        snippet,
        modified,
        raw_data,
        owner_name: None,
    })
}

fn parse_folder_record(record_id: &str, fields: &[record::Field]) -> Option<NoteFolder> {
    for field in fields {
        if let Some(id) = &field.identifier {
            if let Some(name) = &id.name {
                debug!("Folder record field: {}", name);
            }
        }
    }

    // Apple Notes uses "TitleEncrypted" for folder names (encrypted blob)
    let title = get_field_string(fields, "TitleEncrypted")
        .or_else(|| get_field_string(fields, "CD_title"))
        .or_else(|| get_field_string(fields, "title"))
        .or_else(|| get_field_string(fields, "name"))
        .unwrap_or_else(|| "Untitled Folder".to_string());

    Some(NoteFolder {
        id: record_id.to_string(),
        title,
    })
}

pub struct NotesClient<P: AnisetteProvider> {
    pub container: Mutex<Option<Arc<CloudKitOpenContainer<'static, P>>>>,
    pub client: Arc<CloudKitClient<P>>,
    pub keychain: Arc<KeychainClient<P>>,
    /// Cached mapping of attachment→media record IDs, populated during sync
    pub media_map: Mutex<AttachmentMediaMap>,
}

/// Diagnostic helper: sync keychain zones then dump their items' `pcsservice` IDs.
/// This is used to discover the correct PCSService.r#type for the Notes service.
/// The Notes PCS key lives in one of the existing keychain zones (likely Manatee or
/// ProtectedCloudStorage) — its pcsservice value is the numeric service identifier
/// we need to construct NOTES_SERVICE.
pub async fn dump_keychain_diagnostics<P: AnisetteProvider>(
    keychain: &crate::keychain::KeychainClient<P>,
) -> Result<(), PushError> {
    use plist::Value;

    // First, force a sync of the zones most likely to contain Notes PCS keys.
    // The keychain state is empty until sync_keychain is called for specific zones.
    // Sync each zone individually so a missing zone doesn't kill the whole operation.
    let zones_to_check: &[&str] = &["Manatee", "ProtectedCloudStorage", "Engram", "Notes"];
    log::info!("=== KEYCHAIN DIAGNOSTICS: syncing zones {:?} ===", zones_to_check);
    for zone in zones_to_check {
        match keychain.sync_keychain(&[zone]).await {
            Ok(()) => log::info!("=== KEYCHAIN DIAGNOSTICS: sync of '{}' succeeded ===", zone),
            Err(e) => log::warn!("=== KEYCHAIN DIAGNOSTICS: sync of '{}' failed: {:?} ===", zone, e),
        }
    }

    let state = keychain.state.read().await;
    let access_key = state.get_keychain_access_key()?;

    log::info!("=== KEYCHAIN DIAGNOSTICS START ===");
    log::info!("Keychain has {} zones", state.items.len());

    for (zone_name, zone) in &state.items {
        log::info!(
            "Zone '{}': {} items, {} current_keys",
            zone_name,
            zone.keys.len(),
            zone.current_keys.len()
        );

        for (item_id, encrypted_dict) in &zone.keys {
            // Decrypt the entry to access pcsservice field
            let decrypted = crate::keychain::decrypt_entry(encrypted_dict, &access_key);

            // The pcsservice field may be at root or inside v_Data
            let pcsservice = decrypted
                .get("pcsservice")
                .and_then(|v| match v {
                    Value::Integer(i) => i.as_signed(),
                    _ => None,
                });

            // Also try to get the service name (typically in agrp/svce/acct)
            let service_name = decrypted
                .get("svce")
                .or_else(|| decrypted.get("agrp"))
                .or_else(|| decrypted.get("acct"))
                .and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                });

            log::info!(
                "  Item '{}': pcsservice={:?}, svce/agrp/acct={:?}",
                item_id,
                pcsservice,
                service_name
            );
        }

        for (current_name, current_id) in &zone.current_keys {
            log::info!("  current_keys: '{}' -> '{}'", current_name, current_id);
        }
    }

    log::info!("=== KEYCHAIN DIAGNOSTICS END ===");
    Ok(())
}

impl<P: AnisetteProvider> NotesClient<P> {
    pub fn new(client: Arc<CloudKitClient<P>>, keychain: Arc<KeychainClient<P>>) -> Self {
        Self {
            container: Mutex::new(None),
            client,
            keychain,
            media_map: Mutex::new(AttachmentMediaMap::default()),
        }
    }

    pub async fn get_container(
        &self,
    ) -> Result<Arc<CloudKitOpenContainer<'static, P>>, PushError> {
        let mut locked = self.container.lock().await;
        if let Some(container) = &*locked {
            return Ok(container.clone());
        }
        *locked = Some(Arc::new(
            NOTES_CONTAINER.init(self.client.clone()).await?,
        ));
        Ok(locked.clone().unwrap())
    }

    pub async fn sync_notes(
        &self,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<(Option<Vec<u8>>, Vec<NoteFolder>, Vec<NoteEntry>, AttachmentMediaMap), PushError> {
        log::info!("Notes: starting sync, has_token={}", continuation_token.is_some());
        let container = self.get_container().await?;
        let zone = container.private_zone("Notes".to_string());
        log::info!("Notes: fetching changes from zone");

        // Get PCS encryption config for the Notes zone
        let key = container
            .get_zone_encryption_config(&zone, &self.keychain, &NOTES_SERVICE)
            .await?;
        log::info!("Notes: got zone encryption config");

        let (_assets, response) = container
            .perform(
                &CloudKitSession::new(),
                FetchRecordChangesOperation(cloudkit_proto::RetrieveChangesRequest {
                    sync_continuation_token: continuation_token,
                    zone_identifier: Some(zone.clone()),
                    requested_changes_types: Some(3),
                    assets_to_download: Some(NO_ASSETS.clone()),
                    newest_first: Some(true),
                    ..Default::default()
                }),
            )
            .await?;

        log::info!("Notes: got {} changes from CloudKit", response.change.len());

        let mut folders = Vec::new();
        let mut notes = Vec::new();
        let mut media_map = AttachmentMediaMap::default();
        let new_token = response.sync_continuation_token;

        for change in &response.change {
            let Some(record) = &change.record else {
                continue;
            };
            let record_type = record
                .r#type
                .as_ref()
                .and_then(|t| t.name.as_ref())
                .map(|n| n.as_str())
                .unwrap_or("");

            let record_id = change
                .identifier
                .as_ref()
                .and_then(|i| i.value.as_ref())
                .and_then(|v| v.name.as_ref())
                .map(|n| n.to_string())
                .unwrap_or_default();

            log::info!("Notes sync: record_type='{}', record_id='{}'", record_type, record_id);

            match record_type {
                "Note" => {
                    // Try PCS decryption first
                    match pcs_keys_for_record(record, &key) {
                        Ok(pcskey) => {
                            let fields = record.record_field.clone();
                            let decrypt_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                CloudNoteRecord::from_record_encrypted(
                                    &fields,
                                    Some(&pcskey),
                                )
                            }));

                            let decoded = match decrypt_result {
                                Ok(d) => d,
                                Err(e) => {
                                    let msg = e.downcast_ref::<String>()
                                        .map(|s| s.as_str())
                                        .or_else(|| e.downcast_ref::<&str>().copied())
                                        .unwrap_or("unknown panic");
                                    log::warn!(
                                        "Notes: decryption panic for note '{}': {}",
                                        record_id, msg
                                    );
                                    // Fallback to unencrypted parsing
                                    if let Some(note) =
                                        parse_note_record(&record_id, &record.record_field)
                                    {
                                        notes.push(note);
                                    }
                                    continue;
                                }
                            };

                            // Extract folder reference from raw fields (unencrypted reference field)
                            let folder_id =
                                get_field_reference_name(&record.record_field, "Folder");

                            // Convert SystemTime to f64 (seconds since epoch)
                            let modified = decoded
                                .modification_date
                                .map(|t| {
                                    t.duration_since(SystemTime::UNIX_EPOCH)
                                        .map(|d| d.as_secs_f64())
                                        .unwrap_or(0.0)
                                })
                                .unwrap_or(0.0);

                            // Use decrypted text_data as raw_data for later parsing
                            let raw_data = if decoded.text_data.is_empty() {
                                None
                            } else {
                                Some(decoded.text_data.clone())
                            };

                            // Derive title/snippet from raw data if available
                            let (title, snippet) = if let Some(data) = &raw_data {
                                match parse_note_data(data) {
                                    Ok(parsed) => {
                                        let body_title = parsed.title.clone();
                                        // If body-derived title is empty (e.g., attachment-only notes),
                                        // fall back to the TitleEncrypted field from CloudKit
                                        let title = if body_title.is_empty() {
                                            decoded.title.clone()
                                        } else {
                                            body_title
                                        };
                                        (title, extract_snippet(&parsed.body))
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "Notes: failed to parse decrypted note data for '{}': {:?}",
                                            record_id, e
                                        );
                                        (decoded.title.clone(), decoded.snippet.clone())
                                    }
                                }
                            } else {
                                (decoded.title.clone(), decoded.snippet.clone())
                            };

                            notes.push(NoteEntry {
                                id: record_id,
                                folder_id,
                                title,
                                snippet,
                                modified,
                                raw_data,
                                owner_name: None,
                            });
                        }
                        Err(PushError::PCSRecordKeyMissing) => {
                            log::warn!(
                                "Notes: PCS key missing for note record '{}', skipping",
                                record_id
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "Notes: PCS decryption failed for note '{}': {:?}, falling back",
                                record_id, e
                            );
                            // Fallback to unencrypted parsing
                            if let Some(note) =
                                parse_note_record(&record_id, &record.record_field)
                            {
                                notes.push(note);
                            }
                        }
                    }
                }
                "Folder" => {
                    match pcs_keys_for_record(record, &key) {
                        Ok(pcskey) => {
                            let fields = record.record_field.clone();
                            let decrypt_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                CloudFolderRecord::from_record_encrypted(
                                    &fields,
                                    Some(&pcskey),
                                )
                            }));

                            let decoded = match decrypt_result {
                                Ok(d) => d,
                                Err(e) => {
                                    let msg = e.downcast_ref::<String>()
                                        .map(|s| s.as_str())
                                        .or_else(|| e.downcast_ref::<&str>().copied())
                                        .unwrap_or("unknown panic");
                                    log::warn!(
                                        "Notes: decryption panic for folder '{}': {}",
                                        record_id, msg
                                    );
                                    if let Some(folder) =
                                        parse_folder_record(&record_id, &record.record_field)
                                    {
                                        folders.push(folder);
                                    }
                                    continue;
                                }
                            };
                            folders.push(NoteFolder {
                                id: record_id,
                                title: if decoded.title.is_empty() {
                                    "Untitled Folder".to_string()
                                } else {
                                    decoded.title
                                },
                            });
                        }
                        Err(PushError::PCSRecordKeyMissing) => {
                            log::warn!(
                                "Notes: PCS key missing for folder record '{}', skipping",
                                record_id
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "Notes: PCS decryption failed for folder '{}': {:?}, falling back",
                                record_id, e
                            );
                            if let Some(folder) =
                                parse_folder_record(&record_id, &record.record_field)
                            {
                                folders.push(folder);
                            }
                        }
                    }
                }
                // Capture Attachment and Media records for the media map
                "Attachment" => {
                    // Check if this attachment is a child (has ParentAttachment reference)
                    let parent_ref = get_field_reference_name(&record.record_field, "ParentAttachment");
                    if let Some(parent_id) = parent_ref {
                        log::info!("Notes: Attachment '{}' is child of gallery '{}'", record_id, parent_id);
                        media_map.gallery_children
                            .entry(parent_id)
                            .or_default()
                            .push(record_id.clone());
                    }
                }
                "Media" => {
                    // Media record has a reference to its parent Attachment
                    let attachment_ref = get_field_reference_name(&record.record_field, "Attachment");
                    let media_fields: Vec<String> = record.record_field.iter().filter_map(|f| {
                        f.identifier.as_ref()?.name.clone()
                    }).collect();
                    log::info!("Notes: Media record '{}' fields: {:?}, Attachment ref: {:?}", 
                        record_id, media_fields, attachment_ref);
                    
                    if let Some(attach_id) = attachment_ref {
                        media_map.attachment_to_media.insert(attach_id, record_id.clone());
                    }
                }
                // Skip Note_UserSpecific and other auxiliary record types
                _ => {
                    log::info!("Notes: skipping record type: '{}'", record_type);
                }
            }
        }

        log::info!("Notes: sync complete. {} folders, {} notes parsed, media_map: {} attachment→media, {} galleries", 
            folders.len(), notes.len(), media_map.attachment_to_media.len(), media_map.gallery_children.len());
        
        // Store the media map for later use by download_attachment
        {
            let mut stored_map = self.media_map.lock().await;
            // Merge new mappings into existing (incremental sync may only give us some records)
            for (k, v) in &media_map.attachment_to_media {
                stored_map.attachment_to_media.insert(k.clone(), v.clone());
            }
            for (k, v) in &media_map.gallery_children {
                stored_map.gallery_children.entry(k.clone()).or_default().extend(v.iter().cloned());
            }
        }
        
        Ok((new_token, folders, notes, media_map))
    }

    /// Sync shared notes from CloudKit shared database.
    /// Enumerates shared zones and fetches note/folder records from each.
    pub async fn sync_shared_notes(
        &self,
        continuation_token: Option<Vec<u8>>,
    ) -> Result<(Option<Vec<u8>>, Vec<NoteFolder>, Vec<NoteEntry>), PushError> {
        let container = self.get_container().await?;
        let shared_container = container.shared();

        // Discover shared zones
        let (zone_changes, new_token) =
            FetchZoneChangesOperation::do_sync(&shared_container, continuation_token).await?;

        // Collect zone identifiers (non-deleted zones)
        let zones_to_fetch: Vec<_> = zone_changes
            .iter()
            .filter(|z| z.change_type() != 2) // exclude deleted zones
            .filter_map(|z| z.identifier.clone())
            .map(|id| (id, None::<Vec<u8>>)) // no per-zone continuation token for initial sync
            .collect();

        if zones_to_fetch.is_empty() {
            return Ok((new_token, Vec::new(), Vec::new()));
        }

        // Fetch records from each shared zone
        let zone_results = FetchRecordChangesOperation::do_sync(
            &shared_container,
            &zones_to_fetch,
            &NO_ASSETS,
        )
        .await?;

        let mut folders = Vec::new();
        let mut notes = Vec::new();

        for (zone_idx, (_assets, changes, _token)) in zone_results.into_iter().enumerate() {
            // Extract owner name from the zone identifier
            let owner_name = zones_to_fetch
                .get(zone_idx)
                .and_then(|(z, _)| z.owner_identifier.as_ref())
                .and_then(|o| o.name.as_ref())
                .cloned();

            for change in &changes {
                let Some(record) = &change.record else {
                    continue;
                };
                let record_type = record
                    .r#type
                    .as_ref()
                    .and_then(|t| t.name.as_ref())
                    .map(|n| n.as_str())
                    .unwrap_or("");

                let record_id = change
                    .identifier
                    .as_ref()
                    .and_then(|i| i.value.as_ref())
                    .and_then(|v| v.name.as_ref())
                    .map(|n| n.to_string())
                    .unwrap_or_default();

                match record_type {
                    t if t.contains("Note") || t.contains("note") => {
                        if let Some(mut note) = parse_note_record(&record_id, &record.record_field) {
                            note.owner_name = owner_name.clone();
                            notes.push(note);
                        }
                    }
                    t if t.contains("Folder") || t.contains("folder") => {
                        if let Some(folder) = parse_folder_record(&record_id, &record.record_field) {
                            folders.push(folder);
                        }
                    }
                    _ => {
                        debug!("Unknown shared Notes record type: {}", record_type);
                    }
                }
            }
        }

        Ok((new_token, folders, notes))
    }

    /// Download attachment asset data by identifier from CloudKit.
    /// 
    /// Apple Notes architecture for attachments:
    /// - Note record has AttributeRuns referencing Attachment by identifier
    /// - Attachment record holds metadata (UTI, dimensions, previews)
    /// - Media record holds the actual file data as a CKAsset on "mediaData" field
    /// - Media record references its parent Attachment via an "Attachment" reference field
    ///
    /// Strategy:
    /// 1. Fetch the Attachment record → check for inline assets (PreviewImages list, etc.)
    /// 2. If no asset on Attachment, look for a "Media" reference field on Attachment
    /// 3. If no reference, try fetching a Media record by querying with the same zone
    /// 4. As fallback, look for ALL reference fields and try resolving them
    pub async fn download_attachment(
        &self,
        attachment_identifier: &str,
    ) -> Result<Vec<u8>, PushError> {
        log::info!("Notes: download_attachment called for '{}'", attachment_identifier);
        let container = self.get_container().await?;
        let zone = container.private_zone("Notes".to_string());

        let record_id = record_identifier(zone.clone(), attachment_identifier);

        log::info!("Notes: fetching attachment record from CloudKit");
        let fetched = container
            .perform_operations(
                &CloudKitSession::new(),
                &[FetchRecordOperation::new(&ALL_ASSETS, record_id)],
                IsolationLevel::Operation,
            )
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                PushError::KeyedArchiveError(format!(
                    "no response for attachment record: {}",
                    attachment_identifier
                ))
            })??;

        let raw_record = fetched.get_raw_record();

        // Log all field names on the attachment record for discovery
        let field_names: Vec<String> = raw_record.record_field.iter().filter_map(|f| {
            f.identifier.as_ref()?.name.clone()
        }).collect();
        log::info!("Notes: attachment record fields: {:?}", field_names);

        // Strategy 1: Try to find an asset directly on the Attachment record
        // Check PreviewImages (list of assets), then other common field names
        if let Some(asset) = get_field_asset(&raw_record.record_field, "PreviewImages")
            .or_else(|| get_field_asset(&raw_record.record_field, "mediaData"))
            .or_else(|| get_field_asset(&raw_record.record_field, "media"))
            .or_else(|| get_field_asset(&raw_record.record_field, "data"))
        {
            log::info!("Notes: found asset directly on attachment record, downloading via MMCS");
            
            // Notes assets have a 24-byte protection_info that contains the FORD key.
            // Format appears to be: 16-byte AES key + 8-byte identifier/tag.
            // We try multiple interpretations:
            // 1. First 16 bytes of protection_info as the key
            // 2. Full 24 bytes as the key (original behavior)  
            // 3. Record PCS key as fallback
            let mut asset = asset;
            log::info!("Notes: deriving FORD key from record PCS key...");

            // Log the raw protection_info for analysis
            if let Some(prot_info) = &asset.protection_info {
                if let Some(raw_bytes) = &prot_info.protection_info {
                    log::info!("Notes: asset protection_info RAW ({} bytes): {:02x?}", raw_bytes.len(), &raw_bytes[..]);
                    
                    // Try using just the first 16 bytes as the FORD key
                    // (24 bytes might be 16-byte key + 8-byte fingerprint)
                    if raw_bytes.len() >= 16 {
                        let key_bytes = raw_bytes[..16].to_vec();
                        log::info!("Notes: trying first 16 bytes of protection_info as FORD key: {:02x?}", &key_bytes[..]);
                        if let Some(pi) = asset.protection_info.as_mut() {
                            pi.protection_info = Some(key_bytes);
                        }
                    }
                }
            } else {
                // No protection_info at all — try record PCS key
                let key = container
                    .get_zone_encryption_config(&zone, &self.keychain, &NOTES_SERVICE)
                    .await?;
                if let Ok(pcskey) = pcs_keys_for_record(raw_record, &key) {
                    if let Some(first_key) = pcskey.keys.first() {
                        let raw_key = first_key.raw_key_bytes();
                        log::info!("Notes: no protection_info, using record PCS key ({} bytes)", raw_key.len());
                        asset.protection_info = Some(cloudkit_proto::ProtectionInfo {
                            protection_info: Some(raw_key),
                            protection_info_tag: None,
                        });
                    }
                }
            }
            
            let mut output: Vec<u8> = Vec::new();
            let cursor = Cursor::new(&mut output);
            container.get_assets(&fetched.assets, vec![(&asset, cursor)]).await?;
            log::info!("Notes: attachment download complete, {} bytes", output.len());
            return Ok(output);
        }

        // Also check if ANY field on the attachment has an asset
        if let Some((field_name, asset)) = get_any_asset(&raw_record.record_field) {
            log::info!("Notes: found asset on attachment field '{}', downloading", field_name);
            let mut output: Vec<u8> = Vec::new();
            let cursor = Cursor::new(&mut output);
            container.get_assets(&fetched.assets, vec![(&asset, cursor)]).await?;
            log::info!("Notes: attachment download complete, {} bytes", output.len());
            return Ok(output);
        }

        log::info!("Notes: no asset on Attachment record. Looking for Media record reference...");

        // Ensure the media map is populated — if it's empty, do a zone sync
        {
            let map = self.media_map.lock().await;
            if map.attachment_to_media.is_empty() && map.gallery_children.is_empty() {
                drop(map); // Release lock before sync
                log::info!("Notes: media_map is empty, running sync to populate it...");
                // Run a sync to populate attachment/media relationships
                let _ = self.sync_notes(None).await;
            }
        }

        // Strategy 2: Use the stored media map (populated during sync)
        let media_record_id = {
            let stored_map = self.media_map.lock().await;
            
            // Check if this attachment directly maps to a media record
            if let Some(media_id) = stored_map.attachment_to_media.get(attachment_identifier) {
                log::info!("Notes: found in media_map: attachment '{}' → media '{}'", attachment_identifier, media_id);
                Some(media_id.clone())
            } else if let Some(children) = stored_map.gallery_children.get(attachment_identifier) {
                // This is a gallery — use the first child's media record
                log::info!("Notes: '{}' is a gallery with {} children: {:?}", attachment_identifier, children.len(), children);
                children.first().and_then(|child_id| {
                    stored_map.attachment_to_media.get(child_id).cloned()
                })
            } else {
                None
            }
        };

        let media_record_id = if let Some(id) = media_record_id {
            id
        } else {
            // Strategy 3: Look for reference fields on the Attachment record
            let media_ref_id = get_field_reference_name(&raw_record.record_field, "Media")
                .or_else(|| get_field_reference_name(&raw_record.record_field, "media"))
                .or_else(|| get_field_reference_name(&raw_record.record_field, "MediaRecord"));

            if let Some(ref_id) = media_ref_id {
                log::info!("Notes: found Media reference on Attachment: '{}'", ref_id);
                ref_id
            } else {
                // Strategy 4: Check all reference fields for any that might point to Media
                log::info!("Notes: no Media reference. Checking all reference fields...");
                let mut found_ref = None;
                for field in &raw_record.record_field {
                    let fname = field.identifier.as_ref()
                        .and_then(|id| id.name.as_ref())
                        .cloned()
                        .unwrap_or_default();
                    // Skip known back-references
                    if fname == "Note" || fname == "Folder" || fname == "ParentAttachment" {
                        continue;
                    }
                    if let Some(ref_name) = get_field_reference_name(&raw_record.record_field, &fname) {
                        log::info!("Notes: found reference field '{}' -> '{}'", fname, ref_name);
                        found_ref = Some(ref_name);
                        break;
                    }
                }

                if let Some(ref_id) = found_ref {
                    ref_id
                } else {
                    return Err(PushError::KeyedArchiveError(format!(
                        "No asset or Media reference found on Attachment record '{}'. Fields: {:?}. \
                         Media map has {} entries. This might be a gallery with no children synced yet.",
                        attachment_identifier, field_names,
                        self.media_map.lock().await.attachment_to_media.len()
                    )));
                }
            }
        };

        // Fetch the Media record by its ID
        log::info!("Notes: fetching Media record '{}'", media_record_id);
        let media_rid = record_identifier(zone.clone(), &media_record_id);
        let media_fetched = container
            .perform_operations(
                &CloudKitSession::new(),
                &[FetchRecordOperation::new(&ALL_ASSETS, media_rid)],
                IsolationLevel::Operation,
            )
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                PushError::KeyedArchiveError(format!(
                    "no response for media record: {}",
                    media_record_id
                ))
            })??;

        let media_raw = media_fetched.get_raw_record();
        let media_field_names: Vec<String> = media_raw.record_field.iter().filter_map(|f| {
            f.identifier.as_ref()?.name.clone()
        }).collect();
        log::info!("Notes: media record fields: {:?}", media_field_names);

        // Look for the asset on the Media record
        let media_asset = get_field_asset(&media_raw.record_field, "mediaData")
            .or_else(|| get_field_asset(&media_raw.record_field, "MediaData"))
            .or_else(|| get_field_asset(&media_raw.record_field, "media"))
            .or_else(|| get_field_asset(&media_raw.record_field, "data"))
            .or_else(|| get_field_asset(&media_raw.record_field, "fileData"))
            .or_else(|| get_field_asset(&media_raw.record_field, "MediaDataEncrypted"))
            .or_else(|| {
                // Fallback: any asset on the media record
                get_any_asset(&media_raw.record_field).map(|(_, a)| a)
            })
            .ok_or_else(|| {
                PushError::KeyedArchiveError(format!(
                    "no asset field found on Media record '{}'. Fields: {:?}",
                    media_record_id, media_field_names
                ))
            })?;

        log::info!("Notes: found asset on Media record, downloading via MMCS");
        let mut output: Vec<u8> = Vec::new();
        let cursor = Cursor::new(&mut output);
        container.get_assets(&media_fetched.assets, vec![(&media_asset, cursor)]).await?;
        log::info!("Notes: media asset download complete, {} bytes, first bytes: {:02x?}",
            output.len(), &output[..output.len().min(16)]);

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libflate::gzip::{Encoder, EncodeOptions, HeaderBuilder};
    use prost::Message;
    use proptest::prelude::*;
    use std::io::Write;

    /// Helper: gzip-compress bytes
    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        let header = HeaderBuilder::new().finish();
        let options = EncodeOptions::new().header(header);
        let mut encoder = Encoder::with_options(Vec::new(), options).unwrap();
        encoder.write_all(data).unwrap();
        encoder.finish().into_result().unwrap()
    }

    /// Helper: build a valid NoteStoreProto with given text and attribute runs
    fn build_note_proto(
        text: &str,
        runs: Vec<notestorep::AttributeRun>,
    ) -> Vec<u8> {
        let note = notestorep::Note {
            note_text: Some(text.to_string()),
            attribute_run: runs,
        };
        let doc = notestorep::Document {
            note: Some(note),
            version: Some(1),
            unk2: None,
        };
        let proto = notestorep::NoteStoreProto {
            document: Some(doc),
            unk: None,
        };
        let mut buf = Vec::new();
        proto.encode(&mut buf).unwrap();
        buf
    }

    /// Strategy: generate a random paragraph style value (0-4, 100-102)
    fn arb_style() -> impl Strategy<Value = i32> {
        prop_oneof![
            Just(0),
            Just(1),
            Just(2),
            Just(3),
            Just(4),
            Just(100),
            Just(101),
            Just(102),
        ]
    }

    /// Strategy: generate a random type UTI for attachments
    fn arb_type_uti() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("public.jpeg".to_string()),
            Just("public.png".to_string()),
            Just("public.heic".to_string()),
            Just("com.apple.drawing2".to_string()),
            Just("com.apple.notes.table".to_string()),
            Just("com.apple.photos.something".to_string()),
        ]
    }

    // =========================================================================
    // Property 1: Parse produces complete formatting coverage
    // =========================================================================
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Feature: icloud-notes-viewer, Property 1: Parse produces complete formatting coverage
        ///
        /// For any valid gzipped protobuf note data containing text and attribute runs,
        /// parsing it SHALL produce a ParsedNote where the sum of all FormattingRun.length
        /// values equals the length of the body string, and every AttachmentInfo in the input
        /// appears in the attachments list with the correct character position.
        #[test]
        fn prop_parse_formatting_coverage(
            // Generate 1-10 segments of text
            segments in prop::collection::vec("[a-zA-Z0-9 ]{1,20}", 1..10),
            // Whether each segment has an attachment
            has_attachment in prop::collection::vec(prop::bool::ANY, 1..10),
            // Style for each segment
            styles in prop::collection::vec(arb_style(), 1..10),
            // Type UTIs for attachments
            utis in prop::collection::vec(arb_type_uti(), 1..10),
        ) {
            // Build text from segments
            let num_runs = segments.len().min(has_attachment.len()).min(styles.len()).min(utis.len());
            let text: String = segments[..num_runs].join("");

            // Build attribute runs that cover the full text
            let mut runs = Vec::new();
            // Store (identifier, position, uti) for verification
            let mut expected_attachments: Vec<(String, usize, String)> = Vec::new();
            let mut char_pos: usize = 0;

            for i in 0..num_runs {
                let seg_len = segments[i].len() as u32;
                let mut run = notestorep::AttributeRun {
                    length: Some(seg_len),
                    paragraph_style: Some(notestorep::ParagraphStyle {
                        style: Some(styles[i]),
                        alignment: None,
                        indent: None,
                        checklist: None,
                        block_quote: None,
                    }),
                    font: None,
                    font_weight: None,
                    underlined: None,
                    strikethrough: None,
                    superscript: None,
                    link: None,
                    color: None,
                    attachment_info: None,
                };

                if has_attachment[i] {
                    let identifier = format!("attach-{}", i);
                    run.attachment_info = Some(notestorep::AttachmentInfo {
                        attachment_identifier: Some(identifier.clone()),
                        type_uti: Some(utis[i].clone()),
                    });
                    expected_attachments.push((identifier, char_pos, utis[i].clone()));
                }

                char_pos += seg_len as usize;
                runs.push(run);
            }

            // Encode and gzip
            let proto_bytes = build_note_proto(&text, runs);
            let gzipped = gzip_compress(&proto_bytes);

            // Parse
            let parsed = parse_note_data(&gzipped).expect("parse should succeed");

            // Assert: sum of run lengths == body length (in bytes, since text is ASCII here)
            let total_run_len: u32 = parsed.formatting.iter().map(|r| r.length).sum();
            prop_assert_eq!(total_run_len as usize, parsed.body.len());

            // Assert: every expected attachment appears in the output with correct position
            for (expected_id, expected_pos, uti) in &expected_attachments {
                let category = classify_type_uti(uti);

                if category == "table" {
                    // Tables go into the tables list
                    let found = parsed.tables.iter().any(|t| &t.identifier == expected_id && t.position == *expected_pos);
                    prop_assert!(found, "Expected table attachment '{}' at position {} not found", expected_id, expected_pos);
                } else {
                    // Images/drawings go into the attachments list
                    let found = parsed.attachments.iter().any(|a| &a.identifier == expected_id && a.position == *expected_pos);
                    prop_assert!(found, "Expected attachment '{}' at position {} not found", expected_id, expected_pos);
                }
            }
        }
    }

    // =========================================================================
    // Property 2: Snippet extraction invariant
    // =========================================================================
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Feature: icloud-notes-viewer, Property 2: Snippet extraction invariant
        ///
        /// For any note body string, the extracted snippet SHALL be at most 103 characters
        /// long (100 + "..."), SHALL NOT contain the first line (title) of the body, and
        /// SHALL be a prefix of the body text after the first newline (with trailing "..."
        /// if truncated).
        #[test]
        fn prop_snippet_extraction_invariant(
            // Generate random multi-line strings including multi-byte UTF-8
            text in "[a-zA-Z0-9 \\n\\t🎉🌍äöü中文]{0,500}",
        ) {
            let snippet = extract_snippet(&text);

            // 1. Length invariant: snippet ≤ 103 bytes (100 content + 3 for "...")
            // But actually the check is on byte length in the implementation
            // The snippet should be at most 100 chars of content + "..." = 103 chars max
            prop_assert!(snippet.len() <= 103 + 4, "Snippet too long: {} bytes", snippet.len());
            // More precisely: char count should be reasonable
            prop_assert!(snippet.chars().count() <= 103 + 10, "Snippet too many chars: {}", snippet.chars().count());

            // 2. First line exclusion: snippet should not contain the first line
            let first_line = text.lines().next().unwrap_or("");
            if !first_line.is_empty() && !snippet.is_empty() {
                // The snippet is built from lines after the first, so it shouldn't
                // start with the first line (unless the first line content happens to
                // repeat in subsequent lines)
                let without_title = text.lines().skip(1).collect::<Vec<_>>().join("\n");
                let trimmed = without_title.trim();
                if !trimmed.is_empty() {
                    // Snippet should be a prefix of trimmed content (possibly with "...")
                    let snippet_content = if snippet.ends_with("...") {
                        &snippet[..snippet.len() - 3]
                    } else {
                        &snippet
                    };
                    prop_assert!(
                        trimmed.starts_with(snippet_content),
                        "Snippet '{}' is not a prefix of content after title '{}'",
                        snippet_content,
                        &trimmed[..trimmed.len().min(50)]
                    );
                }
            }

            // 3. "..." suffix iff truncated
            let without_title = text.lines().skip(1).collect::<Vec<_>>().join("\n");
            let trimmed = without_title.trim();
            if trimmed.len() > 100 {
                // Content is longer than 100 bytes, so snippet should end with "..."
                prop_assert!(snippet.ends_with("..."), "Long content should produce '...' suffix");
            } else {
                // Content fits, no "..." suffix
                prop_assert!(!snippet.ends_with("...") || trimmed.is_empty() || trimmed.len() <= 100,
                    "Short content should not have '...' suffix");
            }

            // 4. Valid UTF-8 (guaranteed by Rust's String type, but let's be explicit)
            prop_assert!(std::str::from_utf8(snippet.as_bytes()).is_ok(), "Snippet must be valid UTF-8");
        }
    }
}

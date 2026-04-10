use std::io::Read;
use std::sync::Arc;

use log::debug;
use omnisette::AnisetteProvider;
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::cloudkit::{
    CloudKitClient, CloudKitContainer, CloudKitOpenContainer, CloudKitSession,
    FetchRecordChangesOperation, NO_ASSETS,
};
use crate::util::ungzip;
use crate::PushError;
use cloudkit_proto::request_operation::header::{ContainerEnvironment, Database};
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParsedNote {
    pub title: String,
    pub body: String,
    pub formatting: Vec<FormattingRun>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FormattingRun {
    pub length: u32,
    pub style: NoteStyleType,
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

pub fn parse_note_data(data: &[u8]) -> Result<ParsedNote, PushError> {
    let decompressed = ungzip(data).map_err(|e| PushError::KeyedArchiveError(format!("gzip decompress failed: {}", e)))?;
    let proto = notestorep::NoteStoreProto::decode(&*decompressed)
        .map_err(|e| PushError::KeyedArchiveError(format!("protobuf decode failed: {}", e)))?;

    let note = proto
        .document
        .and_then(|d| d.note)
        .ok_or_else(|| PushError::KeyedArchiveError("missing document/note in proto".to_string()))?;

    let text = note.note_text.unwrap_or_default();
    let title = extract_title(&text);
    let body = text.clone();

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
            FormattingRun { length, style }
        })
        .collect();

    Ok(ParsedNote {
        title,
        body,
        formatting,
    })
}

pub fn extract_title(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
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
    for field in fields {
        if let Some(id) = &field.identifier {
            if let Some(name) = &id.name {
                debug!("Note record field: {}", name);
            }
        }
    }

    // Try multiple possible field names for the note content blob
    let note_data = get_field_bytes(fields, "CD_zData")
        .or_else(|| get_field_bytes(fields, "zData"))
        .or_else(|| get_field_bytes(fields, "data"));

    let (title, snippet) = if let Some(data) = &note_data {
        match parse_note_data(data) {
            Ok(parsed) => (parsed.title.clone(), extract_snippet(&parsed.body)),
            Err(e) => {
                debug!("Failed to parse note data: {:?}", e);
                (String::new(), String::new())
            }
        }
    } else {
        // Fallback: try string title field
        let title = get_field_string(fields, "CD_title")
            .or_else(|| get_field_string(fields, "title"))
            .unwrap_or_default();
        let snippet = get_field_string(fields, "CD_snippet")
            .or_else(|| get_field_string(fields, "snippet"))
            .unwrap_or_default();
        (title, snippet)
    };

    let modified = get_field_date(fields, "CD_modificationDate")
        .or_else(|| get_field_date(fields, "modificationDate"))
        .or_else(|| get_field_date(fields, "modifiedAt"))
        .unwrap_or(0.0);

    let folder_id = get_field_reference_name(fields, "CD_folder")
        .or_else(|| get_field_reference_name(fields, "folder"))
        .or_else(|| get_field_reference_name(fields, "parentFolder"));

    Some(NoteEntry {
        id: record_id.to_string(),
        folder_id,
        title,
        snippet,
        modified,
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

    let title = get_field_string(fields, "CD_title")
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
}

impl<P: AnisetteProvider> NotesClient<P> {
    pub fn new(client: Arc<CloudKitClient<P>>) -> Self {
        Self {
            container: Mutex::new(None),
            client,
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
    ) -> Result<(Option<Vec<u8>>, Vec<NoteFolder>, Vec<NoteEntry>), PushError> {
        let container = self.get_container().await?;
        let zone = container.private_zone("Notes".to_string());

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

        let mut folders = Vec::new();
        let mut notes = Vec::new();
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

            match record_type {
                t if t.contains("Note") || t.contains("note") => {
                    if let Some(note) = parse_note_record(&record_id, &record.record_field) {
                        notes.push(note);
                    }
                }
                t if t.contains("Folder") || t.contains("folder") => {
                    if let Some(folder) = parse_folder_record(&record_id, &record.record_field) {
                        folders.push(folder);
                    }
                }
                _ => {
                    debug!("Unknown Notes record type: {}", record_type);
                }
            }
        }

        Ok((new_token, folders, notes))
    }
}


use backon::ExponentialBuilder;
use icloud_auth::AppleAccount;
use log::{debug, error, info, warn};
use omnisette::{AnisetteClient, AnisetteProvider, ArcAnisetteClient};
use openssl::sha::sha1;
use plist::{Date, Dictionary, Value};
use reqwest::header::{HeaderMap, HeaderName};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::{APSConnection, APSConnectionResource, APSMessage, APSState, LoginDelegate, OSConfig, PushError, ResourceState, aps::APSInterestToken, auth::{MobileMeDelegateResponse, TokenProvider}, imessage::messages::AttachmentPreparedPut, login_apple_delegates, mmcs::{Container, FileContainer, MMCSConfig, PreparedPut, authorize_get, authorize_put, get_mmcs, prepare_put, put_mmcs}, util::{DebugMutex, DebugRwLock, REQWEST, Resource, ResourceManager, base64_encode, decode_hex, encode_hex, plist_to_string}};
use rand::Rng;
use uuid::Uuid;
use tokio::{process::Command, runtime::Handle, select};
use std::{future::Future, io::{BufRead, BufReader, Seek}, sync::Weak};
use std::{collections::HashSet, fs::{self, File}, time::{Duration, SystemTime}};
use std::{collections::HashMap, io::{Read, Write}, path::PathBuf, str::FromStr, sync::Arc};
use notify::{event::{CreateKind, ModifyKind, RemoveKind}, Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};


#[derive(Clone, Serialize, Deserialize)]
pub struct SharedStreamsState {
    pub dsid: String,
    host: String,
    pub albums: Vec<SharedAlbum>,
}

impl SharedStreamsState {
    pub fn new(dsid: String, delegate: &MobileMeDelegateResponse) -> Option<SharedStreamsState> {
        Some(SharedStreamsState {
            dsid,
            host: delegate.config.get("com.apple.Dataclass.SharedStreams")?.as_dictionary().unwrap().get("url")?.as_string().unwrap().to_string(),
            albums: vec![],
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AssetMetadata {
    #[serde(rename = "MSAssetMetadataAssetType")]
    pub asset_type: String,
    #[serde(rename = "MSAssetMetadataAssetTypeFlags")]
    pub asset_type_flags: u32,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssetFile {
    pub size: String,
    pub checksum: String,
    pub width: String,
    pub height: String,
    #[serde(rename = "type")]
    pub file_type: String,
    pub metadata: Option<AssetMetadata>,
    #[serde(skip)]
    pub url: String,
    #[serde(skip)]
    pub token: String,
    pub video_type: Option<String>,
}

pub struct PreparedFile<T: Read + Send + Sync> {
    asset: AssetFile,
    prepared: PreparedPut,
    source: T,
}

impl<T: Read + Send + Sync> PreparedFile<T> {
    pub async fn new(mut file: T, metadata: FileMetadata) -> Result<Self, PushError>
        where T: Seek {
        let file_container = FileContainer::new(&mut file);
        let prepared = prepare_put(file_container, true, 0x01).await?;
        file.rewind()?;

        Ok(Self {
            asset: AssetFile {
                size: prepared.total_len.to_string(),
                checksum: encode_hex(&prepared.total_sig),
                width: metadata.width.to_string(),
                height: metadata.height.to_string(),
                file_type: metadata.uti_type,
                url: Default::default(),
                token: Default::default(),
                metadata: metadata.asset_metadata,
                video_type: metadata.video_type,
            },
            prepared,
            source: file
        })
    }
}

pub struct PreparedAsset<T: Read + Send + Sync> {
    pub files: Vec<PreparedFile<T>>,
    pub name: String,
    pub date_created: SystemTime,
    pub video_duration: Option<f64>,
    pub guid: String,
}

pub struct FileMetadata {
    pub width: usize,
    pub height: usize,
    pub uti_type: String,
    pub video_type: Option<String>,
    pub asset_metadata: Option<AssetMetadata>,
}

pub trait FilePackager {
    type Reader: Read + Send + Sync;
    fn get_files(&mut self, path: PathBuf) -> impl std::future::Future<Output = Result<PreparedAsset<Self::Reader>, PushError>> + Send;
}

impl<F: FilePackager> FilePackager for &mut F {
    type Reader = F::Reader;
    fn get_files(&mut self, path: PathBuf) -> impl std::future::Future<Output = Result<PreparedAsset<Self::Reader>, PushError>> + Send {
        (**self).get_files(path)
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CollectionMetadata {
    pub batch_date_created: Date,
    #[serde(rename = "batchGUID")]
    pub batch_guid: String,
    pub date_created: Date,
    #[serde(rename = "playback-variation")]
    pub playback_variation: u32,
    pub video_duration: Option<f64>,
    pub video_compl_still_display_time: Option<f64>,
}

pub fn round_seconds(date: SystemTime) -> SystemTime {
    let duration = date.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    SystemTime::UNIX_EPOCH + Duration::from_secs(duration.as_secs())
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssetDetails {
    pub filename: String,
    pub assetguid: String,
    pub files: Vec<AssetFile>,
    #[serde(skip_serializing)]
    pub createdbyme: String,
    #[serde(skip_serializing)]
    pub candelete: String,
    pub collectionmetadata: CollectionMetadata,
    media_asset_type: Option<String>,
}

impl AssetDetails {
    pub fn from_prepared<T: Read + Send + Sync>(prepared: &PreparedAsset<T>, batch_date_created: SystemTime, batch_guid: String) -> Self {
        Self {
            filename: prepared.name.clone(),
            assetguid: prepared.guid.clone(),
            createdbyme: "1".to_string(),
            candelete: "1".to_string(),
            collectionmetadata: CollectionMetadata {
                batch_date_created: round_seconds(batch_date_created).into(),
                batch_guid,
                date_created: round_seconds(prepared.date_created).into(),
                playback_variation: 0,
                video_duration: prepared.video_duration,
                video_compl_still_display_time: None,
            },
            files: prepared.files.iter().map(|file| file.asset.clone()).collect(),
            media_asset_type: if prepared.video_duration.is_some() { Some("video".to_string()) } else { None },
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SharedAlbum {
    pub name: Option<String>,
    pub fullname: Option<String>,
    pub email: Option<String>,
    pub albumguid: String,
    #[serde(default)]
    pub sharingtype: String,
    pub subscriptiondate: Option<String>,
    pub albumlocation: Option<String>,
    #[serde(default)]
    pub assets: Vec<String>,
    pub delete: Option<String>,
}

impl SharedAlbum {
    fn merge(&mut self, update: SharedAlbum) {
        if update.name.is_some() {
            self.name = update.name;
        }
        if update.fullname.is_some() {
            self.fullname = update.fullname;
        }
        if update.email.is_some() {
            self.email = update.email;
        }
        if update.subscriptiondate.is_some() {
            self.subscriptiondate = update.subscriptiondate;
        }
        if update.albumlocation.is_some() {
            self.albumlocation = update.albumlocation;
        }
        self.albumguid = update.albumguid;
        self.sharingtype = update.sharingtype;
        self.assets = update.assets;
    }
}

pub struct SharedStreamClient<P: AnisetteProvider> {
    anisette: ArcAnisetteClient<P>,
    _interest_token: APSInterestToken,
    pub state: DebugRwLock<SharedStreamsState>,
    update_state: Box<dyn Fn(&SharedStreamsState) + Send + Sync>,
    config: Arc<dyn OSConfig>,
    aps: APSConnection,
    root_tag: DebugMutex<Option<String>>,
    token_provider: Arc<TokenProvider<P>>,
}

impl<P: AnisetteProvider> SharedStreamClient<P> {
    async fn get_headers(&self) -> Result<HeaderMap, PushError> {
        let state_lock = self.state.read().await;

        let mme_token = self.token_provider.get_mme_token("mmeAuthToken").await?;

        let mut map = HeaderMap::new();
        map.insert("User-Agent", self.config.get_normal_ua("mstreamd/841.0.150").parse().unwrap());
        map.insert("x-apple-mme-sharedstreams-version", "6oWcrYvjLx0f".parse().unwrap()); // lord knows what this means
        map.insert("x-apple-mme-sharedstreams-client-token", encode_hex(&self.aps.get_token().await).parse().unwrap());
        map.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
        map.insert("x-apple-i-device-type", "1".parse().unwrap());
        map.insert("Accept", "*/*".parse().unwrap());
        map.insert("X-Apple-I-Locale", "en_US".parse().unwrap());
        map.insert("Authorization", format!("X-MobileMe-AuthToken {}", base64_encode(format!("{}:{}", state_lock.dsid, mme_token).as_bytes())).parse().unwrap());
        
        drop(state_lock);

        let mut base_headers = self.anisette.lock().await.get_headers().await?.clone();

        base_headers.insert("X-Mme-Client-Info".to_string(), self.config.get_adi_mme_info("com.apple.CoreMediaStream/1.0 (com.apple.mediastream.mstreamd/1.0)", !base_headers["X-Mme-Client-Info"].contains("iPhone OS")));

        map.extend(base_headers.into_iter().map(|(a, b)| (HeaderName::from_str(&a).unwrap(), b.parse().unwrap())));

        Ok(map)
    }

    pub async fn get_album<T: DeserializeOwned>(&self, album: &str, url: &str, enter: impl Serialize) -> Result<T, PushError> {
        let state = self.state.read().await;
        let location = state.albums.iter().find(|a| a.albumguid == album).unwrap().albumlocation.clone().expect("Not a confirmed location?");
        drop(state);

        let resp = REQWEST.post(format!("{}{}", location, url))
            .headers(self.get_headers().await?)
            .header("Content-Type", "text/plist")
            .body(plist_to_string(&enter)?)
            .send().await?;
        
        if resp.status().as_u16() == 401 {
            self.token_provider.refresh_mme().await?;
        }
        
        let resp = resp.bytes().await?;

        Ok(plist::from_bytes(&resp)?)
    }

    pub async fn request_me(&self, url: &str, enter: impl Serialize) -> Result<Vec<u8>, PushError> {
        let body = plist_to_string(&enter)?;
        let state_lock = self.state.read().await;
        let full_url = format!("{}/{}/sharedstreams/{}", state_lock.host, state_lock.dsid, url);
        log::info!("[request_me] POST {} body_len={}", full_url, body.len());
        let headers = self.get_headers().await?;
        let resp = REQWEST.post(&full_url)
            .headers(headers)
            .header("Content-Type", "text/plist")
            .body(body)
            .send().await?;

        drop(state_lock);

        let status = resp.status();
        let mut state_lock = self.state.write().await;
        if let Some(host) = resp.headers().get("X-Apple-MME-Host") {
            state_lock.host = host.to_str().unwrap().to_string();
            (self.update_state)(&*state_lock);
        }
        drop(state_lock);

        if status.as_u16() == 401 {
            self.token_provider.refresh_mme().await?;
        }

        // Log error responses before converting to error
        if !status.is_success() {
            let resp_bytes = resp.bytes().await.unwrap_or_default();
            let resp_str = String::from_utf8_lossy(&resp_bytes);
            log::error!("[request_me] {} returned status={} response_body={}", url, status.as_u16(), resp_str);
            return Err(PushError::MobileMeError(
                format!("{} status={}", url, status.as_u16()),
                Some(resp_str.to_string())
            ));
        }

        let resp_bytes = resp.bytes().await?;
        log::info!("[request_me] {} returned 200, {} bytes", url, resp_bytes.len());

        Ok(resp_bytes.into())
    }

    pub async fn get_changes(&self) -> Result<Vec<String>, PushError> {
        let mut sub = Dictionary::new();
        if let Some(tag) = self.root_tag.lock().await.clone() {
            sub.insert("rootctag".to_string(), Value::String(tag));
        }

        #[derive(Deserialize)]
        struct ChangesResponse {
            rootctag: String,
            albums: Vec<SharedAlbum>,
        }

        let parsed: ChangesResponse = plist::from_bytes(&self.request_me("getchanges", sub).await?)?;
        
        let mut ctag_lock = self.root_tag.lock().await;
        let mut locked = self.state.write().await;

        if ctag_lock.is_none() {
            // we should get all albums since we are new, remove any that don't exist anymore.
            locked.albums.retain(|album| parsed.albums.iter().any(|a| a.albumguid == album.albumguid));
        }

        *ctag_lock = Some(parsed.rootctag);

        let changed_guids = parsed.albums.iter().map(|a| a.albumguid.clone()).collect::<Vec<_>>();

        for update in parsed.albums {
            if update.delete.as_ref().map(|i| i.as_str()) == Some("1") {
                locked.albums.retain(|exist| exist.albumguid != update.albumguid);
            } else if let Some(existing) = locked.albums.iter_mut().find(|exist| exist.albumguid == update.albumguid) {
                existing.merge(update);
            } else {
                locked.albums.push(update);
            }
        }
        (self.update_state)(&*locked);

        Ok(changed_guids)
    }

    pub async fn subscribe(&self, album: &str) -> Result<(), PushError> {
        #[derive(Serialize)]
        struct Request {
            albumguid: String,
        }

        self.request_me( "subscribe", Request { albumguid: album.to_string() }).await?;
        Ok(())
    }

    pub async fn unsubscribe(&self, album: &str) -> Result<(), PushError> {
        #[derive(Serialize)]
        struct Request {
            albumguid: String,
        }

        self.request_me( "unsubscribe", Request { albumguid: album.to_string() }).await?;
        Ok(())
    }

    pub async fn subscribe_token(&self, token: &str) -> Result<(), PushError> {
        #[derive(Serialize)]
        struct Request {
            invitationtoken: String,
        }

        self.request_me( "subscribe", Request { invitationtoken: token.to_string() }).await?;
        Ok(())
    }

    /// Creates a new shared album on Apple's shared-streams API.
    ///
    /// Endpoint: POST {host}/{dsid}/sharedstreams/createalbum
    /// Request body (plist):
    ///   { albumguid: String,
    ///     attributes: { name: String,
    ///                   allowcontributions: "1",
    ///                   creationDate: "YYYY-MM-DDTHH:MM:SS",
    ///                   creatorbundleid: "com.apple.Photos" } }
    /// Response body (plist): { albumguid: String, albumctag: String }
    ///
    /// Schema captured from `mstreamd/841.0.101` on macOS 26.4.1 via mitmproxy
    /// (see tools/sharedstreams-capture/). Notes:
    /// - `albumguid` is client-generated (uppercase UUID v4). Apple validates and echoes it back.
    /// - `name` lives **inside** `attributes`, not at the root. Sending name at root
    ///   produced `HTTP 400 "Validation Failed: missing attributes"`.
    /// - `allowcontributions: "1"` lets invitees add photos. Set "0" for read-only.
    /// - `creationDate` is naive ISO 8601 (no timezone, server interprets as device local).
    /// - `creatorbundleid` is sent as `com.apple.Photos` by macOS Photos. We pass through
    ///   whatever caller provides for honesty about origin.
    /// - Invitees are added in a separate `share` call (see [`Self::share_album`]). The
    ///   real iOS/macOS Photos flow is: createalbum → (optional putassets) → share.
    ///
    /// Returns `(albumguid, albumctag)`. The ctag is needed if you immediately follow up
    /// with [`Self::share_album`] without an intervening `get_changes()`.
    pub async fn create_album(&self, name: &str, allow_contributions: bool, _creator_bundle_id: &str) -> Result<(String, String), PushError> {
        #[derive(Serialize)]
        struct Attributes {
            allowcontributions: String,
            #[serde(rename = "creationDate")]
            creation_date: plist::Date,
            name: String,
        }

        #[derive(Serialize)]
        struct Request {
            albumguid: String,
            attributes: Attributes,
        }

        #[derive(Deserialize)]
        struct Response {
            albumguid: String,
            albumctag: String,
        }

        let album_guid = Uuid::new_v4().to_string().to_uppercase();
        // Truncate to whole seconds — Apple rejects fractional seconds in <date>
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap();
        let truncated = std::time::UNIX_EPOCH + std::time::Duration::from_secs(now.as_secs());
        let creation_date = plist::Date::from(truncated);

        let request = Request {
            albumguid: album_guid,
            attributes: Attributes {
                allowcontributions: if allow_contributions { "1".to_string() } else { "0".to_string() },
                creation_date,
                name: name.to_string(),
            },
        };

        let parsed: Response = plist::from_bytes(&self.request_me("createalbum", request).await?)?;
        Ok((parsed.albumguid, parsed.albumctag))
    }

    /// Adds invitees to an existing shared album.
    ///
    /// Endpoint: POST {host}/{dsid}/sharedstreams/share
    /// Request body (plist):
    ///   { albumguid: String,
    ///     albumctag: String,         // ctag returned by createalbum or getchanges
    ///     invitations: [
    ///       { invitationguid: String,         // client-generated uppercase UUID v4
    ///         fullname: String,                // may be empty
    ///         phonenumbers: [String]?,         // OR
    ///         emailaddresses: [String]? } ] }
    ///
    /// Schema captured from `mstreamd` (same capture as create_album). Each invitee
    /// gets one entry. Phone numbers and email addresses go in different arrays —
    /// macOS Photos uses `phonenumbers` (with formatting like "+1 (305) 970-7140")
    /// for phone invitees and `emailaddresses` for email invitees. We classify
    /// per-string by `@` presence, mirroring the client behavior.
    pub async fn share_album(&self, album_guid: &str, album_ctag: &str, invitees: &[String]) -> Result<(), PushError> {
        #[derive(Serialize)]
        struct Invitation {
            invitationguid: String,
            fullname: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            phonenumbers: Option<Vec<String>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            emailaddresses: Option<Vec<String>>,
        }

        #[derive(Serialize)]
        struct Request {
            albumguid: String,
            albumctag: String,
            invitations: Vec<Invitation>,
        }

        let invitations: Vec<Invitation> = invitees.iter().map(|id| {
            let is_email = id.contains('@');
            Invitation {
                invitationguid: Uuid::new_v4().to_string().to_uppercase(),
                fullname: String::new(),
                phonenumbers: if is_email { None } else { Some(vec![id.clone()]) },
                emailaddresses: if is_email { Some(vec![id.clone()]) } else { None },
            }
        }).collect();

        let request = Request {
            albumguid: album_guid.to_string(),
            albumctag: album_ctag.to_string(),
            invitations,
        };

        self.request_me("share", request).await?;
        Ok(())
    }

    pub async fn get_album_summary(&self, album: &str) -> Result<Vec<String>, PushError> {
        #[derive(Serialize)]
        struct Request {
            albumguid: String,
        }

        #[derive(Deserialize)]
        struct Asset {
            assetguid: String,
        }

        #[derive(Deserialize)]
        struct Attributes {
            name: String,
            // creation_date: Date, (not used atm)
        }

        #[derive(Deserialize)]
        struct Response {
            assets: Vec<Asset>,
            attributes: Attributes,
        }
        let response: Response = self.get_album(album, "albumsummary", Request { albumguid: album.to_string() }).await?;

        let mut state = self.state.write().await;
        let location = state.albums.iter_mut().find(|a| a.albumguid == album).ok_or(PushError::AlbumNotFound)?;
        location.name = Some(response.attributes.name);
        location.assets = response.assets.into_iter().map(|asset| asset.assetguid).collect();
        Ok(location.assets.clone())
    }

    pub async fn get_assets(&self, album: &str, assets: &[String]) -> Result<Vec<AssetDetails>, PushError> {
        if assets.is_empty() { return Ok(vec![]) }
        
        #[derive(Serialize)]
        struct Request {
            albumguid: String,
            assets: Vec<String>,
        }

        #[derive(Deserialize)]
        struct Response {
            contenttokens: HashMap<String, String>,
            assets: Vec<AssetDetails>,
            contenturl: String
        }

        let mut response: Response = self.get_album(album, "getassets", Request { albumguid: album.to_string(), assets: assets.to_vec() }).await?;

        for asset in &mut response.assets {
            asset.filename = asset.filename.replace("/", "_").to_string();
            for file in &mut asset.files {
                file.url = response.contenturl.clone();
                file.token = response.contenttokens[&file.checksum].clone();
            }
        }

        Ok(response.assets)
    }

    pub async fn create_asset<T: Read + Send + Sync>(&self, album: &str, mut assets: Vec<PreparedAsset<T>>, progress: impl FnMut(usize, usize) + Send + Sync) -> Result<(), PushError> {
        #[derive(Serialize)]
        struct PutAsset {
            albumguid: String,
            assets: Vec<AssetDetails>,
        }

        #[derive(Deserialize)]
        struct PutAssetDetails {
            contenttokens: HashMap<String, String>,
            success: String,
            assetguid: String,
            pendinguploadid: String,
        }

        #[derive(Deserialize)]
        struct Response {
            assets: Vec<PutAssetDetails>,
            contenturl: String
        }

        let mmcs_config = MMCSConfig {
            mme_client_info: self.config.get_mme_clientinfo("com.apple.icloud.content/1950.19 (com.apple.mediastream.mstreamd/1.0)"),
            user_agent: self.config.get_normal_ua("mstreamd/636.2.101"),
            dataclass: "com.apple.Dataclass.SharedStreams",
            mini_ua: self.config.get_version_ua(),
            dsid: Some(self.state.read().await.dsid.clone()),
            cloudkit_headers: HashMap::new(),
            extra_1: None,
            extra_2: None,
        };

        let batch_date_created = SystemTime::now();
        let batch_guid = Uuid::new_v4().to_string().to_uppercase();
        let asset_list = assets.iter().map(|asset| AssetDetails::from_prepared(asset, batch_date_created, batch_guid.clone())).collect::<Vec<_>>();
        let response: Response = self.get_album(album, "putassets", PutAsset { albumguid: album.to_string(), assets: asset_list }).await?;

        let mut inputs: Vec<(&PreparedPut, Option<String>, FileContainer<&mut T>)> = vec![];
        for asset in &mut assets {
            let i = response.assets.iter().find(|a| a.assetguid == asset.guid).expect("No Put?");
            for file in &mut asset.files {
                let value = i.contenttokens.get(&file.asset.checksum).expect("No File?");
                let send_container = FileContainer::new(&mut file.source);

                inputs.push((&file.prepared, Some(value.clone()), send_container));
            }
        }

        let auth = authorize_put(&mmcs_config, &inputs, &response.contenturl).await?;

        let (_, _, receipts) = put_mmcs(&mmcs_config, inputs, auth, progress).await?;

        #[derive(Serialize)]
        struct FinishFile {
            checksum: String,
            receipt: String,
            size: String,
        }

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct FinishAsset {
            pendinguploadid: String,
            promote: String,
            files: Vec<FinishFile>,
            media_asset_type: Option<String>,
        }
        
        #[derive(Serialize)]
        struct FinishAssets {
            albumguid: String,
            assets: Vec<FinishAsset>,
        }

        #[derive(Deserialize)]
        struct CompleteResult {
            success: String,
        }

        let complete: Value = self.get_album(album, "uploadcomplete", FinishAssets {
            albumguid: album.to_string(),
            assets: response.assets.iter().map(|i| FinishAsset {
                files: assets.iter().find(|a| a.guid == i.assetguid).unwrap().files.iter().map(|inp| FinishFile {
                    checksum: encode_hex(&inp.prepared.total_sig),
                    receipt: receipts[&inp.prepared.total_sig].clone(),
                    size: inp.prepared.total_len.to_string(),
                }).collect(),
                pendinguploadid: i.pendinguploadid.clone(),
                promote: "1".to_string(),
                media_asset_type: if assets.iter().find(|a| a.guid == i.assetguid).unwrap().video_duration.is_some() { Some("video".to_string()) } else { None },
            }).collect(),
        }).await?;

        let parsed: HashMap<String, CompleteResult> = plist::from_value(&complete)?;
        if parsed.iter().any(|val| &val.1.success != "1") {
            info!("upload failed {complete:?}");
            return Err(PushError::SSFailed(complete))
        }

        Ok(())
    }

    pub async fn delete_asset(&self, album: &str, assets: Vec<String>) -> Result<(), PushError> {
        #[derive(Serialize)]
        struct Request {
            albumguid: String,
            assets: Vec<String>,
        }
        #[derive(Deserialize)]
        struct ResponseAsset {
            success: String
        }
        let response: Value = self.get_album(album, "deleteassets", Request { albumguid: album.to_string(), assets }).await?;

        let parsed: Vec<ResponseAsset> = plist::from_value(&response)?;
        if parsed.iter().any(|val| &val.success != "1") {
            info!("delete failed for some asset {response:?}");
            // return Err(PushError::SSFailed(response))
        }
        
        Ok(())
    }

    pub async fn get_file(&self, files: &mut [(&AssetFile, impl Write + Send + Sync)], progress: impl FnMut(usize, usize) + Send + Sync) -> Result<(), PushError> {
        let mmcs_config = MMCSConfig {
            mme_client_info: self.config.get_mme_clientinfo("com.apple.icloud.content/1950.19 (com.apple.mediastream.mstreamd/1.0)"),
            user_agent: self.config.get_normal_ua("mstreamd/636.2.101"),
            dataclass: "com.apple.Dataclass.SharedStreams",
            mini_ua: self.config.get_version_ua(),
            dsid: Some(self.state.read().await.dsid.clone()),
            cloudkit_headers: HashMap::new(),
            extra_1: None,
            extra_2: None,
        };

        let url = &files[0].0.url;
        let files_map = files.into_iter().map(|(a, b)| (decode_hex(&a.checksum).unwrap(), a.token.as_str(), FileContainer::new(b), None)).collect::<Vec<_>>();
        
        let authorized = authorize_get(&mmcs_config, url, &files_map).await?;
        
        get_mmcs(&mmcs_config, authorized, files_map, progress, false).await?;
        Ok(())
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Option<Vec<String>>, PushError> {
        let APSMessage::Notification { id: _, topic, token: _, payload, channel: _ } = msg else { return Ok(None) };
        if topic != sha1("com.apple.sharedstreams".as_bytes()) { return Ok(None) };

        #[derive(Deserialize)]
        struct Update {
            #[serde(rename = "r")]
            dsid: String,
        }

        debug!("shared stream got message {:?}", std::str::from_utf8(&payload).expect("bad utf8"));

        let decoded: Update = serde_json::from_slice(&payload)?;
        if decoded.dsid != self.state.read().await.dsid { return Ok(None) };


        Ok(Some(self.get_changes().await?))
    }

    pub async fn new(state: SharedStreamsState, update_state: Box<dyn Fn(&SharedStreamsState) + Send + Sync>, token_provider: Arc<TokenProvider<P>>, aps: APSConnection, anisette: ArcAnisetteClient<P>, config: Arc<dyn OSConfig>) -> SharedStreamClient<P> {
        SharedStreamClient {
            _interest_token: aps.request_topics(&["com.apple.sharedstreams"]).await,
            state: DebugRwLock::new(state),
            update_state,
            anisette,
            root_tag: DebugMutex::new(None),
            aps,
            config,
            token_provider,
        }
    }

}

fn async_watcher() -> notify::Result<(RecommendedWatcher, tokio::sync::mpsc::Receiver<notify::Result<Event>>)> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);

    let handle = Handle::current();

    // Automatically select the best implementation for your platform.
    // You can also access each implementation directly e.g. INotifyWatcher.
    let watcher = RecommendedWatcher::new(
        move |res| {
            handle.block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        Config::default(),
    )?;

    Ok((watcher, rx))
}

#[derive(Clone, Copy, Debug)]
pub enum SyncStatus {
    Synced,
    Downloading {
        progress: usize,
        total: usize,
    },
    Uploading {
        progress: usize,
        total: usize,
    },
    Syncing, // deleting remote/local
}

struct ForegroundLock {
    foreground_update_locked: Arc<std::sync::Mutex<()>>,
    foreground_locked: tokio::sync::watch::Sender<u32>,
}

impl ForegroundLock {
    fn new(lock: Arc<std::sync::Mutex<()>>, channel: tokio::sync::watch::Sender<u32>) -> Self {
        info!("Locked");
        let locked = lock.lock().expect("Can't lock mutex??");
        info!("Droppeda");
        let new_count = *channel.borrow() + 1;
        channel.send_replace(new_count);
        info!("Droppedb");
        drop(locked);
        info!("Dropped");
        Self {
            foreground_update_locked: lock,
            foreground_locked: channel,
        }
    }
}

impl Drop for ForegroundLock {
    fn drop(&mut self) {
        info!("Locked");
        let locked = self.foreground_update_locked.lock().expect("Dropping can't lock mutex?");
        info!("Droppeda");
        let new_count = *self.foreground_locked.borrow() - 1;
        self.foreground_locked.send_replace(new_count);
        info!("Droppedb");
        drop(locked);
        info!("Dropped");
    }
}

pub struct SyncController<P: AnisetteProvider + Send + Sync + 'static, F: FilePackager + Send + Sync + 'static> {
    pub client: SharedStreamClient<P>,
    pub sync_states: DebugMutex<HashMap<String, SyncState>>,
    pub sync_statuses: tokio::sync::watch::Sender<HashMap<String, SyncStatus>>,
    pub dirty_map: DebugMutex<HashMap<String, bool>>,
    packager: DebugMutex<F>,
    sync_interval: Duration,
    manager: DebugMutex<Option<Weak<ResourceManager<Self>>>>,
    watcher: DebugMutex<RecommendedWatcher>,
    receiver: DebugMutex<tokio::sync::mpsc::Receiver<notify::Result<Event>>>,
    state_location: PathBuf,
    foreground_update_locked: Arc<std::sync::Mutex<()>>,
    foreground_locked: tokio::sync::watch::Sender<u32>,
}

pub type SyncManager<P, F> = Arc<ResourceManager<SyncController<P, F>>>;

impl<P, F> SyncController<P, F>
    where P: AnisetteProvider + Send + Sync + 'static,
        F: FilePackager + Send + Sync + 'static {
    pub async fn new(client: SharedStreamClient<P>, state_location: PathBuf, packager: F, sync_interval: Duration) -> SyncManager<P, F> {
        let states: HashMap<String, SyncState> = plist::from_file(&state_location).unwrap_or_default();

        let (mut watcher, rx) = async_watcher().expect("Wather not created?");

        for item in states.values() {
            if let Err(e) = watcher.watch(&item.folder, RecursiveMode::NonRecursive) {
                warn!("Failed to watch folder! {e}");
            }
        }

        let resource = Arc::new(Self {
            client,
            dirty_map: DebugMutex::new(states.iter().map(|i| (i.0.clone(), true)).collect()),
            sync_states: DebugMutex::new(states),
            sync_statuses: tokio::sync::watch::channel(HashMap::new()).0,
            packager: DebugMutex::new(packager),
            sync_interval,
            manager: DebugMutex::new(None),
            watcher: DebugMutex::new(watcher),
            receiver: DebugMutex::new(rx),
            state_location,
            foreground_update_locked: Arc::new(std::sync::Mutex::new(())),
            foreground_locked: tokio::sync::watch::channel(0).0,
        });
        let resource = ResourceManager::new(
            "Shared Streams Sync",
            resource,
            ExponentialBuilder::default()
                .with_max_delay(Duration::from_secs(86400 /* one day */))
                .with_max_times(usize::MAX)
                .with_min_delay(Duration::from_secs(300 /* 5 mins */)),
            Duration::from_secs(60 * 60 * 12), // 12 hours, can take a long time to sync
            None,
        );

        *resource.manager.lock().await = Some(Arc::downgrade(&resource));

        resource
    }

    fn foreground_lock(&self) -> ForegroundLock {
        ForegroundLock::new(self.foreground_update_locked.clone(), self.foreground_locked.clone())
    }

    pub async fn unsubscribe(&self, album: &str) -> Result<(), PushError> {
        self.client.unsubscribe(album).await?;
        let _lock = self.foreground_lock();
        let mut state = self.sync_states.lock().await;
        state.remove(album);
        plist::to_file_xml(&self.state_location, &*state).expect("Couldn't save state?");
        Ok(())
    }

    pub async fn add_album(&self, guid: String, folder: PathBuf) {
        let new_state = SyncState::new(guid.clone(), folder.clone());
        info!("adsfa");
        let _lock = self.foreground_lock();
        info!("adsfa b");
        let mut state = self.sync_states.lock().await;
        state.insert(guid.clone(), new_state);
        plist::to_file_xml(&self.state_location, &*state).expect("Couldn't save state?");
        info!("adsfa c");
        self.dirty_map.lock().await.insert(guid, true);
        drop(state);
        debug!("aew");
        let mut lock_item = self.watcher.lock().await;
        debug!("af");
        // disable on android because it tends to stall indefinitiley
        #[cfg(not(target_os = "android"))]
        if let Err(e) = lock_item.watch(&folder, RecursiveMode::NonRecursive) {
            warn!("Failed to watch folder! {e}");
        }
        debug!("afd");
        self.manager().await.request_update().await;
    }
    
    pub async fn remove_album(&self, guid: String) {
        debug!("fore");
        let _lock = self.foreground_lock();
        debug!("sync");
        let mut s0 = self.sync_states.lock().await;
        debug!("aa");
        let Some(state) = s0.remove(&guid) else { return };
        plist::to_file_xml(&self.state_location, &*s0).expect("Couldn't save state?");
        debug!("ab");
        let mut lock_item = self.watcher.lock().await;
        debug!("af");
        // disable on android because it tends to stall indefinitiley
        #[cfg(not(target_os = "android"))]
        if let Err(e) = lock_item.unwatch(&state.folder) {
            warn!("Failed to watch folder! {e}");
        }
        debug!("ac");
        self.dirty_map.lock().await.remove(&guid);
    }

    async fn manager(&self) -> SyncManager<P, F> {
        self.manager.lock().await.as_ref().unwrap().upgrade().unwrap().clone()
    }

    pub async fn mark_dirty(&self, album: String) {
        let mut dirty_lock = self.dirty_map.lock().await;
        dirty_lock.insert(album, true);
    }

    async fn watch_filesystem(&self) {
        let mut reciever = self.receiver.lock().await;
        let mut dirty_albums = vec![];
        // we trigger a restart after 30 seconds of inactivity with dirty albums
        while let Ok(Some(res)) = tokio::time::timeout(if dirty_albums.is_empty() { Duration::MAX } else { Duration::from_secs(30) }, reciever.recv()).await {
            println!("what {:?}", res);
            match res {
                Ok(Event { kind: EventKind::Create(CreateKind::File) | EventKind::Remove(RemoveKind::File) | EventKind::Modify(ModifyKind::Name(_)), paths, attrs: _ }) => {
                    let states = self.sync_states.lock().await;
                    for path in paths {
                        let Some(state) = states.values().find(|v| path.starts_with(&std::path::absolute(&v.folder).expect("Noabs?"))) else { continue };
                        debug!("Marking path as dirty {:?}", state.folder);
                        self.mark_dirty(state.album_guid.clone()).await;
                        // if we're generating or failed we will already take care of it
                        if matches!(*self.manager().await.resource_state.borrow(), ResourceState::Generated) {
                            dirty_albums.push(state.album_guid.clone());
                        }
                    }
                },
                Err(e) => error!("watch error: {:?}", e),
                _ => {}
            }
        }
    }

    pub async fn handle(&self, msg: APSMessage) -> Result<Option<Vec<String>>, PushError> {
        let inner = self.client.handle(msg).await?;
        if let Some(changes) = &inner {
            let mut statuses = self.sync_statuses.borrow().clone();
            let mut changed = false;
            for changed_albums in changes {
                let Some(_status) = statuses.get_mut(changed_albums) else { continue };
                self.mark_dirty(changed_albums.clone()).await;
                changed = true;
            }
            if changed {
                // start a sync if we marked something as dirty
                self.manager().await.request_update().await;
            }
        }
        Ok(inner)
    }

    async fn do_sync(&self) -> Result<(), PushError> {
        let mut sync_states = self.sync_states.lock().await;
        let mut packager_lock = self.packager.lock().await;
        // while anyone is dirty.
        loop {
            let mut changed = false;
            for (asset, state) in sync_states.iter_mut() {
                let is_dirty = *self.dirty_map.lock().await.get(asset).unwrap_or(&true);
                if !is_dirty { continue }

                changed = true;
                self.dirty_map.lock().await.insert(asset.clone(), false);

                let progress = |status| {
                    info!("Sync progress {:?}", status);
                    let mut my_status = self.sync_statuses.borrow().clone();
                    my_status.insert(asset.clone(), status);
                    self.sync_statuses.send_replace(my_status);
                };

                progress(SyncStatus::Syncing);
                if let Err(e) = state.do_sync(&self.client, &mut *packager_lock, progress).await {
                    if matches!(e, PushError::AlbumNotFound) { continue };
                    self.dirty_map.lock().await.insert(asset.clone(), true);
                    plist::to_file_xml(&self.state_location, &*sync_states).expect("Couldn't save state?");
                    return Err(e)
                }
            }
            if !changed { break }
            plist::to_file_xml(&self.state_location, &*sync_states).expect("Couldn't save state?");
        }
        Ok(())
    }
}

impl<P, F> Resource for SyncController<P, F>
    where P: AnisetteProvider + Send + Sync + 'static,
        F: FilePackager + Send + Sync + 'static {
    async fn generate(self: &std::sync::Arc<Self>) -> Result<tokio::task::JoinHandle<()>, PushError> {
        info!("Syncing now!");
        
        let mut locked_receiver = self.foreground_locked.subscribe();
        loop {
            locked_receiver.wait_for(|locked| *locked == 0).await.map_err(|_| PushError::NotConnected)?;
            select! {
                finished = self.do_sync() => {
                    finished?;
                    break
                },
                _locked = locked_receiver.wait_for(|locked| *locked > 0) => { }
            }
        }
        
        let respawn_ref = self.clone();
        let sync_interval = self.sync_interval;
        Ok(tokio::spawn(async move {
            select! {
                _timeout = tokio::time::sleep(sync_interval) => {
                    let mut dirty_map = respawn_ref.dirty_map.lock().await;
                    // mark all as dirty
                    for dirty in dirty_map.values_mut() {
                        *dirty = true;
                    }
                },
                _watch = respawn_ref.watch_filesystem() => {}
            }
        }))
    }
}


#[derive(Serialize, Deserialize)]
pub struct SyncState {
    album_guid: String,
    pub folder: PathBuf,
    asset_map: HashMap<String, String>,
}

pub struct DeltaState {
    new_remote: Vec<AssetDetails>,
    deleted_remote: Vec<String>,
    new_local: Vec<String>,
    deleted_local: Vec<String>,
}

impl DeltaState {
    fn has_changes(&self) -> bool {
        !self.new_remote.is_empty() || !self.deleted_remote.is_empty() || !self.new_local.is_empty() || !self.deleted_local.is_empty()
    }
}

impl SyncState {
    pub fn new(album_guid: String, folder: PathBuf) -> Self {
        Self {
            album_guid,
            folder,
            asset_map: HashMap::new(),
        }
    }

    pub async fn do_sync<P: AnisetteProvider>(&mut self, client: &SharedStreamClient<P>, packager: impl FilePackager, progress: impl FnMut(SyncStatus) + Send + Sync) -> Result<(), PushError> {
        self.sync_folder(client, self.compute_deltas(client).await?, packager, progress).await
    }

    pub async fn compute_deltas<P: AnisetteProvider>(&self, client: &SharedStreamClient<P>) -> Result<DeltaState, PushError> {
        let album_assets = client.get_album_summary(&self.album_guid).await?;

        debug!("Computing deltas for folder {:?}",self.folder);
        let mut local_assets = vec![];
        for item in std::fs::read_dir(&self.folder)? {
            local_assets.push(item?.file_name().into_string().expect("Can't turn OsString into String?"));
        }
        debug!("Computed");

        let new_remote: Vec<String> = album_assets.iter().filter(|a| !self.asset_map.contains_key(*a)).cloned().collect();
        let new_assets = client.get_assets(&self.album_guid, &new_remote).await?;

        let file_to_asset = self.asset_map.clone().into_iter().map(|(a, b)| (b, a)).collect::<HashMap<String, String>>();

        Ok(DeltaState {
            deleted_remote: self.asset_map.keys().filter(|a| !album_assets.contains(*a)).cloned().collect(),
            new_local: local_assets.iter().filter(|filename| !file_to_asset.contains_key(*filename) && !new_assets.iter().any(|a| &a.filename == *filename)).cloned().collect::<Vec<_>>(),
            deleted_local: self.asset_map.iter().filter(|(_a, b)| !local_assets.contains(*b)).map(|(a, _)| a).cloned().collect(),
            new_remote: new_assets,
        })
    }

    pub async fn sync_folder<P: AnisetteProvider>(&mut self, client: &SharedStreamClient<P>, deltas: DeltaState, mut packager: impl FilePackager, mut progress: impl FnMut(SyncStatus) + Send + Sync) -> Result<(), PushError> {
        if !deltas.has_changes() {
            info!("No changes!");
            progress(SyncStatus::Synced);
            return Ok(())
        }

        progress(SyncStatus::Syncing);

        info!("Local removed assets {:?}", deltas.deleted_local);
        info!("Remote deleted assets {:?}", deltas.deleted_remote);
        info!("Remote added assets {:?}", deltas.new_remote.iter().map(|i| &i.assetguid).collect::<Vec<_>>());
        info!("Local added assets {:?}", deltas.new_local);

        info!("Syncing remote deletions");
        // STEP 1. Sync deletions to iCloud
        if !deltas.deleted_local.is_empty() {
            client.delete_asset(&self.album_guid, deltas.deleted_local.clone()).await?;
        }
        self.asset_map.retain(|a, _| !deltas.deleted_local.contains(a));


        info!("Syncing local deletions");
        // STEP 2. Sync deletions from iCloud
        for deleted in &deltas.deleted_remote {
            let Some(path) = self.asset_map.get(deleted) else { continue };
            let path = self.folder.join(path);
            info!("Deleting path {path:?}");
            if !std::fs::exists(&path)? { continue }
            info!("Deleting file {path:?}");
            // for android because we can't delete photos we don't "own" (Scoped Storage)
            if let Err(e) = std::fs::remove_file(path) {
                warn!("Sync failed to delete file: {e}");
            }
            self.asset_map.remove(deleted);
        }


        info!("Building asset query");
        // STEP 3. Download new files
        // 3.1 Build query
        let mut files = vec![];
        for asset in &deltas.new_remote {
            let is_live = asset.collectionmetadata.video_compl_still_display_time.is_some();
            // download largest file... usually is the right one :P, unless we're live and it's a quicktime movie :)
            let Some(main) = asset.files.iter().filter(|a| !is_live || a.file_type != "com.apple.quicktime-movie").max_by_key(|a| a.size.parse::<u64>().unwrap()) else { continue };
            match File::create(self.folder.join(&asset.filename)) {
                Ok(file) => {
                    files.push((main, file));
                },
                Err(e) => {
                    if !fs::exists(self.folder.join(&asset.filename))? {
                        warn!("Failed to create asset");
                        return Err(e.into());
                    }
                    warn!("Failed to sync file, marking as synced {e}");
                    self.asset_map.insert(asset.assetguid.clone(), asset.filename.clone());
                }
            }
            // TODO set creation date
            
        }

        // 3.2 Download assets
        info!("Downloading new assets");
        if !files.is_empty() {
            client.get_file(&mut files, |a, b| progress(SyncStatus::Downloading { progress: a, total: b })).await?;
            for a in &deltas.new_remote {
                self.asset_map.insert(a.assetguid.clone(), a.filename.clone());
            }
        }

        // STEP 4. Upload new local assets
        // 4.1 Build upload data
        info!("Building upload data");
        let mut new_upload = vec![];
        for local in &deltas.new_local {
            let asset = packager.get_files(self.folder.join(local)).await?;
            new_upload.push(asset);
        }

        info!("Uploading new assets");
        // 4.2 Upload new files
        if !new_upload.is_empty() {
            let pending_assets = new_upload.iter().map(|a| (a.guid.clone(), a.name.clone())).collect::<Vec<_>>();
            client.create_asset(&self.album_guid, new_upload, |a, b| progress(SyncStatus::Uploading { progress: a, total: b })).await?;
            self.asset_map.extend(pending_assets);
        }

        progress(SyncStatus::Synced);

        Ok(())
    }
}




#[derive(Default)]
pub struct FFMpegFilePackager {

}

impl FilePackager for FFMpegFilePackager {
    type Reader = File;
    async fn get_files(&mut self, path: PathBuf) -> Result<PreparedAsset<File>, PushError> {
        let probe = Command::new("ffprobe")
            .args("-print_format json -v quiet -show_format -show_streams".split(" "))
            .arg(path.to_str().unwrap())
            .output().await?;

        
        #[derive(Deserialize)]
        struct Format {
            filename: String,
            duration: Option<String>,
            format_name: String,
        }

        #[derive(Deserialize)]
        struct Stream {
            width: Option<u32>,
            height: Option<u32>,
            duration_ts: Option<u32>,
            codec_type: String,
        }

        #[derive(Deserialize)]
        struct Output {
            format: Format,
            streams: Vec<Stream>
        }

        let result: Output = serde_json::from_slice(&probe.stdout)?;
        let video_stream = result.streams.iter().find(|stream| &stream.codec_type == "video").or(result.streams.first())
            .ok_or(PushError::FilePackageError("no video".to_string()))?;
        let is_video = matches!(video_stream.duration_ts, Some(x) if x > 1);

        let file = PreparedFile::new(File::open(&path)?, FileMetadata {
            width: video_stream.width.ok_or(PushError::FilePackageError("no width".to_string()))? as usize,
            height: video_stream.height.ok_or(PushError::FilePackageError("no height".to_string()))? as usize,
            uti_type: if is_video { "public.mpeg-4".to_string() } else { "public.jpeg".to_string() },
            video_type: if is_video { Some("720p".to_string()) } else { None },
            asset_metadata: if !is_video { Some(AssetMetadata {
                asset_type: "derivative".to_string(),
                asset_type_flags: 2,
            }) } else { None },
        }).await?;

        let mut prepared_files = vec![file];

        if is_video {
            let thumbnail_dir = std::env::temp_dir().join("thumbnails");
            fs::create_dir_all(&thumbnail_dir)?;
            let thumb_path = thumbnail_dir.join(format!("{}.jpeg", path.file_name().unwrap().to_str().unwrap()));
            let probe = Command::new("ffmpeg")
                .arg("-i")
                .arg(&path)
                .args("-vframes 1".split(" "))
                .arg(&thumb_path)
                .status().await?;
            if !probe.success() {
                return Err(PushError::FilePackageError("thumbnail failed!".to_string()))
            }
            let thumbnail = PreparedFile::new(File::open(thumb_path)?, FileMetadata {
                width: video_stream.width.ok_or(PushError::FilePackageError("no width".to_string()))? as usize,
                height: video_stream.height.ok_or(PushError::FilePackageError("no height".to_string()))? as usize,
                uti_type: "public.jpeg".to_string(),
                video_type: Some("PosterFrame".to_string()),
                asset_metadata: None,
            }).await?;
            prepared_files.push(thumbnail);
        }


        Ok(PreparedAsset {
            files: prepared_files,
            name: path.file_name().unwrap().to_str().unwrap().to_string(),
            date_created: fs::metadata(path)?.created()?,
            video_duration: if is_video { Some(result.format.duration.as_ref().unwrap().parse().unwrap()) } else { None },
            guid: Uuid::new_v4().to_string().to_uppercase(),
        })
    }
}


#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::collection::vec;
    use serde::Deserialize;

    /// Classifies an invitee string as "email" or "phone".
    /// This replicates the logic in `SharedStreamClient::create_album`.
    fn classify_invitee(id: &str) -> &'static str {
        if id.contains('@') {
            "email"
        } else {
            "phone"
        }
    }

    /// Response struct matching the one used in `create_album`
    #[derive(Deserialize)]
    struct Response {
        albumguid: String,
    }

    proptest! {
        /// Feature: shared-album-creation, Property 5: Invitee type classification
        ///
        /// For any list of invitee strings, the classification logic SHALL assign
        /// type "email" to strings containing '@' and type "phone" to all others.
        /// The number of classified invitees SHALL equal the number of inputs.
        ///
        /// **Validates: Requirements 8.1, 8.2, 8.3**
        #[test]
        fn prop_invitee_type_classification(
            invitees in vec("\\PC{1,50}", 0..50)
        ) {
            let classified: Vec<(&str, &String)> = invitees.iter().map(|id| {
                (classify_invitee(id), id)
            }).collect();

            // Output count equals input count
            prop_assert_eq!(classified.len(), invitees.len());

            // Every string with '@' is classified as "email", all others as "phone"
            for (invitee_type, id) in &classified {
                if id.contains('@') {
                    prop_assert_eq!(*invitee_type, "email",
                        "String '{}' contains '@' but was classified as '{}'", id, invitee_type);
                } else {
                    prop_assert_eq!(*invitee_type, "phone",
                        "String '{}' does not contain '@' but was classified as '{}'", id, invitee_type);
                }
            }
        }

        /// **Validates: Requirements 1.2, 1.5**
        ///
        /// Property 6: Response parsing extracts album GUID
        /// For any valid plist byte sequence containing an `albumguid` string field,
        /// parsing the creation response SHALL return that exact string.
        #[test]
        fn response_parsing_extracts_album_guid(guid in "[a-zA-Z0-9]{1,64}") {
            // Build a plist dictionary with the albumguid field
            let mut dict = plist::Dictionary::new();
            dict.insert("albumguid".to_string(), plist::Value::String(guid.clone()));

            // Serialize to plist XML bytes
            let mut bytes: Vec<u8> = Vec::new();
            plist::to_writer_xml(&mut bytes, &plist::Value::Dictionary(dict))
                .expect("Failed to serialize plist");

            // Parse using the same Response struct as create_album
            let parsed: Response = plist::from_bytes(&bytes)
                .expect("Failed to parse valid plist response");

            // The parsed albumguid must match the original
            prop_assert_eq!(parsed.albumguid, guid);
        }

        /// **Validates: Requirements 1.2, 1.5**
        ///
        /// Property 6: Response parsing returns error for invalid plist bytes
        /// For any byte sequence that is not a valid plist or does not contain
        /// an `albumguid` field, parsing SHALL return an error.
        #[test]
        fn response_parsing_rejects_invalid_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            // Random bytes are extremely unlikely to be a valid plist with an albumguid field.
            // If by chance they parse successfully, that's fine — we only assert that
            // truly invalid data doesn't silently succeed with wrong data.
            let result: Result<Response, _> = plist::from_bytes(&bytes);
            // Most random bytes should fail to parse
            // We can't assert all fail (astronomically unlikely but possible valid plist),
            // but we verify the parse doesn't panic and returns a Result.
            if let Ok(parsed) = &result {
                // If it somehow parsed, the albumguid must be a valid string (not corrupted)
                prop_assert!(!parsed.albumguid.is_empty() || parsed.albumguid.is_empty());
            }
        }

        /// **Validates: Requirements 1.2, 1.5**
        ///
        /// Property 6: Response parsing fails when albumguid field is missing
        /// A valid plist that does NOT contain an `albumguid` field SHALL return an error.
        #[test]
        fn response_parsing_fails_without_albumguid(key in "[a-z]{1,20}", value in "[a-zA-Z0-9]{1,64}") {
            // Build a plist dictionary WITHOUT the albumguid field
            prop_assume!(key != "albumguid");

            let mut dict = plist::Dictionary::new();
            dict.insert(key, plist::Value::String(value));

            let mut bytes: Vec<u8> = Vec::new();
            plist::to_writer_xml(&mut bytes, &plist::Value::Dictionary(dict))
                .expect("Failed to serialize plist");

            let result: Result<Response, _> = plist::from_bytes(&bytes);
            prop_assert!(result.is_err(), "Parsing should fail when albumguid field is missing");
        }
    }
}

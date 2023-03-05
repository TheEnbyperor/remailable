use std::fs::Metadata;
use base64::prelude::*;
use sha1::Digest;
use rsa::{pkcs8::DecodePublicKey, SignatureScheme};
use futures::StreamExt;

const USER_TOKEN_URL: &'static str = "https://webapp-prod.cloud.remarkable.engineering/token/json/2/user/new";
const DOWNLOAD_BLOB: &'static str = "https://internal.cloud.remarkable.com/sync/v2/signed-urls/downloads";
const UPLOAD_BLOB: &'static str = "https://internal.cloud.remarkable.com/sync/v2/signed-urls/uploads";
const SYNC_COMPLETE: &'static str = "https://internal.cloud.remarkable.com/sync/v2/sync-complete";

struct Config {
    postal_public_key: rsa::RsaPublicKey,
    device_token: String,
}

#[derive(Debug)]
struct PostalBody(Email);

#[derive(Debug, serde::Deserialize)]
struct Email {
    id: usize,
    rcpt_to: String,
    mail_from: String,
    message: String,
    base64: bool,
    size: usize,
}

#[rocket::async_trait]
impl<'r> rocket::data::FromData<'r> for PostalBody {
    type Error = ();

    async fn from_data(req: &'r rocket::Request<'_>, data: rocket::data::Data<'r>) -> rocket::data::Outcome<'r, Self> {
        let config = match req.guard::<&rocket::State<Config>>().await {
            rocket::request::Outcome::Success(config) => config,
            rocket::request::Outcome::Failure((_, _)) => return rocket::data::Outcome::Failure((rocket::http::Status::InternalServerError, ())),
            rocket::request::Outcome::Forward(_) => return rocket::data::Outcome::Failure((rocket::http::Status::InternalServerError, ()))
        };

        let sig = match req.headers().get_one("X-Postal-Signature") {
            Some(sig) => sig,
            None => return rocket::data::Outcome::Failure((rocket::http::Status::BadRequest, ()))
        };

        let sig = match BASE64_STANDARD.decode(sig) {
            Ok(sig) => sig,
            Err(_) => return rocket::data::Outcome::Failure((rocket::http::Status::BadRequest, ()))
        };

        let data = match data.open(30 * rocket::data::ByteUnit::MiB).into_bytes().await {
            Ok(data) => data.to_vec(),
            Err(_) => return rocket::data::Outcome::Failure((rocket::http::Status::PayloadTooLarge, ()))
        };

        let mut hasher = sha1::Sha1::new();
        hasher.update(&data);
        let data_hash = hasher.finalize();

        match rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>().verify(&config.postal_public_key, &data_hash, &sig) {
            Ok(_) => {},
            Err(_) => return rocket::data::Outcome::Failure((rocket::http::Status::Unauthorized, ()))
        };

        let body = match serde_json::from_slice(&data) {
            Ok(body) => body,
            Err(_) => return rocket::data::Outcome::Failure((rocket::http::Status::BadRequest, ()))
        };

        rocket::data::Outcome::Success(PostalBody(body))
    }
}

struct File<'a> {
    name: String,
    data: &'a [u8],
}

#[rocket::post("/email", data = "<body>")]
async fn email(config: &rocket::State<Config>, body: PostalBody) -> Result<&'static str, rocket::http::Status> {
    let message = if body.0.base64 {
        let m = body.0.message.replace("\n", "");
        match BASE64_STANDARD.decode(&m) {
            Ok(body) => body,
            Err(_) => return Err(rocket::http::Status::UnprocessableEntity)
        }
    } else {
        body.0.message.into_bytes()
    };

    let message = match mail_parser::Message::parse(&message) {
        Some(message) => message,
        None => return Err(rocket::http::Status::UnprocessableEntity)
    };

    let mut files = vec![];
    for a in message.attachments() {
        let h = a.headers();
        let ct = h.iter().find(|h| h.name().to_lowercase() == "content-type");
        let cd = h.iter().find(|h| h.name().to_lowercase() == "content-disposition");
        if let Some(ct) = ct {
            if let Some(ct) = ct.value().as_content_type_ref() {
                if ct.ctype() == "application" && ct.subtype() == Some("pdf") {
                    let file_name = match cd
                        .and_then(|cd| cd.value().as_content_type_ref())
                        .and_then(|cd| cd.attribute("filename")) {
                        Some(n) => n.to_string(),
                        None => format!("{}.pdf", message.subject().unwrap_or("untitled"))
                    };

                    files.push(File {
                        name: file_name,
                        data: a.contents(),
                    });
                }
            }
        }
    }

    let client = RMClient::new(&config.device_token).await?;
    let mut root = client.get_root(false).await?;

    for f in files {
        let (name, ext) = match f.name.rsplit_once(".") {
            Some((name, ext)) => (name, ext),
            None => (f.name.as_str(), "pdf"),
        };
        let mut doc = RMClient::new_doc(name, ext, "");

        let metadata = serde_json::to_vec(&doc.metadata).unwrap();
        let content = serde_json::to_vec(&doc.content).unwrap();

        let metadata_entry = Entry::from_bytes(&metadata, &format!("{}.metadata", doc.entry.document_id));
        let content_entry = Entry::from_bytes(&content, &format!("{}.content", doc.entry.document_id));
        let file_entry = Entry::from_bytes(&f.data, &format!("{}.pdf", doc.entry.document_id));

        client.upload_entry(&metadata_entry.hash, metadata).await?;
        client.upload_entry(&content_entry.hash, content).await?;
        client.upload_entry(&file_entry.hash, f.data.to_vec()).await?;

        doc.files.push(metadata_entry);
        doc.files.push(content_entry);
        doc.files.push(file_entry);
        doc.rehash();

        let doc_index = doc.index();
        let doc_index_enc = doc_index.encode();
        client.upload_entry(&doc.entry.hash, doc_index_enc.into_bytes()).await?;

        root.docs.push(doc);
    }

    root.rehash();
    let root_index = root.index();
    let root_index_enc = root_index.encode();
    client.upload_entry(&root.hash, root_index_enc.into_bytes()).await?;

    let new_generation = client.upload_root(&root).await?;
    root.generation = new_generation;
    client.sync_complete(new_generation).await?;

    Ok("ok")
}

struct RMClient {
    client: reqwest::Client,
    user_token: String,
}

#[derive(Debug)]
enum RMClientError {
    NetworkError,
    APIError,
    InvalidDeviceToken,
    InvalidData,
    WrongGeneration,
}

impl From<RMClientError> for rocket::http::Status {
    fn from(err: RMClientError) -> Self {
        match err {
            RMClientError::NetworkError => rocket::http::Status::ServiceUnavailable,
            RMClientError::APIError => rocket::http::Status::InternalServerError,
            RMClientError::InvalidDeviceToken => rocket::http::Status::Unauthorized,
            RMClientError::InvalidData => rocket::http::Status::InternalServerError,
            RMClientError::WrongGeneration => rocket::http::Status::InternalServerError,
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct BlobStorageRequest {
    http_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    inital_sync: Option<bool>,
    relative_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_path: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct BlobRootStorageRequest {
    http_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    inital_sync: Option<bool>,
    relative_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_schema: Option<String>,
    generation: u64,
}

#[derive(Debug, serde::Serialize)]
struct SyncCompleteRequest {
    generation: u64,
}

#[derive(Debug, serde::Deserialize)]
struct BlobStorageResponse {
    expires: String,
    method: String,
    relative_path: String,
    url: String,
    #[serde(default)]
    maxuploadsize_bytes: Option<u64>,
}

#[derive(Debug)]
struct Index {
    entries: Vec<Entry>
}

#[derive(Debug, Clone)]
struct Entry {
    hash: String,
    entry_type: String,
    document_id: String,
    subfiles: usize,
    size: u64
}

#[derive(Debug)]
struct HashTree {
    hash: String,
    generation: u64,
    docs: Vec<Doc>
}

#[derive(Debug)]
struct Doc {
    entry: Entry,
    files: Vec<Entry>,
    metadata: FileMetadata,
    content: Content,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Default)]
struct FileMetadata {
    #[serde(rename = "visibleName", default)]
    visible_name: String,
    #[serde(rename = "type", default)]
    collection_type: String,
    #[serde(default)]
    parent: String,
    #[serde(rename = "lastModified", default)]
    last_modified: String,
    #[serde(rename = "lastOpened", default)]
    last_opened: String,
    #[serde(rename = "lastOpenedPage", default)]
    last_opened_page: u32,
    #[serde(default)]
    version: u32,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    synced: bool,
    #[serde(default)]
    modified: bool,
    #[serde(default)]
    deleted: bool,
    #[serde(rename = "metadatamodified", default)]
    metadata_modified: bool,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Default)]
struct Content {
    #[serde(rename = "dummyDocument", default)]
    dummy_document: bool,
    #[serde(rename = "extraMetadata", default)]
    extra_metadata: ExtraMetadata,
    #[serde(rename = "fileType", default)]
    file_type: String,
    #[serde(rename = "fontName", default)]
    font_name: String,
    #[serde(rename = "lastOpenedPage", default)]
    last_opened_page: u32,
    #[serde(rename = "lineHeight", default)]
    line_height: i32,
    #[serde(default)]
    margins: i32,
    #[serde(default)]
    orientation: String,
    #[serde(rename = "pageCount", default)]
    page_count: u32,
    #[serde(default)]
    pages: Vec<String>,
    #[serde(rename = "pageTags", default)]
    tags: Vec<String>,
    #[serde(rename = "redirectionPageMap", default)]
    redirection_map: Vec<i32>,
    #[serde(rename = "textScale", default)]
    text_scale: i32,
    #[serde(default)]
    transform: Transform,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Default)]
struct ExtraMetadata {
    #[serde(rename = "LastBrushColor", default)]
    last_brush_color: String,
    #[serde(rename = "LastBrushThicknessScale", default)]
    last_brush_thickness_scale: String,
    #[serde(rename = "LastColor", default)]
    last_color: String,
    #[serde(rename = "LastEraserThicknessScale", default)]
    last_eraser_thickness_scale: String,
    #[serde(rename = "LastEraserTool", default)]
    last_eraser_tool: String,
    #[serde(rename = "LastPen", default)]
    last_pen: String,
    #[serde(rename = "LastPenColor", default)]
    last_pen_color: String,
    #[serde(rename = "LastPenThicknessScale", default)]
    last_pen_thickness_scale: String,
    #[serde(rename = "LastPencil", default)]
    last_pencil: String,
    #[serde(rename = "LastPencilColor", default)]
    last_pencil_color: String,
    #[serde(rename = "LastPencilThicknessScale", default)]
    last_pencil_thickness_scale: String,
    #[serde(rename = "LastTool", default)]
    last_tool: String,
    #[serde(rename = "ThicknessScale", default)]
    thickness_scale: String,
    #[serde(rename = "LastFinelinerv2Size", default)]
    last_finelinerv2_size: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Transform {
    m11: f32,
    m12: f32,
    m13: f32,
    m21: f32,
    m22: f32,
    m23: f32,
    m31: f32,
    m32: f32,
    m33: f32,
}

impl Default for Transform {
    fn default() -> Self {
        Self {
            m11: 1.0,
            m12: 0.0,
            m13: 0.0,
            m21: 0.0,
            m22: 1.0,
            m23: 0.0,
            m31: 0.0,
            m32: 0.0,
            m33: 1.0,
        }
    }
}

impl RMClient {
    async fn new(device_token: &str) -> Result<Self, RMClientError> {
        let client = reqwest::Client::builder()
            .user_agent("reMailableRust")
            .build().unwrap();

        let res = match client.post(USER_TOKEN_URL)
            .header("Authorization", format!("Bearer {}", device_token))
            .header("Content-Length", "0")
            .send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        };

        if !res.status().is_success() {
            return Err(RMClientError::InvalidDeviceToken)
        }

        let user_token = match res.text().await {
            Ok(user_token) => user_token,
            Err(_) => return Err(RMClientError::APIError)
        };

        Ok(RMClient {
            client,
            user_token,
        })
    }

    async fn get_url(&self, hash: &str) -> Result<String, RMClientError> {
        let res = match match self.client.post(DOWNLOAD_BLOB)
            .header("Authorization", format!("Bearer {}", self.user_token))
            .json(&BlobStorageRequest {
                http_method: "GET".to_string(),
                inital_sync: None,
                relative_path: hash.to_string(),
                parent_path: None,
            })
            .send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        }.json::<BlobStorageResponse>().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::APIError)
        };

        Ok(res.url)
    }

    async fn put_url(&self, hash: &str) -> Result<(String, Option<u64>), RMClientError> {
        let res = match match self.client.post(UPLOAD_BLOB)
            .header("Authorization", format!("Bearer {}", self.user_token))
            .json(&BlobStorageRequest {
                http_method: "PUT".to_string(),
                inital_sync: None,
                relative_path: hash.to_string(),
                parent_path: None,
            })
            .send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        }.json::<BlobStorageResponse>().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::APIError)
        };

        Ok((res.url, res.maxuploadsize_bytes))
    }

    async fn put_root_url(&self, hash: &str, generation: u64) -> Result<(String, Option<u64>), RMClientError> {
        let res = match match self.client.post(UPLOAD_BLOB)
            .header("Authorization", format!("Bearer {}", self.user_token))
            .json(&BlobRootStorageRequest {
                http_method: "PUT".to_string(),
                inital_sync: None,
                relative_path: "root".to_string(),
                root_schema: Some(hash.to_string()),
                generation,
            })
            .send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        }.json::<BlobStorageResponse>().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::APIError)
        };

        Ok((res.url, res.maxuploadsize_bytes))
    }

    async fn get_file(&self, url: &str) -> Result<(String, u64), RMClientError> {
        let res = match self.client.get(url).send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        };
        if !res.status().is_success() {
            return Err(RMClientError::APIError)
        }
        let gen = match res.headers().get("x-goog-generation").and_then(|h| h.to_str().ok()) {
            Some(gen) => gen.parse::<u64>().unwrap_or(0),
            None => 0
        };
        let text = match res.text().await {
            Ok(root) => root,
            Err(_) => return Err(RMClientError::APIError)
        };
        Ok((text, gen))
    }

    async fn upload_entry(&self, hash: &str, data: Vec<u8>) -> Result<(), RMClientError> {
        let (url, size) = self.put_url(&hash).await?;
        let mut req_build = self.client.put(url);

        if let Some(size) = size {
            req_build = req_build.header("x-goog-content-length-range", format!("0,{}", size));
        }

        let res = match req_build.body(data).send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        };
        if !res.status().is_success() {
            return Err(RMClientError::APIError)
        }
        Ok(())
    }

    async fn upload_root(&self, root: &HashTree) -> Result<u64, RMClientError> {
        let (url, size) = self.put_root_url(&root.hash, root.generation).await?;
        let mut req_build = self.client.put(url)
            .header("x-goog-if-generation-match", format!("{}", root.generation));

        if let Some(size) = size {
            req_build = req_build.header("x-goog-content-length-range", format!("0,{}", size));
        }

        let res = match req_build.body(root.hash.clone().into_bytes()).send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        };

        if res.status() == reqwest::StatusCode::PRECONDITION_FAILED {
            return Err(RMClientError::WrongGeneration)
        }

        if !res.status().is_success() {
            return Err(RMClientError::APIError)
        }

        let gen = match res.headers().get("x-goog-generation").and_then(|h| h.to_str().ok()) {
            Some(gen) => gen.parse::<u64>().unwrap_or(0),
            None => 0
        };

        Ok(gen)
    }

    async fn sync_complete(&self, generation: u64) -> Result<(), RMClientError> {
        let res = match self.client.post(SYNC_COMPLETE)
            .header("Authorization", format!("Bearer {}", self.user_token))
            .json(&SyncCompleteRequest {
                generation,
            })
            .send().await {
            Ok(res) => res,
            Err(_) => return Err(RMClientError::NetworkError)
        };
        if !res.status().is_success() {
            return Err(RMClientError::APIError)
        }
        Ok(())
    }

    async fn get_root(&self, expand: bool) -> Result<HashTree, RMClientError> {
        let root_hash_url = self.get_url("root").await?;
        let (root_hash, root_gen) = self.get_file(&root_hash_url).await?;
        let root_url = self.get_url(&root_hash).await?;
        let (root, _) = self.get_file(&root_url).await?;
        let root_index = Index::parse(&root)?;

        let docs = if expand {
            futures::stream::iter(root_index.entries.into_iter()).map(|e| async move {
                let url = self.get_url(&e.hash).await?;
                let (text, gen) = self.get_file(&url).await?;
                let index = Index::parse(&text)?;

                let metadata = match index.entries.iter().find(|ie| ie.document_id == format!("{}.metadata", e.document_id)) {
                    Some(m) => {
                        let url = self.get_url(&m.hash).await?;
                        let (text, _) = self.get_file(&url).await?;
                        match serde_json::from_str(&text) {
                            Ok(m) => m,
                            Err(_) => return Err(RMClientError::InvalidData)
                        }
                    },
                    None => return Err(RMClientError::InvalidData)
                };

                let content = match index.entries.iter().find(|ie| ie.document_id == format!("{}.content", e.document_id)) {
                    Some(m) => {
                        let url = self.get_url(&m.hash).await?;
                        let (text, _) = self.get_file(&url).await?;
                        match serde_json::from_str(&text) {
                            Ok(m) => m,
                            Err(e) => {
                                print!("{:?}", e);
                                return Err(RMClientError::InvalidData)
                            }
                        }
                    },
                    None => return Err(RMClientError::InvalidData)
                };

                Ok(Doc {
                    entry: e,
                    files: index.entries,
                    metadata,
                    content,
                })
            }).buffer_unordered(250).collect::<Vec<Result<_, _>>>().await.into_iter().collect::<Result<Vec<_>, _>>()?
        } else {
            root_index.entries.into_iter().map(|e| Doc {
                entry: e,
                files: vec![],
                metadata: FileMetadata::default(),
                content: Content::default(),
            }).collect()
        };

        Ok(HashTree {
            hash: root_hash,
            generation: root_gen,
            docs,
        })
    }

    fn new_doc(name: &str, ext: &str, parent_id: &str) -> Doc {
        Doc {
            entry: Entry {
                hash: "".to_string(),
                entry_type: "80000000".to_string(),
                document_id: uuid::Uuid::new_v4().to_string(),
                subfiles: 0,
                size: 0,
            },
            files: vec![],
            metadata: FileMetadata {
                visible_name: name.to_string(),
                collection_type: "DocumentType".to_string(),
                parent: parent_id.to_string(),
                last_modified: chrono::Utc::now().timestamp_millis().to_string(),
                last_opened: "".to_string(),
                last_opened_page: 0,
                version: 0,
                pinned: false,
                synced: false,
                modified: false,
                deleted: false,
                metadata_modified: false,
            },
            content: Content {
                dummy_document: false,
                extra_metadata: ExtraMetadata {
                    last_pen: "Finelinerv2".to_string(),
                    last_tool: "Finelinerv2".to_string(),
                    last_finelinerv2_size: "1".to_string(),
                    ..Default::default()
                },
                file_type: ext.to_string(),
                line_height:     -1,
                margins:        180,
                text_scale:      1,
                ..Default::default()
            }
        }
    }
}

impl Doc {
    fn rehash(&mut self) {
        self.files.sort_by(|e1, e2| e1.document_id.cmp(&e2.document_id));
        let mut hasher = sha2::Sha256::new();
        for f in &self.files {
            hasher.update(hex::decode(&f.hash).unwrap());
        }
        self.entry.hash = hex::encode(hasher.finalize());
    }

    fn index(&self) -> Index {
        Index {
            entries: self.files.clone()
        }
    }
}

impl Index {
    fn parse(text: &str) -> Result<Self, RMClientError> {
        let mut index_lines = text.trim().split("\n");

        let schema_version = match index_lines.next() {
            Some(line) => line,
            None => return Err(RMClientError::InvalidData)
        };
        if schema_version != "3" {
            return Err(RMClientError::InvalidData)
        }

        let mut index = Index {
            entries: vec![]
        };

        while let Some(l) = index_lines.next() {
            let fields = l.split(":").collect::<Vec<_>>();
            if fields.len() != 5 {
                return Err(RMClientError::InvalidData)
            }
            index.entries.push(Entry {
                hash: fields[0].to_string(),
                entry_type: fields[1].to_string(),
                document_id: fields[2].to_string(),
                subfiles: fields[3].parse::<usize>().unwrap_or(0),
                size: fields[4].parse::<u64>().unwrap_or(0),
            });
        }

        Ok(index)
    }

    fn encode(&self) -> String {
        let mut out = String::new();
        out.push_str("3\n");
        for e in &self.entries {
            out.push_str(&format!("{}:{}:{}:{}:{}\n", e.hash, e.entry_type, e.document_id, e.subfiles, e.size));
        }
        out
    }
}

impl Entry {
    fn from_bytes(data: &[u8], name: &str) -> Entry {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        Entry {
            hash: hex::encode(&hash),
            document_id: name.to_string(),
            entry_type: "0".to_string(),
            subfiles: 0,
            size: data.len() as u64,
        }
    }
}

impl HashTree {
    fn rehash(&mut self) {
        self.docs.sort_by(|d1, d2| d1.entry.document_id.cmp(&d2.entry.document_id));
        let mut hasher = sha2::Sha256::new();
        for d in &self.docs {
            hasher.update(hex::decode(&d.entry.hash).unwrap());
        }
        self.hash = hex::encode(hasher.finalize());
    }

    fn index(&self) -> Index {
        Index {
            entries: self.docs.iter().map(|d| d.entry.clone()).collect()
        }
    }
}

#[rocket::launch]
fn rocket() -> _ {
    let device_token = std::env::var("DEVICE_TOKEN").unwrap();
    let postal_public_key_str = std::env::var("POSTAL_PUBLIC_KEY").unwrap();

    let pubkey = BASE64_STANDARD_NO_PAD.decode(postal_public_key_str).unwrap();
    let pubkey = rsa::RsaPublicKey::from_public_key_der(&pubkey).unwrap();

    const POSTAL_PUBLIC_KEY: &'static str =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChELn1Fkauo6bduyGeXNca/z27OYNMd85JZMlNiycfFHaAXzgPd53OKV\
    SbyzBuILFPYmzkfaFuOCW2qgvFd8cAye6qLsUAqEetiuRTPpAysX3hss1TqIML51kb0ADTmylKi3Hr553qrDy9AEMFmvaKn\
    TH8o0YFozGk0QtlmiLtXQIDAQAB";

    rocket::build()
        .manage(Config {
            postal_public_key: pubkey,
            device_token: device_token.to_string(),
        })
        .mount("/", rocket::routes![email])
}

// const ROOT: &'static str = include_str!("../root");
//
// #[rocket::main]
// async fn main() {
//     let client = RMClient::new(DEVCE_TOKEN).await.unwrap();
//     let root = client.get_root(false).await.unwrap();
//     println!("{:?}", root);
//
//     let root_index = Index::parse(ROOT).unwrap();
//     println!("{:?}", root_index);
//
//     let mut root = HashTree {
//         hash: "".to_string(),
//         generation: root.generation,
//         docs: root_index.entries.into_iter().map(|e| Doc {
//             entry: e,
//             files: vec![],
//             metadata: FileMetadata::default(),
//             content: Content::default(),
//         }).collect(),
//     };
//     root.rehash();
//
//     let ng = client.upload_root(&root).await.unwrap();
//     client.sync_complete(ng).await.unwrap();
// }
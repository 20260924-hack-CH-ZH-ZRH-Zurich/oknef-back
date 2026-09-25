use crate::{
    App, AppError, AppResult,
    application::{auth, security},
    domain::now,
};
use axum::{
    Json,
    extract::{Multipart, State},
    http::HeaderMap,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const MAX_FILE_BYTES: usize = 20 * 1024 * 1024;
const FIELDS: &[&str] = &[
    "kind",
    "title",
    "content",
    "reference_text",
    "locale",
    "parent_session_id",
    "source",
    "asset_ids",
    "captured_at",
];

struct Upload {
    name: String,
    mime: String,
    bytes: Vec<u8>,
}

fn signature(mime: &str, bytes: &[u8]) -> bool {
    match mime {
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/webp" => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
        "application/pdf" => bytes.starts_with(b"%PDF-"),
        "audio/wav" => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE"),
        "audio/ogg" => bytes.starts_with(b"OggS"),
        "audio/mpeg" => {
            bytes.starts_with(b"ID3")
                || bytes.first() == Some(&0xff) && bytes.get(1).is_some_and(|b| b & 0xe0 == 0xe0)
        }
        "audio/mp4" | "video/mp4" | "video/quicktime" => bytes.get(4..8) == Some(b"ftyp"),
        "audio/webm" | "video/webm" => bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]),
        "text/plain" => std::str::from_utf8(bytes).is_ok_and(|text| !text.contains('\0')),
        _ => false,
    }
}

fn upload(name: String, mime: &str, bytes: Vec<u8>) -> AppResult<Upload> {
    let mime = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 200
        || name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
    {
        return Err(AppError::bad(
            "Use a filename of 1-200 characters without paths or control characters",
        ));
    }
    if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
        return Err(AppError::bad("Upload one nonempty file of at most 20 MiB"));
    }
    if !signature(&mime, &bytes) {
        return Err(AppError::bad(
            "The file signature must match a supported image, PDF, audio, video, or UTF-8 text type",
        ));
    }
    Ok(Upload { name, mime, bytes })
}

async fn read(mut multipart: Multipart) -> AppResult<(Upload, HashMap<String, String>)> {
    let mut file = None;
    let mut fields = HashMap::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::bad("Invalid multipart upload"))?
    {
        let name = field.name().unwrap_or("").to_owned();
        if name == "file" {
            if file.is_some() {
                return Err(AppError::bad("Upload exactly one file"));
            }
            let filename = field.file_name().unwrap_or("capture").to_owned();
            let mime = field
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_owned();
            let bytes = field
                .bytes()
                .await
                .map_err(|_| AppError::bad("Unreadable upload or body limit exceeded"))?;
            file = Some(upload(filename, &mime, bytes.to_vec())?);
        } else {
            if !FIELDS.contains(&name.as_str())
                || fields.contains_key(&name)
                || field.file_name().is_some()
            {
                return Err(AppError::bad("Unsupported or duplicate capture field"));
            }
            let value = field
                .text()
                .await
                .map_err(|_| AppError::bad("Invalid capture text field"))?;
            let max = if ["content", "reference_text"].contains(&name.as_str()) {
                32000
            } else {
                2000
            };
            if value.len() > max {
                return Err(AppError::bad("Capture text field exceeds its limit"));
            }
            fields.insert(name, value);
        }
    }
    Ok((
        file.ok_or_else(|| AppError::bad("A capture file is required"))?,
        fields,
    ))
}

fn prepare(file: Upload, mut fields: HashMap<String, String>) -> AppResult<(Value, Value)> {
    if fields
        .remove("locale")
        .is_some_and(|locale| !["en", "es", "de", "fr"].contains(&locale.as_str()))
    {
        return Err(AppError::bad("Choose en, es, de, or fr"));
    }
    let source = fields.remove("source").unwrap_or_else(|| "upload".into());
    if !["camera", "upload", "microphone", "text"].contains(&source.as_str()) {
        return Err(AppError::bad("Unsupported capture source"));
    }
    let mut evidence = json!({"id":uuid::Uuid::new_v4().to_string(), "name":file.name, "mime_type":file.mime,
        "size_bytes":file.bytes.len(), "sha256":format!("{:x}",Sha256::digest(&file.bytes)), "source":source,
        "provenance":"server_received_upload", "digest_verified":true, "bytes_retained":false,
        "received_at":now(), "source_verified":false, "content_provenance":"user_reviewed_extraction"});
    if let Some(captured) = fields.remove("captured_at") {
        let captured = captured
            .parse::<u64>()
            .ok()
            .filter(|date| *date <= now() + 300)
            .ok_or_else(|| AppError::bad("Invalid capture timestamp"))?;
        evidence["captured_at"] = json!(captured);
    }
    let mut body = json!({});
    for (key, value) in fields {
        body[&key] = if key == "asset_ids" {
            serde_json::from_str(&value)
                .map_err(|_| AppError::bad("Asset references must be a JSON array"))?
        } else {
            json!(value)
        };
    }
    Ok((body, json!([evidence])))
}

pub async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    multipart: Multipart,
) -> AppResult<Json<Value>> {
    let user = auth::session(&app, &headers).await?;
    app.limit(&format!("capture:{}", user["id"]), 30, 300)?;
    let (file, fields) = read(multipart).await?;
    let (body, evidence) = prepare(file, fields)?;
    security::create_with_evidence(&app, &user, body, evidence, false)
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_received_bytes_define_digest_not_client_fields() {
        let file = upload(
            "note.txt".into(),
            "text/plain",
            b"untrusted evidence".to_vec(),
        )
        .unwrap();
        let (_, evidence) = prepare(file, HashMap::new()).unwrap();
        assert_eq!(
            evidence[0]["sha256"],
            format!("{:x}", Sha256::digest(b"untrusted evidence"))
        );
        assert_eq!(evidence[0]["digest_verified"], true);
        assert_eq!(evidence[0]["source_verified"], false);
        assert_eq!(evidence[0]["bytes_retained"], false);
    }

    #[test]
    fn file_validation_rejects_mismatch_paths_empty_and_unsupported_types() {
        for (name, mime, bytes) in [
            ("bad.png", "image/png", b"not a PNG".as_slice()),
            ("../note.txt", "text/plain", b"text"),
            ("x.txt", "text/plain", b""),
            ("x.html", "text/html", b"<script>"),
        ] {
            assert!(upload(name.into(), mime, bytes.to_vec()).is_err());
        }
        assert!(upload("a.txt".into(), "text/plain", vec![b'a'; MAX_FILE_BYTES + 1]).is_err());
        assert!(
            upload(
                "a.webm".into(),
                "audio/webm;codecs=opus",
                vec![0x1a, 0x45, 0xdf, 0xa3, 0]
            )
            .is_ok()
        );
    }

    #[test]
    fn capture_context_rejects_unknown_source_locale_and_future_time() {
        for (key, value) in [
            ("source", "issuer_verified"),
            ("locale", "xx"),
            ("captured_at", "18446744073709551615"),
        ] {
            let file = upload("a.txt".into(), "text/plain", b"text".to_vec()).unwrap();
            assert!(prepare(file, HashMap::from([(key.into(), value.into())])).is_err());
        }
    }
}

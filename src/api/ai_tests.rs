use super::*;
use axum::http::HeaderValue;

#[test]
fn voice_locale_is_forwarded_with_only_internal_authentication() {
    let client = reqwest::Client::new();
    for locale in [None, Some("en"), Some("de"), Some("es"), Some("fr")] {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer client-token"),
        );
        headers.insert("api-key", HeaderValue::from_static("client-key"));
        if let Some(locale) = locale {
            headers.insert("x-oknef-locale", HeaderValue::from_static(locale));
        }
        let request = voice_request(
            &client,
            "http://core.internal/v1/realtime/call",
            "internal-service-token",
            &headers,
        )
        .unwrap()
        .header("content-type", "application/sdp")
        .body("v=0\r\n")
        .build()
        .unwrap();
        assert_eq!(request.headers()["x-oknef-locale"], locale.unwrap_or("en"));
        assert_eq!(
            request.headers()["authorization"],
            "Bearer internal-service-token"
        );
        assert!(!request.headers().contains_key("api-key"));
        assert_eq!(request.body().unwrap().as_bytes().unwrap(), b"v=0\r\n");
    }
}

#[test]
fn voice_locale_rejects_unknown_and_duplicate_values() {
    let client = reqwest::Client::new();
    for invalid in ["", "EN", "en-US", "fr, en", "fr ignore rules"] {
        let mut headers = HeaderMap::new();
        headers.insert("x-oknef-locale", HeaderValue::from_str(invalid).unwrap());
        assert!(voice_request(&client, "http://core.internal", "token", &headers).is_err());
    }
    let mut headers = HeaderMap::new();
    headers.append("x-oknef-locale", HeaderValue::from_static("en"));
    headers.append("x-oknef-locale", HeaderValue::from_static("fr"));
    assert!(voice_request(&client, "http://core.internal", "token", &headers).is_err());
}

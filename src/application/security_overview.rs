use crate::{
    App, AppResult,
    application::{records, security},
    domain::now,
};
use serde_json::{Value, json};

pub async fn settings(app: &App, user: &Value) -> AppResult<Value> {
    Ok(app
        .db
        .records(records::tenant(user)?, "security_settings")
        .await?
        .into_iter()
        .next()
        .unwrap_or_else(|| json!({"mode":"standard","updated_at":null,"scope":"in_app_checks"})))
}

pub async fn mode(app: &App, user: &Value, body: Value) -> AppResult<Value> {
    security::fields(&body, &["mode"])?;
    let mode = security::text(&body, "mode", 20)?;
    if !["standard", "active", "paranoid"].contains(&mode) {
        return Err(crate::AppError::bad("Choose standard, active, or paranoid"));
    }
    if user["role"] != "owner" {
        return Err(crate::AppError::new(
            axum::http::StatusCode::FORBIDDEN,
            "Owner role required",
        ));
    }
    let value = json!({"mode":mode,"updated_at":now(),"scope":"in_app_checks",
        "effect":match mode {"active"=>"Review prompts for every in-app check", "paranoid"=>"Independent verification reminder for every in-app check", _=>"Review prompts when configured text signals match"},
        "device_protection":false,"background_monitoring":false});
    app.db
        .save(
            records::tenant(user)?,
            "security_settings",
            "current",
            &value,
        )
        .await?;
    app.event(user, "security.mode_changed");
    Ok(value)
}

pub async fn overview(app: &App, user: &Value) -> AppResult<Value> {
    let tenant = records::tenant(user)?;
    let mut sessions = app.db.records(tenant, "security_sessions").await?;
    let mut events = app.db.records(tenant, "security_events").await?;
    sessions.sort_by_key(|s| std::cmp::Reverse(s["created_at"].as_u64().unwrap_or(0)));
    events.sort_by_key(|s| std::cmp::Reverse(s["created_at"].as_u64().unwrap_or(0)));
    Ok(
        json!({"trends":trends(&sessions,now()),"compliance":compliance(&sessions),"sessions":sessions,
        "events":events,"attack_vectors":attack_vectors(),"settings":settings(app,user).await?,
        "capabilities":{"deepfake_detection":false,"mailbox_monitoring":false,"call_interception":false,
        "url_reputation":false,"document_authentication":false,"evidence_persistence":true,"in_app_alerts":true}}),
    )
}

pub fn trends(sessions: &[Value], timestamp: u64) -> Vec<Value> {
    let today = timestamp / 86400 * 86400;
    (0..30).map(|offset| {
        let day=today.saturating_sub((29-offset)*86400);
        let records:Vec<_>=sessions.iter().filter(|s| s["synthetic"] == false)
            .filter(|s| s["created_at"].as_u64().is_some_and(|t| t>=day && t<day+86400 && t<=timestamp)).collect();
        json!({"day_start":day,"checks":records.len(),"flagged":records.iter().filter(|s|s["assessment"]["status"]=="review_required").count()})
    }).collect()
}

fn compliance(sessions: &[Value]) -> Value {
    let live: Vec<_> = sessions
        .iter()
        .filter(|s| s["synthetic"] == false)
        .collect();
    let document = live.iter().filter(|s| s["kind"] == "document").count();
    let controls = json!([
        {"id":"session_traceability","label":"Submitted evidence and method recorded","evidence_count":live.len(),"status":if live.is_empty(){"missing"}else{"evidence_present"}},
        {"id":"document_reference","label":"Document review evidence","evidence_count":document,"status":if document==0{"missing"}else{"evidence_present"}},
        {"id":"pad_evaluation","label":"Independent presentation-attack detection evaluation","evidence_count":0,"status":"not_assessed"},
        {"id":"regulatory_assessment","label":"Independent regulatory applicability assessment","evidence_count":0,"status":"not_assessed"}
    ]);
    json!({"status":"not_assessed","certified":false,"coverage_percent":((!live.is_empty()) as usize+(document>0) as usize)*25,
        "evidence_count":live.len(),"controls":controls,"frameworks":["ISO/IEC 30107","FINMA"],
        "measurement":"Percentage of four internal evidence categories with records; not a standards compliance score",
        "limitations":"No ISO certification, PAD benchmark, FINMA assessment or legal conclusion has been performed."})
}

pub fn attack_vectors() -> Value {
    json!([
        {"id":"qr_phishing","title":"QR and link phishing","channel":"qr","impact":"Credential theft or payment redirection","mitigation":"Inspect decoded text before opening; verify the destination independently","validation":"Deterministic URL and request-pattern fixtures","status":"rules_available"},
        {"id":"email_impersonation","title":"Email impersonation","channel":"email","impact":"Secret disclosure and fraudulent instructions","mitigation":"Record pressure and credential signals; verify through a known channel","validation":"Submitted-text rules; no mailbox authentication integration","status":"rules_available"},
        {"id":"prompt_injection","title":"Instructions embedded in evidence","channel":"document","impact":"Agent attempts to bypass policy or disclose data","mitigation":"Treat evidence as data; never execute embedded instructions","validation":"Adversarial text fixtures and server-owned evidence fields","status":"rules_available"},
        {"id":"voice_impersonation","title":"Voice impersonation","channel":"call","impact":"Fraudulent high-pressure calls","mitigation":"Check transcript pressure, end the call and use a known callback number","validation":"Transcript rules only; no acoustic deepfake classifier","status":"requires_external_validation"},
        {"id":"document_forgery","title":"Document forgery","channel":"document","impact":"Onboarding with altered identity evidence","mitigation":"Compare supplied reference text and require issuer or specialist review","validation":"Text comparison only; no issuer authentication","status":"requires_external_validation"},
        {"id":"presentation_attack","title":"Presentation and digital injection attacks","channel":"identity","impact":"Bypassing a biometric capture process","mitigation":"Trusted capture, challenge freshness and independent PAD evaluation","validation":"No capture pipeline or PAD dataset connected","status":"research_only"},
        {"id":"iot_identity","title":"Device and eSIM identity misuse","channel":"iot","impact":"Unauthorized connected-device access","mitigation":"Inventory identities and require provider-backed device attestation","validation":"No telecom provisioning or attestation provider connected","status":"research_only"}
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trends_exclude_synthetic_future_and_old_records() {
        let timestamp = 2000000000;
        let item = |created, synthetic| json!({"created_at":created,"synthetic":synthetic,"assessment":{"status":"review_required"}});
        let values = vec![
            item(timestamp, false),
            item(timestamp, true),
            item(timestamp + 1, false),
            item(timestamp - 31 * 86400, false),
        ];
        let result = trends(&values, timestamp);
        assert_eq!(result.len(), 30);
        assert_eq!(
            result
                .iter()
                .filter_map(|v| v["checks"].as_u64())
                .sum::<u64>(),
            1
        );
        assert_eq!(compliance(&[])["certified"], false);
    }
}

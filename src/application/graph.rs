use crate::{App, AppResult, application::records, domain::now};
use serde_json::{Value, json};
use std::collections::HashSet;

pub async fn get(app: &App, user: &Value) -> AppResult<Value> {
    let tenant = records::tenant(user)?;
    let mut nodes = vec![
        json!({"id":tenant,"kind":"workspace","label":user["account_type"],"synthetic":user["demo"]==true}),
    ];
    let mut edges = Vec::new();
    let mut candidates = Vec::new();
    for (collection, kind, label) in [
        ("assets", "asset", "name"),
        ("vault", "encrypted_item", "id"),
        ("drive", "encrypted_file", "id"),
        ("integrations", "integration", "name"),
        ("security_sessions", "evidence_session", "title"),
        ("chat_sessions", "chat_session", "title"),
        ("succession", "succession", "title"),
        ("approval_policies", "approval_policy", "title"),
        ("approval_requests", "approval_request", "title"),
        ("workflow_runs", "agent_workflow", "workflow"),
    ] {
        for value in app.db.records(tenant, collection).await? {
            let Some(id) = value["id"].as_str() else {
                continue;
            };
            nodes.push(json!({"id":id,"kind":kind,"label":value[label],"status":value["status"],"created_at":value["created_at"],"synthetic":value.get("synthetic").cloned().unwrap_or_else(|| json!(user["demo"]==true))}));
            edges.push(json!({"source":tenant,"target":id,"relation":"contains","provenance":"tenant_record"}));
            for asset in value["asset_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                candidates.push(json!({"source":id,"target":asset,"relation":"references_asset","provenance":"stored_reference"}));
            }
            for (field, relation) in [
                ("parent_session_id", "continued_from"),
                ("policy_id", "governed_by"),
                ("source_session_id", "discovered_from"),
            ] {
                if let Some(target) = value[field].as_str() {
                    candidates.push(json!({"source":id,"target":target,"relation":relation,"provenance":"stored_reference"}));
                }
            }
        }
    }
    let ids: HashSet<_> = nodes
        .iter()
        .filter_map(|node| node["id"].as_str())
        .collect();
    edges.extend(candidates.into_iter().filter(|edge| {
        edge["target"]
            .as_str()
            .is_some_and(|target| ids.contains(target))
    }));
    Ok(
        json!({"nodes":nodes,"edges":edges,"generated_at":now(),"scope":"current_workspace","discovery":"stored_records_and_explicit_references","physical_network_scan":false}),
    )
}

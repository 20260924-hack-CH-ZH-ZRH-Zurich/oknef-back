use super::*;
fn registration(state: &PasskeyState) -> (Value, Ceremony) {
    let (options, registration) = state
        .webauthn
        .start_passkey_registration(Uuid::new_v4(), "test@example.test", "Test", None)
        .unwrap();
    (
        serde_json::to_value(options).unwrap(),
        Ceremony::Register(registration),
    )
}
#[test]
fn configured_origin_is_strict_and_secure() {
    assert!(PasskeyState::new("https://oknef.example").is_ok());
    assert!(PasskeyState::new("http://localhost:3180").is_ok());
    for invalid in [
        "http://oknef.example",
        "invalid",
        "https://user:password@oknef.example",
        "https://oknef.example/path",
        "https://oknef.example?test=1",
    ] {
        assert!(PasskeyState::new(invalid).is_err());
    }
}
#[test]
fn challenge_is_unique_and_consumed_once() {
    let state = PasskeyState::new("http://localhost:3180").unwrap();
    let (first, ceremony) = registration(&state);
    let (second, _) = registration(&state);
    assert_ne!(
        first["publicKey"]["challenge"],
        second["publicKey"]["challenge"]
    );
    assert_eq!(
        first["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    let id = state.insert(json!({"id":"test"}), ceremony).unwrap();
    assert!(state.consume(&id).is_ok());
    assert!(state.consume(&id).is_err());
    assert!(state.consume("unknown").is_err());
}
#[test]
fn expired_challenge_is_rejected_and_removed() {
    let state = PasskeyState::new("http://localhost:3180").unwrap();
    let (_, ceremony) = registration(&state);
    let id = state.insert(json!({"id":"test"}), ceremony).unwrap();
    state.pending.lock().unwrap().get_mut(&id).unwrap().expires = 0;
    assert!(state.consume(&id).is_err());
    assert!(!state.pending.lock().unwrap().contains_key(&id));
}
#[test]
fn cache_sweeps_expired_challenges() {
    let state = PasskeyState::new("http://localhost:3180").unwrap();
    let (_, ceremony) = registration(&state);
    let id = state.insert(json!({}), ceremony).unwrap();
    state.pending.lock().unwrap().get_mut(&id).unwrap().expires = 0;
    let (_, next) = registration(&state);
    state.insert(json!({}), next).unwrap();
    assert!(!state.pending.lock().unwrap().contains_key(&id));
}

#[test]
fn passkey_account_is_independent_of_active_workspace_but_not_identity() {
    let owner = json!({"id":"account-a","email":"a@example.test","tenant_id":"personal"});
    let active = json!({"id":"account-a","email":"a@example.test","tenant_id":"company"});
    assert!(same_account(&active, &owner).is_ok());
    assert!(same_account(&json!({"id":"account-b","email":"a@example.test"}), &owner).is_err());
    assert!(same_account(&json!({"id":"account-a","email":"b@example.test"}), &owner).is_err());
    assert!(same_account(&json!({}), &json!({})).is_err());
}

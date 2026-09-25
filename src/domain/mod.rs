pub mod security;
mod security_patterns;

pub fn valid_email(email: &str) -> bool {
    email.len() <= 254
        && email.contains('@')
        && email.split('@').count() == 2
        && !email.chars().any(char::is_whitespace)
        && email.split('@').all(|part| !part.is_empty())
        && email
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
}
pub fn valid_name(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(|c| c.is_control())
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn can_review(status: &str) -> bool {
    status == "draft"
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn email_rejects_path_and_control_injection() {
        assert!(!valid_email("x@a/../../b"));
        assert!(!valid_email("x@y\nHost:x"));
        assert!(valid_email("person+test@example.test"));
    }
    #[test]
    fn succession_cannot_skip_human_gate() {
        assert!(can_review("draft"));
        for state in ["review_requested", "released", "approved", "cancelled"] {
            assert!(!can_review(state));
        }
    }
}

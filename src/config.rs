#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub db_url: String,
    pub db_token: String,
    pub core_url: String,
    pub core_grpc_url: String,
    pub core_token: String,
    pub origin: String,
    pub cookie_secure: bool,
    pub demo_email: String,
    pub demo_password: String,
    pub demo_enabled: bool,
    pub covenant_url: String,
    pub covenant_token: String,
}
impl Config {
    pub fn from_env() -> Result<Self, String> {
        let _ = dotenvy::dotenv();
        let get = |n| std::env::var(n).map_err(|_| format!("{n} is required"));
        let config = Self {
            covenant_url: get("COVENANT_URL")?,
            covenant_token: get("COVENANT_TOKEN")?,
            bind: get("HTTP_BIND")?,
            db_url: get("DATABASE_SERVICE_URL")?.trim_end_matches('/').into(),
            db_token: get("DB_SERVICE_TOKEN")?,
            core_url: get("AI_CORE_URL")?.trim_end_matches('/').into(),
            core_grpc_url: get("AI_CORE_GRPC_URL")?,
            core_token: get("AI_CORE_TOKEN")?,
            origin: get("PUBLIC_ORIGIN")?.trim_end_matches('/').into(),
            cookie_secure: get("COOKIE_SECURE")? == "true",
            demo_email: get("DEMO_EMAIL")?,
            demo_password: get("DEMO_PASSWORD")?,
            demo_enabled: std::env::var("DEMO_ENABLED").unwrap_or_else(|_| "true".into()) == "true",
        };
        if config.db_token.len() < 32 || config.core_token.len() < 32 {
            return Err("Service tokens require at least 32 characters".into());
        }
        if config.demo_password.len() < 16 {
            return Err("Demo credential must contain at least 16 characters".into());
        }
        if config.origin.starts_with("https://") && !config.cookie_secure {
            return Err("Secure cookies are required with HTTPS".into());
        }
        Ok(config)
    }
}

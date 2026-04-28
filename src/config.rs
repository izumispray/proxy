use serde::Deserialize;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub singbox: SingboxConfig,
    pub database: DatabaseConfig,
    pub validation: ValidationConfig,
    pub quality: QualityConfig,
    pub oauth: OAuthConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub subscription: SubscriptionConfig,
    #[serde(default)]
    pub proxy_listener: Vec<ProxyListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub admin_password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub required_guild_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SingboxConfig {
    pub binary_path: PathBuf,
    pub config_path: PathBuf,
    pub base_port: u16,
    /// Binding/port budget for live sing-box outbounds, not the total proxy inventory cap.
    #[serde(default = "default_max_proxies")]
    pub max_proxies: usize,
    #[serde(default = "default_prebound_proxies")]
    pub prebound_proxies: usize,
    #[serde(default = "default_binding_idle_secs")]
    pub binding_idle_secs: u64,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_watchdog_interval_secs")]
    pub watchdog_interval_secs: u64,
    #[serde(default)]
    pub restart_interval_mins: u64,
    /// Restart sing-box when its RSS exceeds this many MiB. Set 0 to disable.
    #[serde(default = "default_memory_restart_mb")]
    pub memory_restart_mb: u64,
    pub api_secret: Option<String>,
}

fn default_max_proxies() -> usize {
    20000
}

fn default_prebound_proxies() -> usize {
    200
}

fn default_binding_idle_secs() -> u64 {
    300
}

fn default_api_port() -> u16 {
    9090
}

fn default_watchdog_interval_secs() -> u64 {
    60
}

fn default_memory_restart_mb() -> u64 {
    3072
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidationConfig {
    pub url: String,
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub interval_mins: u64,
    pub error_threshold: u32,
    #[serde(default = "default_validation_max_rounds")]
    pub max_rounds_per_run: usize,
    #[serde(default = "default_retry_invalid_per_run")]
    pub retry_invalid_per_run: usize,
    /// How many port slots to reserve for validation/quality-check per round.
    /// The rest stay with Valid proxies serving users. Default 30.
    #[serde(default = "default_validation_batch")]
    pub batch_size: usize,
}

fn default_validation_max_rounds() -> usize {
    100
}

fn default_retry_invalid_per_run() -> usize {
    60
}

fn default_validation_batch() -> usize {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct QualityConfig {
    pub interval_mins: u64,
    pub concurrency: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    #[serde(default = "default_relay_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_relay_timeout_secs(),
        }
    }
}

fn default_relay_timeout_secs() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionConfig {
    #[serde(default)]
    pub auto_refresh_interval_mins: u64, // legacy/global default for subscriptions without explicit interval
    #[serde(default = "default_orphaned_valid_grace_hours")]
    pub orphaned_valid_grace_hours: u64,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            auto_refresh_interval_mins: 0,
            orphaned_valid_grace_hours: default_orphaned_valid_grace_hours(),
        }
    }
}

fn default_orphaned_valid_grace_hours() -> u64 {
    24
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProxyListenerConfig {
    #[serde(default)]
    pub name: String,
    pub listen: String,
    pub username: String,
    pub password: String,
}

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string("config.toml")
            .unwrap_or_else(|_| include_str!("../config.toml.example").to_string());
        let mut config: AppConfig = toml::from_str(&content)?;
        config.apply_env_overrides()?;
        Ok(config)
    }

    fn apply_env_overrides(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        set_string_from_env(&mut self.server.host, "ZENPROXY_SERVER_HOST");
        set_u16_from_env(&mut self.server.port, "ZENPROXY_SERVER_PORT")?;
        set_string_from_env(&mut self.server.admin_password, "ZENPROXY_ADMIN_PASSWORD");

        set_string_from_env(&mut self.database.url, "ZENPROXY_DATABASE_URL");

        set_string_from_env(&mut self.oauth.client_id, "ZENPROXY_OAUTH_CLIENT_ID");
        set_string_from_env(&mut self.oauth.client_secret, "ZENPROXY_OAUTH_CLIENT_SECRET");
        set_string_from_env(&mut self.oauth.redirect_uri, "ZENPROXY_OAUTH_REDIRECT_URI");
        set_string_from_env(
            &mut self.oauth.required_guild_id,
            "ZENPROXY_OAUTH_REQUIRED_GUILD_ID",
        );

        // Proxy listeners from env: ZENPROXY_PROXY_LISTENER or ZENPROXY_PROXY_LISTENER_1..N
        let mut env_listeners = Vec::new();
        if let Some(val) = env_value("ZENPROXY_PROXY_LISTENER") {
            if let Some(cfg) = parse_listener_uri(&val, "env") {
                env_listeners.push(cfg);
            }
        }
        for i in 1..=10 {
            let key = format!("ZENPROXY_PROXY_LISTENER_{i}");
            if let Some(val) = env_value(&key) {
                if let Some(cfg) = parse_listener_uri(&val, &format!("env-{i}")) {
                    env_listeners.push(cfg);
                }
            }
        }
        if !env_listeners.is_empty() {
            self.proxy_listener = env_listeners;
        }

        Ok(())
    }
}

fn env_value(key: &str) -> Option<String> {
    env::var_os(key).map(|value| value.to_string_lossy().into_owned())
}

fn set_string_from_env(target: &mut String, key: &str) {
    if let Some(value) = env_value(key) {
        *target = value;
    }
}

fn set_u16_from_env(target: &mut u16, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(value) = env_value(key) {
        *target = value.parse()?;
    }
    Ok(())
}

/// Parse `user:pass@host:port` into a `ProxyListenerConfig`.
fn parse_listener_uri(uri: &str, default_name: &str) -> Option<ProxyListenerConfig> {
    let (creds, listen) = uri.rsplit_once('@')?;
    let (username, password) = creds.split_once(':')?;
    if username.is_empty() || password.is_empty() || listen.is_empty() {
        return None;
    }
    Some(ProxyListenerConfig {
        name: default_name.to_string(),
        listen: listen.to_string(),
        username: username.to_string(),
        password: password.to_string(),
    })
}

use serde::Deserialize;
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

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string("config.toml")
            .unwrap_or_else(|_| include_str!("../config.toml.example").to_string());
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

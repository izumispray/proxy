use crate::config::SingboxConfig;
use crate::singbox::config::generate_minimal_config;
use serde::Deserialize;
use std::collections::HashSet;
use std::process::Stdio;
use tokio::process::{Child, Command};

const CREATE_BINDING_MAX_ATTEMPTS: usize = 16;

pub struct SingboxManager {
    config: SingboxConfig,
    process: Option<Child>,
    client: reqwest::Client,
    api_base: String,
    port_pool: PortPool,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiBinding {
    tag: String,
    listen_port: u16,
}

struct PortPool {
    base_port: u16,
    max_ports: u16,
    used: HashSet<u16>,
}

impl PortPool {
    fn new(base_port: u16, max_ports: u16) -> Self {
        PortPool {
            base_port,
            max_ports,
            used: HashSet::new(),
        }
    }

    fn allocate(&mut self) -> Option<u16> {
        for offset in 1..=self.max_ports {
            let port = self.base_port + offset;
            if !self.used.contains(&port) {
                self.used.insert(port);
                return Some(port);
            }
        }
        None
    }

    fn free(&mut self, port: u16) {
        self.used.remove(&port);
    }

    fn mark_used(&mut self, port: u16) {
        if self.in_range(port) {
            self.used.insert(port);
        }
    }

    fn replace_used<I>(&mut self, ports: I)
    where
        I: IntoIterator<Item = u16>,
    {
        self.used = ports
            .into_iter()
            .filter(|port| self.in_range(*port))
            .collect();
    }

    fn in_range(&self, port: u16) -> bool {
        let start = self.base_port.saturating_add(1);
        let end = self.base_port.saturating_add(self.max_ports);
        port >= start && port <= end
    }

    fn used_count(&self) -> usize {
        self.used.len()
    }
}

impl SingboxManager {
    pub fn new(config: SingboxConfig, extra_ports: u16) -> Self {
        let api_base = format!("http://127.0.0.1:{}", config.api_port);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");

        let max_ports = config.max_proxies as u16 + extra_ports;
        let base_port = config.base_port;

        SingboxManager {
            config,
            process: None,
            client,
            api_base,
            port_pool: PortPool::new(base_port, max_ports),
        }
    }

    /// Start sing-box with minimal config, then poll the API until ready.
    pub async fn start(&mut self) -> Result<(), String> {
        // Generate minimal config
        let api_addr = format!("127.0.0.1:{}", self.config.api_port);
        let api_secret = self.config.api_secret.as_deref().unwrap_or("");
        let config_json = generate_minimal_config(&api_addr, api_secret);
        let config_str = serde_json::to_string_pretty(&config_json)
            .map_err(|e| format!("Failed to serialize config: {e}"))?;

        // Ensure directory exists
        if let Some(parent) = self.config.config_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Write config file
        std::fs::write(&self.config.config_path, &config_str)
            .map_err(|e| format!("Failed to write config: {e}"))?;

        tracing::info!(
            "Generated minimal sing-box config at {}",
            self.config.config_path.display()
        );

        // Resolve binary
        let binary = which_singbox(&self.config.binary_path);

        let config_path = self
            .config
            .config_path
            .canonicalize()
            .unwrap_or_else(|_| self.config.config_path.clone());

        tracing::info!(
            "Starting sing-box: {} run -c {}",
            binary.display(),
            config_path.display()
        );

        let child = Command::new(&binary)
            .args(["run", "-c", &config_path.to_string_lossy()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to start sing-box: {e}"))?;

        tracing::info!("sing-box started with PID: {:?}", child.id());
        self.process = Some(child);

        // Poll the Clash API until it's ready
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut ready = false;
        while tokio::time::Instant::now() < deadline {
            if self.client.get(&self.api_base).send().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        if ready {
            tracing::info!("sing-box API ready at {}", self.api_base);
            if let Err(e) = self.refresh_port_pool_from_api().await {
                tracing::warn!("Failed to sync binding ports from API on startup: {e}");
            }
        } else {
            tracing::warn!("sing-box API readiness probe timed out, proceeding anyway");
        }

        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            tracing::info!("Stopping sing-box process...");
            let _ = child.kill().await;
            let _ = child.wait().await;
            tracing::info!("sing-box process stopped");
        }
    }

    async fn fetch_bindings(&self) -> Result<Vec<ApiBinding>, String> {
        let url = format!("{}/bindings", self.api_base);
        let secret = self.config.api_secret.clone().unwrap_or_default();

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&secret)
            .send()
            .await
            .map_err(|e| format!("Bindings API LIST request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Bindings API LIST returned {status}: {body}"));
        }

        resp.json::<Vec<ApiBinding>>()
            .await
            .map_err(|e| format!("Bindings API LIST decode failed: {e}"))
    }

    async fn refresh_port_pool_from_api(&mut self) -> Result<Vec<ApiBinding>, String> {
        let bindings = self.fetch_bindings().await?;
        self.port_pool
            .replace_used(bindings.iter().map(|binding| binding.listen_port));
        Ok(bindings)
    }

    /// Create a binding: allocate a port and POST to the bindings API.
    /// Returns the allocated local port on success.
    pub async fn create_binding(
        &mut self,
        proxy_id: &str,
        outbound_json: &serde_json::Value,
    ) -> Result<u16, String> {
        match self.refresh_port_pool_from_api().await {
            Ok(bindings) => {
                if let Some(port) = find_binding_port(&bindings, proxy_id) {
                    tracing::warn!(
                        "Binding {proxy_id} already exists in API on port {port}, reusing it"
                    );
                    return Ok(port);
                }
            }
            Err(e) => tracing::warn!("Failed to sync binding ports before create {proxy_id}: {e}"),
        }

        let url = format!("{}/bindings", self.api_base);
        let secret = self.config.api_secret.clone().unwrap_or_default();
        let mut last_error = None;

        for _ in 0..CREATE_BINDING_MAX_ATTEMPTS {
            let port = self
                .port_pool
                .allocate()
                .ok_or_else(|| "No available ports in pool".to_string())?;

            let payload = serde_json::json!({
                "tag": proxy_id,
                "listen_port": port,
                "outbound": outbound_json,
            });

            let result = self
                .client
                .post(&url)
                .bearer_auth(&secret)
                .json(&payload)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("Created binding {proxy_id} on port {port}");
                    return Ok(port);
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let err = format!("Bindings API returned {status} for {proxy_id}: {body}");

                    match self.refresh_port_pool_from_api().await {
                        Ok(bindings) => {
                            if let Some(existing_port) = find_binding_port(&bindings, proxy_id) {
                                tracing::warn!(
                                    "Binding {proxy_id} appeared in API on port {existing_port} after create error, reusing it"
                                );
                                return Ok(existing_port);
                            }
                        }
                        Err(sync_err) => {
                            tracing::warn!(
                                "Failed to resync binding ports after create error for {proxy_id}: {sync_err}"
                            );
                        }
                    }

                    if is_bind_address_in_use_error(&body) {
                        // Keep the port reserved locally so the next allocation skips it even if
                        // sing-box still has a listener that our app state missed.
                        self.port_pool.mark_used(port);
                        last_error = Some(err);
                        continue;
                    }

                    self.port_pool.free(port);
                    return Err(err);
                }
                Err(e) => {
                    let err = format!("Bindings API request failed for {proxy_id}: {e}");

                    match self.refresh_port_pool_from_api().await {
                        Ok(bindings) => {
                            if let Some(existing_port) = find_binding_port(&bindings, proxy_id) {
                                tracing::warn!(
                                    "Binding {proxy_id} appeared in API on port {existing_port} after request error, reusing it"
                                );
                                return Ok(existing_port);
                            }
                        }
                        Err(sync_err) => {
                            tracing::warn!(
                                "Failed to resync binding ports after request error for {proxy_id}: {sync_err}"
                            );
                        }
                    }

                    self.port_pool.free(port);
                    return Err(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            format!("Failed to create binding for {proxy_id}: no free port after retries")
        }))
    }

    /// Remove a binding: DELETE from the API and free the port.
    pub async fn remove_binding(&mut self, proxy_id: &str, port: u16) -> Result<(), String> {
        let url = format!("{}/bindings/{}", self.api_base, proxy_id);
        let secret = self.config.api_secret.clone().unwrap_or_default();

        let result = self
            .client
            .delete(&url)
            .bearer_auth(&secret)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                self.port_pool.free(port);
                tracing::debug!("Removed binding {proxy_id} (port {port})");
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let err = format!("Bindings API DELETE returned {status} for {proxy_id}: {body}");

                match self.refresh_port_pool_from_api().await {
                    Ok(bindings) => {
                        if !binding_or_port_present(&bindings, proxy_id, port) {
                            self.port_pool.free(port);
                            if status == reqwest::StatusCode::NOT_FOUND {
                                tracing::debug!(
                                    "Binding {proxy_id} already absent in API during delete, treating as removed"
                                );
                                return Ok(());
                            }
                            tracing::debug!(
                                "Binding {proxy_id} absent after delete error, treating local state as cleaned up"
                            );
                            return Ok(());
                        }
                    }
                    Err(sync_err) => {
                        tracing::warn!(
                            "Failed to resync binding ports after delete error for {proxy_id}: {sync_err}"
                        );
                    }
                }

                Err(err)
            }
            Err(e) => {
                let err = format!("Bindings API DELETE request failed for {proxy_id}: {e}");

                match self.refresh_port_pool_from_api().await {
                    Ok(bindings) => {
                        if !binding_or_port_present(&bindings, proxy_id, port) {
                            self.port_pool.free(port);
                            tracing::debug!(
                                "Binding {proxy_id} absent after delete request error, treating local state as cleaned up"
                            );
                            return Ok(());
                        }
                    }
                    Err(sync_err) => {
                        tracing::warn!(
                            "Failed to resync binding ports after delete request error for {proxy_id}: {sync_err}"
                        );
                    }
                }

                Err(err)
            }
        }
    }

    /// Sync bindings: compute diff between desired and current, then remove/add as needed.
    /// `desired` is a list of (proxy_id, outbound_json, current_local_port).
    /// Returns a list of (proxy_id, assigned_port) for successfully created bindings.
    pub async fn sync_bindings(
        &mut self,
        desired: &[(String, serde_json::Value)],
        current_ports: &[(String, u16)],
    ) -> Vec<(String, u16)> {
        let api_current_ports = match self.refresh_port_pool_from_api().await {
            Ok(bindings) => bindings_to_ports(&bindings),
            Err(e) => {
                tracing::warn!("Failed to sync binding ports before batch sync: {e}");
                current_ports.to_vec()
            }
        };

        let desired_ids: HashSet<&str> = desired.iter().map(|(id, _)| id.as_str()).collect();
        let current_map: std::collections::HashMap<&str, u16> = api_current_ports
            .iter()
            .map(|(id, port)| (id.as_str(), *port))
            .collect();

        let api_current_id_set: HashSet<&str> = current_map.keys().copied().collect();
        let stale_local_ids: Vec<&str> = current_ports
            .iter()
            .map(|(id, _)| id.as_str())
            .filter(|id| !api_current_id_set.contains(id))
            .collect();
        if !stale_local_ids.is_empty() {
            tracing::info!(
                "Ignoring {} stale local binding records missing from sing-box API",
                stale_local_ids.len()
            );
        }

        // To remove: have a port but not in desired set
        let to_remove: Vec<(String, u16)> = api_current_ports
            .iter()
            .filter(|(id, _)| !desired_ids.contains(id.as_str()))
            .cloned()
            .collect();

        // To add: in desired but don't have a port
        let to_add: Vec<(String, serde_json::Value)> = desired
            .iter()
            .filter(|(id, _)| !current_map.contains_key(id.as_str()))
            .cloned()
            .collect();

        // Remove first to free ports
        for (id, port) in &to_remove {
            if let Err(e) = self.remove_binding(id, *port).await {
                tracing::warn!("Failed to remove binding {id}: {e}");
            }
        }

        // Add new bindings
        let mut assignments = Vec::new();

        // Keep existing bindings that are still desired
        for (id, port) in &api_current_ports {
            if desired_ids.contains(id.as_str()) {
                assignments.push((id.clone(), *port));
            }
        }

        for (id, outbound) in &to_add {
            match self.create_binding(id, outbound).await {
                Ok(port) => {
                    assignments.push((id.clone(), port));
                }
                Err(e) => {
                    tracing::warn!("Failed to create binding {id}: {e}");
                }
            }
        }

        assignments
    }

    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.process {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.process = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn used_ports(&self) -> usize {
        self.port_pool.used_count()
    }
}

fn bindings_to_ports(bindings: &[ApiBinding]) -> Vec<(String, u16)> {
    bindings
        .iter()
        .map(|binding| (binding.tag.clone(), binding.listen_port))
        .collect()
}

fn find_binding_port(bindings: &[ApiBinding], proxy_id: &str) -> Option<u16> {
    bindings
        .iter()
        .find(|binding| binding.tag == proxy_id)
        .map(|binding| binding.listen_port)
}

fn binding_or_port_present(bindings: &[ApiBinding], proxy_id: &str, port: u16) -> bool {
    bindings
        .iter()
        .any(|binding| binding.tag == proxy_id || binding.listen_port == port)
}

fn is_bind_address_in_use_error(body: &str) -> bool {
    body.contains("address already in use")
}

/// Try to find sing-box: same directory as our executable first, then config path, then system PATH.
fn which_singbox(config_path: &std::path::Path) -> std::path::PathBuf {
    // 1. Check same directory as our own executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let name = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
            let local = exe_dir.join(name);
            if local.exists() {
                tracing::info!("Found sing-box next to executable: {}", local.display());
                return local;
            }
        }
    }

    // 2. Check config path
    if config_path.exists() {
        tracing::info!("Using sing-box from config: {}", config_path.display());
        return config_path.to_path_buf();
    }

    // 3. Fall back to system PATH
    for name in &["sing-box", "sing-box.exe"] {
        if let Ok(output) =
            std::process::Command::new(if cfg!(windows) { "where" } else { "which" })
                .arg(name)
                .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !path.is_empty() {
                    tracing::info!("Found sing-box in PATH: {path}");
                    return std::path::PathBuf::from(path);
                }
            }
        }
    }

    tracing::warn!(
        "sing-box not found locally or in PATH, will attempt config path: {}",
        config_path.display()
    );
    config_path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::{
        binding_or_port_present, bindings_to_ports, find_binding_port,
        is_bind_address_in_use_error, ApiBinding,
        PortPool,
    };

    #[test]
    fn port_pool_replace_used_respects_managed_range() {
        let mut pool = PortPool::new(10001, 4);
        pool.replace_used([10000, 10002, 10005, 10006]);

        assert_eq!(pool.used_count(), 2);
        assert_eq!(pool.allocate(), Some(10003));
        assert_eq!(pool.allocate(), Some(10004));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn binding_helpers_match_proxy_and_port() {
        let bindings = vec![
            ApiBinding {
                tag: "proxy-a".into(),
                listen_port: 10002,
            },
            ApiBinding {
                tag: "proxy-b".into(),
                listen_port: 10003,
            },
        ];

        assert_eq!(find_binding_port(&bindings, "proxy-a"), Some(10002));
        assert_eq!(find_binding_port(&bindings, "missing"), None);
        assert_eq!(
            bindings_to_ports(&bindings),
            vec![("proxy-a".into(), 10002), ("proxy-b".into(), 10003)]
        );
        assert!(binding_or_port_present(&bindings, "proxy-a", 9999));
        assert!(binding_or_port_present(&bindings, "missing", 10003));
        assert!(!binding_or_port_present(&bindings, "missing", 10099));
    }

    #[test]
    fn detects_bind_address_conflicts() {
        assert!(is_bind_address_in_use_error(
            "failed to create inbound: listen tcp 127.0.0.1:10002: bind: address already in use"
        ));
        assert!(!is_bind_address_in_use_error("failed to parse outbound"));
    }
}

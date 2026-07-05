use crate::db::ProxyRow;
use crate::error::AppError;
use crate::parser::ProxyType;
use crate::{AppState, SubscriptionExportCacheEntry};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

const CONTENT_TYPE_CLASH: &str = "application/x-yaml; charset=utf-8";
const FALLBACK_PROXY_GROUP_MEMBER: &str = "DIRECT";

#[derive(Debug, Clone, Copy)]
enum ExportFormat {
    Clash,
}

impl ExportFormat {
    fn cache_name(self) -> &'static str {
        match self {
            ExportFormat::Clash => "clash",
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            ExportFormat::Clash => CONTENT_TYPE_CLASH,
        }
    }
}

#[derive(Debug, Clone)]
enum ExportSelector {
    All,
    Type(String),
}

impl ExportSelector {
    fn db_type(&self) -> Option<&str> {
        match self {
            ExportSelector::All => None,
            ExportSelector::Type(proxy_type) => Some(proxy_type.as_str()),
        }
    }

    fn cache_name(&self) -> &str {
        match self {
            ExportSelector::All => "all",
            ExportSelector::Type(proxy_type) => proxy_type.as_str(),
        }
    }
}

pub async fn export_subscription_default(
    State(state): State<Arc<AppState>>,
    Path((token, selector)): Path<(String, String)>,
) -> Result<Response, AppError> {
    export_subscription(state, token, selector, ExportFormat::Clash).await
}

pub async fn export_subscription_clash(
    State(state): State<Arc<AppState>>,
    Path((token, selector)): Path<(String, String)>,
) -> Result<Response, AppError> {
    export_subscription(state, token, selector, ExportFormat::Clash).await
}

pub fn invalidate_subscription_export_cache(state: &AppState) {
    state.subscription_export_cache.clear();
}

async fn export_subscription(
    state: Arc<AppState>,
    token: String,
    selector: String,
    format: ExportFormat,
) -> Result<Response, AppError> {
    if token != state.config.server.admin_password.as_str() {
        return Err(AppError::Unauthorized("Invalid subscription token".into()));
    }

    let selector = parse_selector(&selector)?;
    let cache_key = format!("{}:{}", format.cache_name(), selector.cache_name());
    let cache_ttl_secs = state.config.subscription.export_cache_secs;
    let now = tokio::time::Instant::now();

    if cache_ttl_secs > 0 {
        if let Some(entry) = state.subscription_export_cache.get(&cache_key) {
            if entry.expires_at > now {
                return Ok(build_response(
                    entry.body.clone(),
                    format,
                    cache_ttl_secs,
                    entry.proxy_count,
                ));
            }
        }
    }

    let rows = state.db.get_valid_export_proxies(selector.db_type())?;
    let body = match format {
        ExportFormat::Clash => build_clash_yaml(&rows)?,
    };
    let proxy_count = rows.len();

    if cache_ttl_secs > 0 {
        state.subscription_export_cache.insert(
            cache_key,
            SubscriptionExportCacheEntry {
                body: body.clone(),
                proxy_count,
                expires_at: now + std::time::Duration::from_secs(cache_ttl_secs),
            },
        );
    }

    Ok(build_response(body, format, cache_ttl_secs, proxy_count))
}

fn parse_selector(value: &str) -> Result<ExportSelector, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized == "all" {
        return Ok(ExportSelector::All);
    }

    let proxy_type = ProxyType::from_str_loose(&normalized)
        .ok_or_else(|| AppError::BadRequest(format!("Unsupported subscription type: {value}")))?;
    Ok(ExportSelector::Type(proxy_type.to_string()))
}

fn build_response(
    body: String,
    format: ExportFormat,
    cache_ttl_secs: u64,
    proxy_count: usize,
) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(format.content_type()),
    );

    let cache_control = if cache_ttl_secs == 0 {
        "no-store".to_string()
    } else {
        format!("private, max-age={cache_ttl_secs}")
    };
    if let Ok(value) = HeaderValue::from_str(&cache_control) {
        headers.insert(header::CACHE_CONTROL, value);
    }
    if let Ok(value) = HeaderValue::from_str(&proxy_count.to_string()) {
        headers.insert("x-proxy-count", value);
    }

    response
}

fn build_clash_yaml(rows: &[ProxyRow]) -> Result<String, AppError> {
    let mut used_names = HashMap::new();
    let mut proxies = Vec::new();
    let mut proxy_names = Vec::new();

    for row in rows {
        let outbound: Value = match serde_json::from_str(&row.config_json) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("Skipping proxy {} during subscription export: {e}", row.id);
                continue;
            }
        };
        let name = unique_proxy_name(row, &mut used_names);
        if let Some(proxy) = singbox_outbound_to_clash(row, &outbound, &name) {
            proxy_names.push(name);
            proxies.push(proxy);
        }
    }

    if proxy_names.is_empty() {
        proxy_names.push(FALLBACK_PROXY_GROUP_MEMBER.to_string());
    }

    let profile = json!({
        "mixed-port": 7890,
        "allow-lan": false,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": proxy_names,
            }
        ],
        "rules": [
            "MATCH,PROXY"
        ]
    });

    serde_yaml::to_string(&profile)
        .map_err(|e| AppError::Internal(format!("Failed to build Clash YAML: {e}")))
}

fn unique_proxy_name(row: &ProxyRow, used_names: &mut HashMap<String, usize>) -> String {
    let base = if row.name.trim().is_empty() {
        format!("{}:{}", row.server, row.port)
    } else {
        row.name.trim().to_string()
    };

    let count = used_names.entry(base.clone()).or_insert(0);
    *count += 1;
    if *count == 1 {
        base
    } else {
        format!("{base} ({})", *count)
    }
}

fn singbox_outbound_to_clash(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    match outbound
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or(row.proxy_type.as_str())
    {
        "vmess" => clash_vmess(row, outbound, name),
        "vless" => clash_vless(row, outbound, name),
        "trojan" => clash_trojan(row, outbound, name),
        "shadowsocks" => clash_shadowsocks(row, outbound, name),
        "hysteria2" => clash_hysteria2(row, outbound, name),
        "socks" => clash_socks(row, outbound, name),
        "http" => clash_http(row, outbound, name),
        other => {
            tracing::warn!("Skipping unsupported subscription export proxy type: {other}");
            None
        }
    }
}

fn clash_vmess(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    let uuid = string_field(outbound, "uuid")?;
    let mut proxy = base_clash_proxy(row, outbound, name, "vmess");
    insert_string(&mut proxy, "uuid", uuid);
    insert_i64(
        &mut proxy,
        "alterId",
        int_field(outbound, "alter_id").unwrap_or(0),
    );
    insert_string(
        &mut proxy,
        "cipher",
        string_field(outbound, "security").unwrap_or("auto"),
    );
    apply_tls(&mut proxy, outbound);
    apply_transport(&mut proxy, outbound);
    Some(Value::Object(proxy))
}

fn clash_vless(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    let uuid = string_field(outbound, "uuid")?;
    let mut proxy = base_clash_proxy(row, outbound, name, "vless");
    insert_string(&mut proxy, "uuid", uuid);
    if let Some(flow) = string_field(outbound, "flow") {
        insert_string(&mut proxy, "flow", flow);
    }
    apply_tls(&mut proxy, outbound);
    apply_vless_reality(&mut proxy, outbound);
    apply_transport(&mut proxy, outbound);
    Some(Value::Object(proxy))
}

fn clash_trojan(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    let password = string_field(outbound, "password")?;
    let mut proxy = base_clash_proxy(row, outbound, name, "trojan");
    insert_string(&mut proxy, "password", password);
    apply_tls(&mut proxy, outbound);
    apply_transport(&mut proxy, outbound);
    Some(Value::Object(proxy))
}

fn clash_shadowsocks(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    let method = string_field(outbound, "method")?;
    let password = string_field(outbound, "password")?;
    let mut proxy = base_clash_proxy(row, outbound, name, "ss");
    insert_string(&mut proxy, "cipher", method);
    insert_string(&mut proxy, "password", password);
    Some(Value::Object(proxy))
}

fn clash_hysteria2(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    let password = string_field(outbound, "password")?;
    let mut proxy = base_clash_proxy(row, outbound, name, "hysteria2");
    insert_string(&mut proxy, "password", password);
    apply_tls(&mut proxy, outbound);

    if let Some(obfs) = outbound.get("obfs").and_then(Value::as_object) {
        if let Some(obfs_type) = obfs.get("type").and_then(Value::as_str) {
            insert_string(&mut proxy, "obfs", obfs_type);
        }
        if let Some(password) = obfs.get("password").and_then(Value::as_str) {
            insert_string(&mut proxy, "obfs-password", password);
        }
    }

    Some(Value::Object(proxy))
}

fn clash_socks(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    let mut proxy = base_clash_proxy(row, outbound, name, "socks5");
    if let Some(username) = string_field(outbound, "username") {
        insert_string(&mut proxy, "username", username);
    }
    if let Some(password) = string_field(outbound, "password") {
        insert_string(&mut proxy, "password", password);
    }
    apply_tls(&mut proxy, outbound);
    Some(Value::Object(proxy))
}

fn clash_http(row: &ProxyRow, outbound: &Value, name: &str) -> Option<Value> {
    let mut proxy = base_clash_proxy(row, outbound, name, "http");
    if let Some(username) = string_field(outbound, "username") {
        insert_string(&mut proxy, "username", username);
    }
    if let Some(password) = string_field(outbound, "password") {
        insert_string(&mut proxy, "password", password);
    }
    apply_tls(&mut proxy, outbound);
    Some(Value::Object(proxy))
}

fn base_clash_proxy(
    row: &ProxyRow,
    outbound: &Value,
    name: &str,
    clash_type: &str,
) -> Map<String, Value> {
    let mut proxy = Map::new();
    insert_string(&mut proxy, "name", name);
    insert_string(&mut proxy, "type", clash_type);
    insert_string(
        &mut proxy,
        "server",
        string_field(outbound, "server").unwrap_or(row.server.as_str()),
    );
    insert_i64(
        &mut proxy,
        "port",
        int_field(outbound, "server_port").unwrap_or(row.port as i64),
    );
    proxy
}

fn apply_tls(proxy: &mut Map<String, Value>, outbound: &Value) {
    let Some(tls) = outbound.get("tls").and_then(Value::as_object) else {
        return;
    };
    if !tls.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
        return;
    }

    proxy.insert("tls".to_string(), Value::Bool(true));
    if let Some(server_name) = tls.get("server_name").and_then(Value::as_str) {
        insert_string(proxy, "servername", server_name);
    }
    if let Some(insecure) = tls.get("insecure").and_then(Value::as_bool) {
        proxy.insert("skip-cert-verify".to_string(), Value::Bool(insecure));
    }
    if let Some(fingerprint) = tls
        .get("utls")
        .and_then(Value::as_object)
        .and_then(|utls| utls.get("fingerprint"))
        .and_then(Value::as_str)
    {
        insert_string(proxy, "client-fingerprint", fingerprint);
    }
}

fn apply_vless_reality(proxy: &mut Map<String, Value>, outbound: &Value) {
    let Some(reality) = outbound
        .get("tls")
        .and_then(Value::as_object)
        .and_then(|tls| tls.get("reality"))
        .and_then(Value::as_object)
    else {
        return;
    };
    if !reality
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return;
    }

    let mut reality_opts = Map::new();
    if let Some(public_key) = reality.get("public_key").and_then(Value::as_str) {
        insert_string(&mut reality_opts, "public-key", public_key);
    }
    if let Some(short_id) = reality.get("short_id").and_then(Value::as_str) {
        insert_string(&mut reality_opts, "short-id", short_id);
    }
    if !reality_opts.is_empty() {
        proxy.insert("reality-opts".to_string(), Value::Object(reality_opts));
    }
}

fn apply_transport(proxy: &mut Map<String, Value>, outbound: &Value) {
    let Some(transport) = outbound.get("transport").and_then(Value::as_object) else {
        return;
    };
    match transport.get("type").and_then(Value::as_str) {
        Some("ws") => {
            insert_string(proxy, "network", "ws");
            let mut opts = Map::new();
            insert_string(
                &mut opts,
                "path",
                transport.get("path").and_then(Value::as_str).unwrap_or("/"),
            );
            if let Some(headers) = transport.get("headers").and_then(Value::as_object) {
                opts.insert("headers".to_string(), Value::Object(headers.clone()));
            }
            proxy.insert("ws-opts".to_string(), Value::Object(opts));
        }
        Some("grpc") => {
            insert_string(proxy, "network", "grpc");
            let mut opts = Map::new();
            insert_string(
                &mut opts,
                "grpc-service-name",
                transport
                    .get("service_name")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            proxy.insert("grpc-opts".to_string(), Value::Object(opts));
        }
        Some("http") => {
            insert_string(proxy, "network", "h2");
            let mut opts = Map::new();
            insert_string(
                &mut opts,
                "path",
                transport.get("path").and_then(Value::as_str).unwrap_or("/"),
            );
            if let Some(host) = transport.get("host") {
                opts.insert("host".to_string(), host.clone());
            }
            proxy.insert("h2-opts".to_string(), Value::Object(opts));
        }
        _ => {}
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn int_field(value: &Value, key: &str) -> Option<i64> {
    value
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_u64().map(|n| n as i64)))
}

fn insert_string(map: &mut Map<String, Value>, key: &str, value: &str) {
    map.insert(key.to_string(), Value::String(value.to_string()));
}

fn insert_i64(map: &mut Map<String, Value>, key: &str, value: i64) {
    map.insert(key.to_string(), Value::Number(value.into()));
}

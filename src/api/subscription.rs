use crate::db::{ProxyRow, Subscription};
use crate::error::AppError;
use crate::parser;
use crate::pool::manager::ProxyStatus;
use crate::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AddSubscriptionRequest {
    pub name: String,
    #[serde(rename = "type", default = "default_sub_type")]
    pub sub_type: String,
    pub url: Option<String>,
    pub content: Option<String>,
    pub refresh_interval_mins: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub refresh_interval_mins: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionDefaultsRequest {
    pub refresh_interval_mins: i32,
}

fn default_sub_type() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Copy)]
pub enum SyncMode {
    Normal,
    Validation,
    QualityCheck,
}

pub struct SyncBindingsResult {
    pub selected_ids: Vec<String>,
}

pub async fn list_subscriptions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let subs = state.db.get_subscriptions()?;
    let default_refresh_interval_mins = state
        .db
        .get_subscription_default_refresh_interval_mins(
            state.config.subscription.auto_refresh_interval_mins,
        )?;
    Ok(Json(json!({
        "subscriptions": subs,
        "default_refresh_interval_mins": default_refresh_interval_mins,
    })))
}

pub async fn add_subscription(
    State(state): State<Arc<AppState>>,
    body: axum::body::Body,
) -> Result<Json<serde_json::Value>, AppError> {
    // Try to parse as JSON first
    let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read body: {e}")))?;

    let req: AddSubscriptionRequest = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

    let refresh_interval_mins = validate_refresh_interval_mins(req.refresh_interval_mins)?;
    if req.url.is_none() && refresh_interval_mins.unwrap_or(0) > 0 {
        return Err(AppError::BadRequest(
            "Auto-refresh requires a subscription URL".into(),
        ));
    }

    // Fetch content from URL or use provided content
    let content = if let Some(ref url) = req.url {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch subscription: {e}")))?;
        resp.text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read response: {e}")))?
    } else if let Some(ref content) = req.content {
        content.clone()
    } else {
        return Err(AppError::BadRequest(
            "Either 'url' or 'content' must be provided".into(),
        ));
    };

    // Parse the content
    let parsed = parser::parse_subscription(&content, &req.sub_type);
    if parsed.is_empty() {
        return Err(AppError::BadRequest(
            "No proxies found in subscription content".into(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let sub_id = uuid::Uuid::new_v4().to_string();

    let subscription = Subscription {
        id: sub_id.clone(),
        name: req.name.clone(),
        sub_type: req.sub_type.clone(),
        url: req.url.clone(),
        content: if req.url.is_some() { None } else { Some(content) },
        proxy_count: parsed.len() as i32,
        refresh_interval_mins,
        last_refresh_at: Some(now.clone()),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    state.db.insert_subscription(&subscription)?;

    // Insert proxies
    let mut proxy_rows = Vec::with_capacity(parsed.len());
    for pc in &parsed {
        let proxy_id = uuid::Uuid::new_v4().to_string();
        proxy_rows.push(ProxyRow {
            id: proxy_id.clone(),
            subscription_id: sub_id.clone(),
            name: pc.name.clone(),
            proxy_type: pc.proxy_type.to_string(),
            server: pc.server.clone(),
            port: pc.port as i32,
            config_json: serde_json::to_string(&pc.singbox_outbound).unwrap_or_default(),
            is_valid: false,
            local_port: None,
            error_count: 0,
            last_error: None,
            last_validated: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            orphaned_at: None,
        });
    }

    state.db.insert_proxies_batch(&proxy_rows)?;

    let added = proxy_rows.len();

    tracing::info!("Added subscription '{}' with {added} proxies", req.name);

    // Assign ports then validate in background (must be sequential, not two separate spawns)
    let state2 = state.clone();
    tokio::spawn(async move {
        tracing::info!("Running initial validation for new proxies...");
        if let Err(e) = crate::pool::validator::validate_all(state2).await {
            tracing::error!("Initial validation failed: {e}");
        }
    });

    Ok(Json(json!({
        "subscription": subscription,
        "proxies_added": added,
    })))
}

pub async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.pool.remove_by_subscription(&id);
    state.db.delete_subscription(&id)?;

    // Sync bindings in background
    let state2 = state.clone();
    tokio::spawn(async move {
        let _ = sync_proxy_bindings(&state2, SyncMode::Normal).await;
    });

    Ok(Json(json!({ "message": "Subscription deleted" })))
}

pub async fn update_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    if req.refresh_interval_mins < 0 {
        return Err(AppError::BadRequest(
            "refresh_interval_mins must be >= 0".into(),
        ));
    }
    if sub.url.is_none() && req.refresh_interval_mins > 0 {
        return Err(AppError::BadRequest(
            "Auto-refresh requires a subscription URL".into(),
        ));
    }

    state
        .db
        .update_subscription_refresh_settings(&id, req.refresh_interval_mins)?;

    Ok(Json(json!({
        "message": "Subscription settings updated",
        "refresh_interval_mins": req.refresh_interval_mins,
    })))
}

pub async fn update_subscription_defaults(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateSubscriptionDefaultsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if req.refresh_interval_mins < 0 {
        return Err(AppError::BadRequest(
            "refresh_interval_mins must be >= 0".into(),
        ));
    }

    state
        .db
        .set_subscription_default_refresh_interval_mins(req.refresh_interval_mins as u64)?;

    Ok(Json(json!({
        "message": "Default subscription refresh settings updated",
        "refresh_interval_mins": req.refresh_interval_mins,
    })))
}

/// Core logic for refreshing a subscription: fetch content, parse, replace proxies.
/// Returns the number of new proxies added, or an error message.
/// Does NOT spawn validation — the caller decides when/how to validate.
///
/// This uses a **smooth replacement** strategy:
/// 1. Fetch & parse first — if it fails, old proxies are untouched.
/// 2. If parse returns 0 proxies, abort (don't wipe the subscription).
/// 3. For proxies whose (server, port, proxy_type) match an existing one,
///    preserve their validation status, error_count, local_port and quality data.
/// 4. Only then handle old proxies that no longer appear in the new list:
///    - explicit Invalid: delete immediately
///    - Valid/Untested: keep as orphaned for fallback or delayed cleanup
pub async fn refresh_subscription_core(state: &Arc<AppState>, sub: &Subscription) -> Result<usize, String> {
    let content = if let Some(ref url) = sub.url {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch: {e}"))?;
        resp.text()
            .await
            .map_err(|e| format!("Failed to read: {e}"))?
    } else if let Some(ref content) = sub.content {
        content.clone()
    } else {
        return Err("No URL or content to refresh".into());
    };

    let parsed = parser::parse_subscription(&content, &sub.sub_type);
    if parsed.is_empty() {
        return Err("Parsed 0 proxies, keeping existing data".into());
    }

    // Collect old proxies for this subscription, keyed by (server, port, proxy_type)
    let old_proxies = state
        .db
        .get_proxies_by_subscription(&sub.id)
        .map_err(|e| format!("Failed to load old proxies: {e}"))?;
    let mut old_map: std::collections::HashMap<(String, u16, String), ProxyRow> = old_proxies
        .into_iter()
        .map(|p| ((p.server.clone(), p.port as u16, p.proxy_type.clone()), p))
        .collect();

    let now = chrono::Utc::now().to_rfc3339();
    let mut total = 0;
    let mut kept_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut new_proxy_rows = Vec::new();

    for pc in &parsed {
        let key = (pc.server.clone(), pc.port, pc.proxy_type.to_string());

        if let Some(old) = old_map.remove(&key) {
            // Same proxy still exists — update config but preserve status
            kept_ids.insert(old.id.clone());

            // Update the outbound config in DB (it may have changed)
            let new_config = serde_json::to_string(&pc.singbox_outbound).unwrap_or_default();
            state.db.update_proxy_config(&old.id, &pc.name, &new_config)
                .map_err(|e| format!("Failed to update proxy config: {e}"))?;

            // Update pool entry's name and outbound (keep status, local_port, etc.)
            state.pool.update_proxy_config(&old.id, &pc.name, pc.singbox_outbound.clone());

            total += 1;
        } else {
            // New proxy — insert fresh
            let proxy_id = uuid::Uuid::new_v4().to_string();
            new_proxy_rows.push(ProxyRow {
                id: proxy_id.clone(),
                subscription_id: sub.id.clone(),
                name: pc.name.clone(),
                proxy_type: pc.proxy_type.to_string(),
                server: pc.server.clone(),
                port: pc.port as i32,
                config_json: serde_json::to_string(&pc.singbox_outbound).unwrap_or_default(),
                is_valid: false,
                local_port: None,
                error_count: 0,
                last_error: None,
                last_validated: None,
                created_at: now.clone(),
                updated_at: now.clone(),
                orphaned_at: None,
            });
            total += 1;
        }
    }

    state
        .db
        .insert_proxies_batch(&new_proxy_rows)
        .map_err(|e| format!("Failed to insert proxies: {e}"))?;

    // Handle old proxies that no longer appear in the new list:
    // - explicit invalid: delete immediately
    // - valid: keep as orphaned fallback
    // - untested: keep as orphaned and let periodic cleanup decide later
    let mut removed_invalid = 0usize;
    let mut orphaned_valid = 0usize;
    let mut orphaned_untested = 0usize;
    for old in old_map.values() {
        if old.is_valid {
            state.db.mark_proxy_orphaned(&old.id, &now).ok();
            orphaned_valid += 1;
        } else if old.last_validated.is_some() {
            state.pool.remove(&old.id);
            state.db.delete_proxy(&old.id).ok();
            removed_invalid += 1;
        } else {
            state.db.mark_proxy_orphaned(&old.id, &now).ok();
            orphaned_untested += 1;
        }
    }

    state
        .db
        .mark_subscription_refreshed(&sub.id, total as i32)
        .map_err(|e| format!("Failed to update proxy count: {e}"))?;

    if removed_invalid > 0 || orphaned_valid > 0 || orphaned_untested > 0 {
        tracing::info!(
            "Refresh '{}': kept {}, new {}, removed_invalid {}, orphaned_valid {}, orphaned_untested {}",
            sub.name,
            kept_ids.len(),
            total - kept_ids.len(),
            removed_invalid,
            orphaned_valid,
            orphaned_untested
        );
    }

    Ok(total)
}

pub async fn refresh_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    let added = refresh_subscription_core(&state, &sub)
        .await
        .map_err(|e| AppError::Internal(e))?;

    // Validate in background
    let state2 = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::pool::validator::validate_all(state2).await {
            tracing::error!("Validation after refresh failed: {e}");
        }
    });

    Ok(Json(json!({
        "message": "Subscription refreshed",
        "proxies_added": added,
    })))
}

/// Sync proxy bindings dynamically without restarting sing-box.
///
/// Port pool total = max_proxies + batch_size.
/// - Normal: keep a smaller prebound hot set ready.
/// - Validation: keep the hot set plus the current untested validation batch.
/// - QualityCheck: keep the hot set plus a temporary batch of stale-quality proxies.
/// Active relay traffic is preserved even if it falls outside the managed hot set.
pub async fn sync_proxy_bindings(state: &Arc<AppState>, mode: SyncMode) -> SyncBindingsResult {
    let max = state.config.singbox.max_proxies;
    let prebound = state
        .config
        .singbox
        .prebound_proxies
        .min(state.config.singbox.max_proxies);
    let batch = state.config.validation.batch_size;
    let current_active = state.pool.get_all();

    // Snapshot ALL current ports before changes (for sync_bindings diff)
    let all_current_ports: Vec<(String, u16)> = current_active
        .iter()
        .filter_map(|p| p.local_port.map(|port| (p.id.clone(), port)))
        .collect();

    let mut selected = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for (row, quality) in state.db.get_hot_proxy_records(prebound).unwrap_or_default() {
        if seen_ids.insert(row.id.clone()) {
            selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
        }
    }
    if matches!(mode, SyncMode::Validation) {
        for (row, quality) in state.db.get_untested_proxy_records(batch).unwrap_or_default() {
            if seen_ids.insert(row.id.clone()) {
                selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
            }
        }
    }
    if matches!(mode, SyncMode::QualityCheck) {
        let stale_before =
            (chrono::Utc::now() - chrono::Duration::hours(crate::quality::checker::STALE_HOURS))
                .to_rfc3339();
        for (row, quality) in state
            .db
            .get_due_quality_proxy_records(
                batch,
                &stale_before,
                crate::quality::checker::MAX_INCOMPLETE_RETRIES,
            )
            .unwrap_or_default()
        {
            if seen_ids.insert(row.id.clone()) {
                selected.push(crate::pool::manager::ProxyPool::from_db_parts(row, quality));
            }
        }
    }

    let mut managed_ids = std::collections::HashSet::new();
    let now = chrono::Utc::now();
    for proxy in selected.iter().filter(|p| p.status == ProxyStatus::Valid).take(prebound) {
        managed_ids.insert(proxy.id.clone());
    }
    match mode {
        SyncMode::Validation => {
            for proxy in selected.iter().filter(|p| p.status == ProxyStatus::Untested) {
                managed_ids.insert(proxy.id.clone());
            }
        }
        SyncMode::QualityCheck => {
            let mut extra = 0usize;
            for proxy in selected.iter().filter(|p| p.status == ProxyStatus::Valid) {
                if extra >= batch {
                    break;
                }
                if crate::quality::checker::needs_quality_check(proxy, &now) {
                    if managed_ids.insert(proxy.id.clone()) {
                        extra += 1;
                    }
                }
            }
        }
        SyncMode::Normal => {}
    }

    let mut desired_ids = managed_ids.clone();
    let selected_id_set: std::collections::HashSet<String> =
        selected.iter().map(|proxy| proxy.id.clone()).collect();
    for proxy in &current_active {
        if proxy.local_port.is_none() {
            continue;
        }
        let Some(usage) = state.binding_usage.get(&proxy.id) else {
            continue;
        };
        if usage.in_flight == 0 {
            continue;
        }
        desired_ids.insert(proxy.id.clone());
        if !selected_id_set.contains(&proxy.id) {
            selected.push(proxy.clone());
        }
    }

    let selected_ids: Vec<String> = selected.iter().map(|p| p.id.clone()).collect();

    let mode_str = match mode {
        SyncMode::Normal => "normal",
        SyncMode::Validation => "validation",
        SyncMode::QualityCheck => "quality-check",
    };
    tracing::info!(
        "Syncing bindings: {} selected, {} desired (mode={}, max={}, prebound={}, batch={})",
        selected.len(),
        desired_ids.len(),
        mode_str,
        max,
        prebound,
        batch,
    );

    let selected_id_set: std::collections::HashSet<&str> =
        selected_ids.iter().map(|id| id.as_str()).collect();
    for p in &current_active {
        if p.local_port.is_some() && !selected_id_set.contains(p.id.as_str()) {
            state.db.update_proxy_local_port_null(&p.id).ok();
        }
    }

    let mut mgr = state.singbox.lock().await;
    let desired: Vec<(String, serde_json::Value)> = selected
        .iter()
        .filter(|p| desired_ids.contains(&p.id))
        .map(|p| (p.id.clone(), p.singbox_outbound.clone()))
        .collect();
    let assignments = mgr.sync_bindings(&desired, &all_current_ports).await;
    drop(mgr);

    // Update pool and DB
    for proxy in &mut selected {
        proxy.local_port = None;
    }
    state.pool.replace_all(selected);
    for (id, port) in &assignments {
        state.pool.set_local_port(id, *port);
        state.db.update_proxy_local_port(id, *port as i32).ok();
    }
    let assigned_ids: std::collections::HashSet<&str> =
        assignments.iter().map(|(id, _)| id.as_str()).collect();
    for id in &selected_ids {
        if !assigned_ids.contains(id.as_str()) {
            state.pool.clear_local_port(id);
            state.db.update_proxy_local_port_null(id).ok();
        }
    }

    let active_ports: Vec<u16> = assignments.iter().map(|(_, port)| *port).collect();
    crate::bindings::reconcile_binding_usage(state, &assignments, &managed_ids);
    crate::api::relay::invalidate_relay_clients(state, &active_ports);

    SyncBindingsResult {
        selected_ids,
    }
}

fn validate_refresh_interval_mins(value: Option<i32>) -> Result<Option<i32>, AppError> {
    match value {
        Some(interval) if interval < 0 => Err(AppError::BadRequest(
            "refresh_interval_mins must be >= 0".into(),
        )),
        other => Ok(other),
    }
}

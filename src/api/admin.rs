use crate::api::fetch::{find_proxy_snapshot, list_query_to_db, proxy_list_item_to_json, ListProxyQuery};
use crate::error::AppError;
use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub async fn list_proxies(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListProxyQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = state.db.list_proxy_page(&list_query_to_db(&query))?;
    let proxy_list: Vec<serde_json::Value> = page.proxies.iter().map(proxy_list_item_to_json).collect();

    Ok(Json(json!({
        "proxies": proxy_list,
        "total": page.total,
        "filtered": page.filtered,
        "page": page.page,
        "page_size": page.page_size,
        "total_pages": page.total_pages,
    })))
}

pub async fn delete_proxy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let proxy = find_proxy_snapshot(&state, &id)?;
    if let Some(proxy) = &proxy {
        crate::bindings::cleanup_proxy_binding(&state, &proxy.id, proxy.local_port).await;
    }

    state.binding_usage.remove(&id);
    state.pool.remove(&id);
    state.db.delete_proxy(&id)?;
    Ok(Json(json!({ "message": "Proxy deleted" })))
}

pub async fn cleanup_proxies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let threshold = state.config.validation.error_threshold;

    // Remove bindings before deleting DB rows so sing-box listeners do not leak.
    let targets: Vec<_> = state
        .pool
        .get_all()
        .into_iter()
        .filter(|proxy| proxy.error_count >= threshold)
        .collect();
    for proxy in &targets {
        crate::bindings::cleanup_proxy_binding(&state, &proxy.id, proxy.local_port).await;
    }

    let count = state.db.cleanup_high_error_proxies(threshold)?;

    // Remove from pool too
    for proxy in &targets {
        state.binding_usage.remove(&proxy.id);
        state.pool.remove(&proxy.id);
    }

    Ok(Json(json!({
        "message": format!("Cleaned up {count} proxies"),
        "removed": count,
    })))
}

pub async fn trigger_validation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    if state.validation_running.load(Ordering::Acquire) {
        return Ok(Json(json!({
            "message": "Validation already running"
        })));
    }

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::pool::validator::validate_all(state_clone).await {
            tracing::error!("Manual validation failed: {e}");
        }
    });

    Ok(Json(json!({
        "message": "Validation started in background"
    })))
}

pub async fn trigger_quality_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    if state.quality_running.load(Ordering::Acquire) {
        return Ok(Json(json!({
            "message": "Quality check already running"
        })));
    }

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::quality::checker::check_all(state_clone).await {
            tracing::error!("Manual quality check failed: {e}");
        }
    });

    Ok(Json(json!({
        "message": "Quality check started in background"
    })))
}

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let stats = state.db.get_stats()?;
    Ok(Json(stats))
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let users = state.db.get_all_users()?;
    let total = users.len();
    Ok(Json(json!({
        "users": users,
        "total": total,
    })))
}

pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.delete_user(&id)?;
    Ok(Json(json!({ "message": "User deleted" })))
}

pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.set_user_banned(&id, true)?;
    Ok(Json(json!({ "message": "User banned" })))
}

pub async fn unban_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.set_user_banned(&id, false)?;
    Ok(Json(json!({ "message": "User unbanned" })))
}

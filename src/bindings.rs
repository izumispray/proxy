use crate::error::AppError;
use crate::pool::manager::PoolProxy;
use crate::AppState;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct BindingUsage {
    pub managed: bool,
    pub in_flight: usize,
    pub last_used: Instant,
}

pub fn reconcile_binding_usage(
    state: &AppState,
    assignments: &[(String, u16)],
    managed_ids: &std::collections::HashSet<String>,
) {
    let assigned_ids: std::collections::HashSet<&str> =
        assignments.iter().map(|(id, _)| id.as_str()).collect();

    state.binding_usage.retain(|id, usage| {
        if assigned_ids.contains(id.as_str()) {
            usage.managed = managed_ids.contains(id);
            true
        } else {
            usage.in_flight > 0
        }
    });

    let now = Instant::now();
    for (id, _) in assignments {
        let managed = managed_ids.contains(id);
        state
            .binding_usage
            .entry(id.clone())
            .and_modify(|usage| usage.managed = managed)
            .or_insert(BindingUsage {
                managed,
                in_flight: 0,
                last_used: now,
            });
    }
}

pub fn seed_managed_bindings(state: &AppState) {
    let now = Instant::now();
    for proxy in state.pool.get_all() {
        if proxy.local_port.is_some() {
            state.binding_usage.insert(
                proxy.id,
                BindingUsage {
                    managed: true,
                    in_flight: 0,
                    last_used: now,
                },
            );
        }
    }
}

pub fn touch_binding(state: &AppState, proxy_id: &str, managed: bool) {
    let now = Instant::now();
    state
        .binding_usage
        .entry(proxy_id.to_string())
        .and_modify(|usage| {
            usage.managed = usage.managed || managed;
            usage.last_used = now;
        })
        .or_insert(BindingUsage {
            managed,
            in_flight: 0,
            last_used: now,
        });
}

pub struct BindingUseGuard {
    state: Arc<AppState>,
    proxy_id: String,
}

impl BindingUseGuard {
    pub fn new(state: Arc<AppState>, proxy_id: String) -> Self {
        let now = Instant::now();
        state
            .binding_usage
            .entry(proxy_id.clone())
            .and_modify(|usage| {
                usage.in_flight += 1;
                usage.last_used = now;
            })
            .or_insert(BindingUsage {
                managed: false,
                in_flight: 1,
                last_used: now,
            });

        Self { state, proxy_id }
    }
}

impl Drop for BindingUseGuard {
    fn drop(&mut self) {
        let now = Instant::now();
        if let Some(mut usage) = self.state.binding_usage.get_mut(&self.proxy_id) {
            usage.in_flight = usage.in_flight.saturating_sub(1);
            usage.last_used = now;
        }
    }
}

pub async fn ensure_binding(
    state: &Arc<AppState>,
    proxy: &PoolProxy,
    managed: bool,
) -> Result<u16, AppError> {
    if state.pool.get(&proxy.id).is_none() {
        state.pool.add(proxy.clone());
    }

    if let Some(port) = state.pool.get(&proxy.id).and_then(|p| p.local_port) {
        touch_binding(state, &proxy.id, managed);
        return Ok(port);
    }

    let mut mgr = state.singbox.lock().await;
    if let Some(port) = state.pool.get(&proxy.id).and_then(|p| p.local_port) {
        drop(mgr);
        touch_binding(state, &proxy.id, managed);
        return Ok(port);
    }

    let port = mgr
        .create_binding(&proxy.id, &proxy.singbox_outbound)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create binding: {e}")))?;
    drop(mgr);

    state.pool.set_local_port(&proxy.id, port);
    state.db.update_proxy_local_port(&proxy.id, port as i32).ok();
    touch_binding(state, &proxy.id, managed);

    Ok(port)
}

pub async fn cleanup_idle_bindings(state: Arc<AppState>) -> Result<usize, String> {
    let idle_after = Duration::from_secs(state.config.singbox.binding_idle_secs);
    let candidates: Vec<(String, u16)> = state
        .pool
        .get_all()
        .into_iter()
        .filter_map(|proxy| {
            let port = proxy.local_port?;
            let usage = state.binding_usage.get(&proxy.id)?;
            if usage.managed || usage.in_flight > 0 || usage.last_used.elapsed() < idle_after {
                return None;
            }
            Some((proxy.id, port))
        })
        .collect();

    if candidates.is_empty() {
        return Ok(0);
    }

    let mut mgr = state.singbox.lock().await;
    let mut removed = Vec::new();

    for (id, port) in candidates {
        let Some(usage) = state.binding_usage.get(&id) else {
            continue;
        };
        let should_remove =
            !usage.managed && usage.in_flight == 0 && usage.last_used.elapsed() >= idle_after;
        drop(usage);
        if !should_remove {
            continue;
        }

        match mgr.remove_binding(&id, port).await {
            Ok(()) => removed.push((id, port)),
            Err(e) => tracing::warn!("Failed to remove idle binding {id}: {e}"),
        }
    }
    drop(mgr);

    for (id, port) in &removed {
        state.pool.clear_local_port(id);
        state.db.update_proxy_local_port_null(id).ok();
        state.relay_clients.remove(port);
        state.binding_usage.remove(id);
    }

    Ok(removed.len())
}

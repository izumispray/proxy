use crate::api::subscription::SyncMode;
use crate::pool::manager::ProxyStatus;
use crate::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

const VALID_ERROR_RECHECK_THRESHOLD: u32 = 1;
const INVALID_RETRY_COOLDOWN_MINS: i64 = 180;

struct RunningGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

fn acquire_running_guard(flag: &AtomicBool) -> Option<RunningGuard<'_>> {
    flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| RunningGuard { flag })
}

pub async fn validate_all(state: Arc<AppState>) -> Result<(), String> {
    let _running = match acquire_running_guard(&state.validation_running) {
        Some(guard) => guard,
        None => {
            tracing::info!("Validation already running, skipping duplicate trigger");
            return Ok(());
        }
    };

    // Serialize validations — wait if another is running, then check for remaining work
    let _lock = state.validation_lock.lock().await;

    let total = state.db.count_all_proxies().unwrap_or(0);
    if total == 0 {
        tracing::info!("No proxies to validate");
        return Ok(());
    }

    // Reset Valid proxies with error_count > 0 back to Untested so they get re-validated.
    // This catches proxies that users reported as failing via relay.
    let recheck = state
        .db
        .get_valid_with_errors_ids(VALID_ERROR_RECHECK_THRESHOLD)
        .unwrap_or_default();
    if !recheck.is_empty() {
        tracing::info!("Re-validating {} proxies with relay errors", recheck.len());
        for id in &recheck {
            state.pool.set_status(id, ProxyStatus::Untested);
            state.db.reset_proxy_to_untested(id).ok();
        }
    }

    let orphaned_cutoff = (chrono::Utc::now()
        - chrono::Duration::hours(state.config.subscription.orphaned_valid_grace_hours as i64))
    .to_rfc3339();
    match state.db.delete_orphaned_non_valid_before(&orphaned_cutoff) {
        Ok(count) if count > 0 => {
            tracing::info!(
                "Deleted {count} orphaned non-valid proxies past grace period (grace={}h)",
                state.config.subscription.orphaned_valid_grace_hours
            );
        }
        _ => {}
    }

    let untested_before_retry = state.db.count_untested_proxies().unwrap_or(0);
    if untested_before_retry == 0 {
        let retry_limit = state.config.validation.retry_invalid_per_run;
        let orphaned_ids = state
            .db
            .get_orphaned_valid_recheck_ids(&orphaned_cutoff, retry_limit)
            .unwrap_or_default();

        if !orphaned_ids.is_empty() {
            tracing::info!(
                "Re-validating {} orphaned valid proxies (grace={}h)",
                orphaned_ids.len(),
                state.config.subscription.orphaned_valid_grace_hours
            );
            for id in &orphaned_ids {
                state.pool.set_status(id, ProxyStatus::Untested);
                state.db.reset_proxy_to_untested(id).ok();
            }
        } else {
            let error_threshold = state.config.validation.error_threshold;
            let retry_before =
                (chrono::Utc::now() - chrono::Duration::minutes(INVALID_RETRY_COOLDOWN_MINS))
                    .to_rfc3339();
            let retry_ids = state
                .db
                .get_invalid_retry_ids(error_threshold, &retry_before, retry_limit)
                .unwrap_or_default();

            if !retry_ids.is_empty() {
                tracing::info!(
                    "Retrying {} previously invalid proxies (threshold={error_threshold}, cooldown={}m)",
                    retry_ids.len(),
                    INVALID_RETRY_COOLDOWN_MINS
                );
                for id in &retry_ids {
                    state.pool.set_status(id, ProxyStatus::Untested);
                    state.db.reset_proxy_to_untested(id).ok();
                }
            }
        }
    }

    let concurrency = state.config.validation.concurrency;
    let timeout_duration = std::time::Duration::from_secs(state.config.validation.timeout_secs);
    let validation_url = state.config.validation.url.clone();
    let max_proxies = state.config.singbox.max_proxies;
    let max_rounds = state.config.validation.max_rounds_per_run;

    let mut round = 0u32;
    let mut total_validated = 0usize;

    loop {
        round += 1;

        // Use validation-mode sorting: Untested get port priority over Valid
        let sync_result =
            crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Validation).await;

        let selected_untested: Vec<_> = sync_result
            .selected_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .filter(|p| p.status == ProxyStatus::Untested)
            .collect();

        let failed_to_bind: Vec<_> = selected_untested
            .iter()
            .filter(|p| p.local_port.is_none())
            .cloned()
            .collect();

        for proxy in &failed_to_bind {
            drop_proxy_after_binding_failure(&state, proxy).await;
        }

        // Collect only the untested proxies selected for this round that actually got bindings.
        let to_validate: Vec<_> = selected_untested
            .iter()
            .filter(|p| p.local_port.is_some())
            .cloned()
            .collect();

        if to_validate.is_empty() {
            let remaining_untested = state.db.count_untested_proxies().unwrap_or(0);

            if selected_untested.is_empty() {
                if remaining_untested > 0 {
                    tracing::warn!(
                        "Validation stopped early: no untested proxies received bindings in round {round}, {} untested remain",
                        remaining_untested
                    );
                }
                break;
            }

            continue;
        }

        tracing::info!(
            "Validation round {round}: checking {} proxies (max_proxies={max_proxies})",
            to_validate.len()
        );

        // Validate this batch
        let round_count = validate_batch(
            &to_validate,
            &validation_url,
            timeout_duration,
            concurrency,
            &state,
        )
        .await;

        total_validated += round_count;

        let valid = state.db.count_valid_proxies().unwrap_or(0);
        let total = state.db.count_all_proxies().unwrap_or(0);
        let untested_remaining = state.db.count_untested_proxies().unwrap_or(0);

        tracing::info!(
            "Round {round}: {round_count} checked, {valid}/{total} valid, {untested_remaining} untested remaining"
        );

        if untested_remaining == 0 {
            break;
        }
        if round as usize >= max_rounds {
            tracing::info!(
                "Validation paused after {round} rounds (limit={max_rounds}), {untested_remaining} untested remain"
            );
            break;
        }
    }

    // Cleanup high-error proxies (once, after all rounds)
    let threshold = state.config.validation.error_threshold;
    let high_error_targets: Vec<_> = state
        .pool
        .get_all()
        .into_iter()
        .filter(|proxy| proxy.error_count >= threshold)
        .collect();
    for proxy in &high_error_targets {
        crate::bindings::cleanup_proxy_binding(&state, &proxy.id, proxy.local_port).await;
    }
    match state.db.cleanup_high_error_proxies(threshold) {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} proxies exceeding error threshold");
            for proxy in &high_error_targets {
                state.binding_usage.remove(&proxy.id);
                state.pool.remove(&proxy.id);
            }
        }
        _ => {}
    }

    // Final assignment: normal mode (Valid gets priority for serving traffic)
    let _ = crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Normal).await;

    let valid = state.db.count_valid_proxies().unwrap_or(0);
    let total = state.db.count_all_proxies().unwrap_or(0);
    tracing::info!(
        "Validation complete: {total_validated} checked in {round} rounds, {valid}/{total} valid"
    );

    Ok(())
}

async fn drop_proxy_after_binding_failure(
    state: &Arc<AppState>,
    proxy: &crate::pool::manager::PoolProxy,
) {
    tracing::warn!(
        "Proxy {} failed to get binding, deleting immediately",
        proxy.name
    );
    crate::bindings::cleanup_proxy_binding(state, &proxy.id, proxy.local_port).await;
    state.binding_usage.remove(&proxy.id);
    state.pool.remove(&proxy.id);
    state.db.delete_proxy(&proxy.id).ok();
}

/// Validate a batch of proxies concurrently, reusing one reqwest::Client per proxy port.
async fn validate_batch(
    proxies: &[crate::pool::manager::PoolProxy],
    validation_url: &str,
    timeout: std::time::Duration,
    concurrency: usize,
    state: &Arc<AppState>,
) -> usize {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(proxies.len());

    for proxy in proxies {
        let local_port = match proxy.local_port {
            Some(p) => p,
            None => continue,
        };

        let sem = semaphore.clone();
        let state = state.clone();
        let url = validation_url.to_string();
        let proxy_id = proxy.id.clone();
        let proxy_name = proxy.name.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let proxy_addr = format!("http://127.0.0.1:{local_port}");
            let result = validate_single(&proxy_addr, &url, timeout).await;

            match result {
                Ok(()) => {
                    state.pool.set_status(&proxy_id, ProxyStatus::Valid);
                    state
                        .db
                        .update_proxy_validation(&proxy_id, true, None)
                        .ok();
                }
                Err(e) => {
                    tracing::debug!("Proxy {proxy_name} failed validation: {e}");
                    state.pool.set_status(&proxy_id, ProxyStatus::Invalid);
                    state
                        .db
                        .update_proxy_validation(&proxy_id, false, Some(&e))
                        .ok();
                    if state.db.delete_proxy_if_orphaned(&proxy_id).unwrap_or(false) {
                        crate::bindings::cleanup_proxy_binding(&state, &proxy_id, Some(local_port))
                            .await;
                        state.binding_usage.remove(&proxy_id);
                        state.pool.remove(&proxy_id);
                    }
                }
            }
        });
        handles.push(handle);
    }

    let mut count = 0;
    for handle in handles {
        if handle.await.is_ok() {
            count += 1;
        }
    }
    count
}

async fn validate_single(
    proxy_addr: &str,
    target_url: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let proxy = reqwest::Proxy::all(proxy_addr).map_err(|e| format!("Proxy config error: {e}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(0) // don't keep idle connections
        .build()
        .map_err(|e| format!("Client build error: {e}"))?;

    let resp = client
        .get(target_url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if resp.status().is_success() || resp.status().is_redirection() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

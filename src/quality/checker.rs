use crate::db::ProxyQuality;
use crate::pool::manager::{PoolProxy, ProxyQualityInfo};
use crate::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;

/// Staleness threshold: re-check quality after 24 hours.
pub(crate) const STALE_HOURS: i64 = 24;
/// Incomplete quality data can be retried at most this many times.
pub(crate) const MAX_INCOMPLETE_RETRIES: u8 = 2;
/// Limit checks per run so quality task won't hold validation resources for too long.
const MAX_QUALITY_CHECKS_PER_RUN: usize = 40;

/// ip-api.com rate limiter: max 40 requests/minute (free tier limit is 45).
struct RateLimiter {
    last_call: Mutex<Instant>,
    min_interval: std::time::Duration,
}

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

impl RateLimiter {
    fn new(calls_per_minute: u32) -> Self {
        RateLimiter {
            last_call: Mutex::new(Instant::now() - std::time::Duration::from_secs(60)),
            min_interval: std::time::Duration::from_millis(60_000 / calls_per_minute as u64),
        }
    }

    async fn wait(&self) {
        let mut last = self.last_call.lock().await;
        let elapsed = last.elapsed();
        if elapsed < self.min_interval {
            tokio::time::sleep(self.min_interval - elapsed).await;
        }
        *last = Instant::now();
    }
}

/// Returns the number of proxies actually checked.
pub async fn check_all(state: Arc<AppState>) -> Result<usize, String> {
    let _running = match acquire_running_guard(&state.quality_running) {
        Some(guard) => guard,
        None => {
            tracing::info!("Quality check already running, skipping duplicate trigger");
            return Ok(0);
        }
    };

    let now = chrono::Utc::now();
    let mut total_checked = 0usize;
    let rate_limiter = Arc::new(RateLimiter::new(40));

    // Hold lock only for short binding-selection work.
    let to_check = {
        let _lock = state.validation_lock.lock().await;
        let stale_before = (now - chrono::Duration::hours(STALE_HOURS)).to_rfc3339();
        let due = state
            .db
            .get_due_quality_proxy_records(
                MAX_QUALITY_CHECKS_PER_RUN,
                &stale_before,
                MAX_INCOMPLETE_RETRIES,
            )
            .map_err(|e| format!("Failed to load quality-check candidates: {e}"))?;

        if due.is_empty() {
            return Ok(0);
        }

        let sync_result = crate::api::subscription::sync_proxy_bindings(
            &state,
            crate::api::subscription::SyncMode::QualityCheck,
        )
        .await;

        sync_result
            .selected_ids
            .iter()
            .filter_map(|id| state.pool.get(id))
            .filter(|p| p.status == crate::pool::manager::ProxyStatus::Valid)
            .filter(|p| p.local_port.is_some())
            .filter(|p| needs_quality_check(p, &now))
            .take(MAX_QUALITY_CHECKS_PER_RUN)
            .collect::<Vec<PoolProxy>>()
    };

    if !to_check.is_empty() {
        tracing::info!(
            "Quality check: checking {} proxies this run (limit={MAX_QUALITY_CHECKS_PER_RUN})",
            to_check.len()
        );
        total_checked += check_batch(&to_check, &state, &rate_limiter).await;
    } else {
        tracing::info!("Quality check: due proxies exist but none received active bindings this round");
    }

    let _lock = state.validation_lock.lock().await;
    let _ = crate::api::subscription::sync_proxy_bindings(
        &state,
        crate::api::subscription::SyncMode::Normal,
    )
    .await;

    if total_checked > 0 {
        tracing::info!("Quality check complete: {total_checked} proxies checked in this run");
    }

    Ok(total_checked)
}

/// Check a batch of proxies concurrently, respecting rate limits.
async fn check_batch(
    proxies: &[PoolProxy],
    state: &Arc<AppState>,
    rate_limiter: &Arc<RateLimiter>,
) -> usize {
    let semaphore = Arc::new(Semaphore::new(state.config.quality.concurrency));
    let mut handles = Vec::new();

    for proxy in proxies.iter().cloned() {
        let sem = semaphore.clone();
        let state = state.clone();
        let rl = rate_limiter.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let local_port = match proxy.local_port {
                Some(p) => p,
                None => return,
            };

            let proxy_addr = format!("http://127.0.0.1:{local_port}");
            match check_single(&proxy_addr, &proxy, &rl).await {
                Ok(result) => {
                    let mut quality = result.quality;
                    let is_incomplete = quality_is_incomplete(&quality);
                    let incomplete_retry_count = if is_incomplete {
                        proxy
                            .quality
                            .as_ref()
                            .map(|q| q.incomplete_retry_count)
                            .unwrap_or(0)
                            .saturating_add(1)
                    } else {
                        0
                    };

                    tracing::info!(
                        "Quality OK: {} | IP={} country={} type={} residential={} google={}({}) chatgpt={}({}) risk={}({})",
                        proxy.name,
                        quality.ip_address.as_deref().unwrap_or("-"),
                        quality.country.as_deref().unwrap_or("-"),
                        quality.ip_type.as_deref().unwrap_or("-"),
                        quality.is_residential,
                        quality.google_accessible,
                        result.google_detail,
                        quality.chatgpt_accessible,
                        result.chatgpt_detail,
                        quality.risk_score,
                        &quality.risk_level,
                    );
                    let mut extra = result.extra_json;
                    if let Some(obj) = extra.as_object_mut() {
                        obj.insert(
                            "incomplete_retry_count".to_string(),
                            serde_json::json!(incomplete_retry_count),
                        );
                    }
                    let db_quality = ProxyQuality {
                        proxy_id: proxy.id.clone(),
                        ip_address: quality.ip_address.clone(),
                        country: quality.country.clone(),
                        ip_type: quality.ip_type.clone(),
                        is_residential: quality.is_residential,
                        chatgpt_accessible: quality.chatgpt_accessible,
                        google_accessible: quality.google_accessible,
                        risk_score: quality.risk_score,
                        risk_level: quality.risk_level.clone(),
                        extra_json: Some(extra.to_string()),
                        checked_at: chrono::Utc::now().to_rfc3339(),
                    };
                    state.db.upsert_quality(&db_quality).ok();
                    quality.incomplete_retry_count = incomplete_retry_count;
                    state.pool.set_quality(&proxy.id, quality);
                }
                Err(e) => {
                    tracing::warn!("Quality check failed for {}: {e}", proxy.name);
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

/// Check if a proxy needs a quality check: no quality data, incomplete data, or stale.
pub(crate) fn needs_quality_check(proxy: &PoolProxy, now: &chrono::DateTime<chrono::Utc>) -> bool {
    match &proxy.quality {
        None => true,
        Some(q) => {
            // Incomplete data → retry
            if quality_is_incomplete(q) {
                if q.incomplete_retry_count >= MAX_INCOMPLETE_RETRIES {
                    return false;
                }
                return true;
            }
            match &q.checked_at {
                None => true,
                Some(checked_at) => {
                    match chrono::DateTime::parse_from_rfc3339(checked_at) {
                        Ok(t) => {
                            let age = *now - t.with_timezone(&chrono::Utc);
                            age.num_hours() >= STALE_HOURS
                        }
                        Err(_) => true, // unparseable → re-check
                    }
                }
            }
        }
    }
}

fn quality_is_incomplete(q: &ProxyQualityInfo) -> bool {
    q.country.is_none() || q.ip_type.is_none() || q.ip_address.is_none() || q.risk_level == "Unknown"
}

/// IP info from ip-api.com (primary source — free, no key, auto-detects caller IP)
struct IpApiResult {
    ip: Option<String>,
    country: Option<String>,
    is_proxy: bool,
    is_hosting: bool,
}

struct EndpointCheck {
    accessible: bool,
    status_code: Option<u16>,
    detail: String,
}

impl EndpointCheck {
    fn ok(status_code: Option<u16>, detail: impl Into<String>) -> Self {
        Self {
            accessible: true,
            status_code,
            detail: detail.into(),
        }
    }

    fn fail(status_code: Option<u16>, detail: impl Into<String>) -> Self {
        Self {
            accessible: false,
            status_code,
            detail: detail.into(),
        }
    }

    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "accessible": self.accessible,
            "status_code": self.status_code,
            "detail": self.detail,
        })
    }
}

struct QualityCheckResult {
    quality: ProxyQualityInfo,
    extra_json: serde_json::Value,
    google_detail: String,
    chatgpt_detail: String,
}

async fn check_single(
    proxy_addr: &str,
    _proxy: &PoolProxy,
    rate_limiter: &RateLimiter,
) -> Result<QualityCheckResult, String> {
    let proxy = reqwest::Proxy::all(proxy_addr).map_err(|e| e.to_string())?;
    // no_proxy() must come BEFORE .proxy() — it clears all proxies and disables
    // env var detection; the subsequent .proxy() then adds our explicit proxy back.
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| e.to_string())?;

    // Rate-limit ip-api.com calls, run other checks in parallel
    let (ipapi_result, ipinfo_result, google_result, chatgpt_result) = tokio::join!(
        rate_limited_ip_api(&client, rate_limiter),
        query_ipinfo(&client),
        check_google(&client),
        check_chatgpt(&client),
    );

    let ip_api_ok = ipapi_result.is_some();
    let ipinfo_ok = ipinfo_result.is_some();

    // Merge IP info: prefer ipinfo.io for org detail, fall back to ip-api.com for IP/country
    let (ip_address, country, ip_type, mut is_residential) = match ipinfo_result {
        Some((ip, country, ip_type, residential)) => (ip, country, ip_type, residential),
        None => {
            // ipinfo.io failed — use ip-api.com as fallback
            let ip = ipapi_result.as_ref().and_then(|r| r.ip.clone());
            let country = ipapi_result.as_ref().and_then(|r| r.country.clone());
            (ip, country, None, false)
        }
    };

    // Risk scoring from ip-api.com
    let (risk_score, risk_level, is_hosting) = match &ipapi_result {
        Some(r) => {
            let (score, level) = match (r.is_proxy, r.is_hosting) {
                (true, true) => (0.9, "Very High"),
                (true, false) => (0.7, "High"),
                (false, true) => (0.5, "Medium"),
                (false, false) => (0.1, "Low"),
            };
            (score, level.to_string(), r.is_hosting)
        }
        None => (0.5, "Unknown".to_string(), false),
    };

    // ip-api.com hosting flag overrides residential detection
    let ip_type = if is_hosting {
        is_residential = false;
        Some("Datacenter".to_string())
    } else {
        ip_type
    };

    Ok(QualityCheckResult {
        quality: ProxyQualityInfo {
            ip_address,
            country,
            ip_type,
            is_residential,
            chatgpt_accessible: chatgpt_result.accessible,
            google_accessible: google_result.accessible,
            risk_score,
            risk_level,
            checked_at: Some(chrono::Utc::now().to_rfc3339()),
            incomplete_retry_count: 0,
        },
        extra_json: serde_json::json!({
            "ip_api_ok": ip_api_ok,
            "ipinfo_ok": ipinfo_ok,
            "google_check": google_result.as_json(),
            "chatgpt_check": chatgpt_result.as_json(),
        }),
        google_detail: google_result.detail,
        chatgpt_detail: chatgpt_result.detail,
    })
}

/// Wraps query_ip_api with rate limiting to stay under free tier limits.
async fn rate_limited_ip_api(
    client: &reqwest::Client,
    rate_limiter: &RateLimiter,
) -> Option<IpApiResult> {
    rate_limiter.wait().await;
    query_ip_api(client).await
}

/// Query ip-api.com — auto-detects caller IP, returns IP/country/proxy/hosting.
/// Retries up to 2 times on failure.
async fn query_ip_api(client: &reqwest::Client) -> Option<IpApiResult> {
    let url = "http://ip-api.com/json?fields=query,countryCode,proxy,hosting,status,message";
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let resp = match client.get(url).send().await {
            Ok(r) if r.status().as_u16() == 429 => {
                tracing::warn!("ip-api.com rate limited (attempt {}), backing off", attempt + 1);
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!("ip-api.com returned status {} (attempt {})", r.status(), attempt + 1);
                continue;
            }
            Err(e) => {
                tracing::warn!("ip-api.com request failed (attempt {}): {e}", attempt + 1);
                continue;
            }
        };
        match resp.json::<serde_json::Value>().await {
            Ok(body) if body["status"].as_str() == Some("success") => {
                return Some(IpApiResult {
                    ip: body["query"].as_str().map(|s| s.to_string()),
                    country: body["countryCode"].as_str().map(|s| s.to_string()),
                    is_proxy: body["proxy"].as_bool().unwrap_or(false),
                    is_hosting: body["hosting"].as_bool().unwrap_or(false),
                });
            }
            Ok(body) => {
                tracing::warn!(
                    "ip-api.com returned non-success: {}",
                    body["message"].as_str().unwrap_or("unknown")
                );
                return None; // API-level failure, don't retry
            }
            Err(e) => {
                tracing::warn!("ip-api.com parse failed (attempt {}): {e}", attempt + 1);
            }
        }
    }
    None
}

/// Query ipinfo.io — richer org/company data for residential detection.
/// Retries up to 2 times on failure.
async fn query_ipinfo(
    client: &reqwest::Client,
) -> Option<(Option<String>, Option<String>, Option<String>, bool)> {
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        let resp = match client.get("https://ipinfo.io/json").send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!("ipinfo.io returned status {} (attempt {})", r.status(), attempt + 1);
                continue;
            }
            Err(e) => {
                tracing::warn!("ipinfo.io request failed (attempt {}): {e}", attempt + 1);
                continue;
            }
        };
        match resp.json::<serde_json::Value>().await {
            Ok(body) => {
                let ip = body["ip"].as_str().map(|s| s.to_string());
                let country = body["country"].as_str().map(|s| s.to_string());
                let org = body["org"].as_str().unwrap_or("");
                let org_lower = org.to_lowercase();

                let company_type = body["company"]["type"].as_str().unwrap_or("");

                let (ip_type, is_residential) = if !company_type.is_empty() {
                    let residential = company_type.eq_ignore_ascii_case("isp");
                    (Some(company_type.to_string()), residential)
                } else {
                    let is_datacenter = org_lower.contains("hosting")
                        || org_lower.contains("cloud")
                        || org_lower.contains("server")
                        || org_lower.contains("data center")
                        || org_lower.contains("datacenter")
                        || org_lower.contains("vps")
                        || org_lower.contains("amazon")
                        || org_lower.contains("google")
                        || org_lower.contains("microsoft")
                        || org_lower.contains("digitalocean")
                        || org_lower.contains("linode")
                        || org_lower.contains("vultr")
                        || org_lower.contains("hetzner")
                        || org_lower.contains("ovh")
                        || org_lower.contains("contabo")
                        || org_lower.contains("alibaba")
                        || org_lower.contains("tencent")
                        || org_lower.contains("oracle");

                    if is_datacenter {
                        (Some("Datacenter".to_string()), false)
                    } else {
                        (Some("ISP".to_string()), true)
                    }
                };

                return Some((ip, country, ip_type, is_residential));
            }
            Err(e) => {
                tracing::warn!("ipinfo.io parse failed (attempt {}): {e}", attempt + 1);
            }
        }
    }
    None
}

async fn check_google(client: &reqwest::Client) -> EndpointCheck {
    match client
        .get("https://www.google.com/generate_204")
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status();
            let code = status.as_u16();
            if code == 204 || status.is_success() {
                EndpointCheck::ok(Some(code), format!("http {code}"))
            } else {
                EndpointCheck::fail(Some(code), format!("http {code}"))
            }
        }
        Err(e) => EndpointCheck::fail(None, shorten_detail(e.to_string())),
    }
}

async fn check_chatgpt(client: &reqwest::Client) -> EndpointCheck {
    match client.get("https://chatgpt.com/").send().await {
        Ok(r) => {
            let status = r.status();
            let code = status.as_u16();
            if status == reqwest::StatusCode::FORBIDDEN {
                return EndpointCheck::fail(Some(code), "http 403");
            }
            if !status.is_success() && !status.is_redirection() {
                return EndpointCheck::fail(Some(code), format!("http {code}"));
            }
            match r.text().await {
                Ok(body) => {
                    if body.contains("unsupported_country") {
                        EndpointCheck::fail(Some(code), "unsupported_country")
                    } else if body.contains("unavailable in your country") {
                        EndpointCheck::fail(Some(code), "unavailable in your country")
                    } else if body.contains("not available") {
                        EndpointCheck::fail(Some(code), "not available")
                    } else {
                        EndpointCheck::ok(Some(code), format!("http {code}"))
                    }
                }
                Err(e) => EndpointCheck::ok(Some(code), format!("body read failed: {}", shorten_detail(e.to_string()))),
            }
        }
        Err(e) => EndpointCheck::fail(None, shorten_detail(e.to_string())),
    }
}

fn shorten_detail(detail: String) -> String {
    const MAX_LEN: usize = 160;
    if detail.chars().count() <= MAX_LEN {
        return detail;
    }
    detail.chars().take(MAX_LEN).collect::<String>() + "..."
}

use postgres::types::ToSql;
use postgres::{Client, Config, NoTls, Row};
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Client>,
}

const SETTING_SUBSCRIPTION_DEFAULT_REFRESH_INTERVAL_MINS: &str =
    "subscription_auto_refresh_interval_mins";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub sub_type: String,
    pub url: Option<String>,
    pub content: Option<String>,
    pub proxy_count: i32,
    pub refresh_interval_mins: Option<i32>,
    pub last_refresh_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Subscription {
    pub fn effective_refresh_interval_mins(
        &self,
        default_refresh_interval_mins: u64,
    ) -> Option<u64> {
        if self.url.is_none() {
            return None;
        }

        match self.refresh_interval_mins {
            Some(interval) if interval > 0 => Some(interval as u64),
            Some(_) => None,
            None if default_refresh_interval_mins > 0 => Some(default_refresh_interval_mins),
            None => None,
        }
    }

    pub fn is_refresh_due(
        &self,
        default_refresh_interval_mins: u64,
        now: &chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(interval_mins) = self.effective_refresh_interval_mins(default_refresh_interval_mins)
        else {
            return false;
        };

        let anchor = self
            .last_refresh_at
            .as_deref()
            .or(Some(self.updated_at.as_str()))
            .or(Some(self.created_at.as_str()))
            .and_then(parse_rfc3339_utc);

        let Some(anchor) = anchor else {
            return true;
        };

        *now >= anchor + chrono::Duration::minutes(interval_mins as i64)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyRow {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub proxy_type: String,
    pub server: String,
    pub port: i32,
    pub config_json: String,
    pub is_valid: bool,
    pub local_port: Option<i32>,
    pub error_count: i32,
    pub last_error: Option<String>,
    pub last_validated: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub orphaned_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyQuality {
    pub proxy_id: String,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub ip_type: Option<String>,
    pub is_residential: bool,
    pub chatgpt_accessible: bool,
    pub google_accessible: bool,
    pub risk_score: f64,
    pub risk_level: String,
    pub extra_json: Option<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub name: Option<String>,
    pub avatar_template: Option<String>,
    pub active: bool,
    pub trust_level: i32,
    pub silenced: bool,
    pub is_banned: bool,
    pub api_key: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct ProxyListQuery {
    pub page: usize,
    pub page_size: usize,
    pub search: Option<String>,
    pub status: Option<String>,
    pub proxy_type: Option<String>,
    pub quality: Option<String>,
    pub sort: Option<String>,
    pub dir: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyListItem {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub proxy_type: String,
    pub server: String,
    pub port: i32,
    pub local_port: Option<i32>,
    pub status: String,
    pub error_count: i32,
    pub quality: Option<ProxyQuality>,
}

#[derive(Debug, Clone)]
pub struct ProxyListPage {
    pub proxies: Vec<ProxyListItem>,
    pub total: usize,
    pub filtered: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
}

impl Database {
    pub fn new(url: &str) -> Result<Self, postgres::Error> {
        let mut config: Config = url.parse()?;
        config.application_name("zenproxy");
        let conn = tokio::task::block_in_place(|| config.connect(NoTls))?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut Client) -> Result<T, postgres::Error>,
    ) -> Result<T, postgres::Error> {
        tokio::task::block_in_place(|| {
            let mut conn = self.conn.lock().unwrap();
            f(&mut conn)
        })
    }

    fn migrate(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.batch_execute(
                "
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    sub_type TEXT NOT NULL,
                    url TEXT,
                    content TEXT,
                    proxy_count INTEGER NOT NULL DEFAULT 0,
                    refresh_interval_mins INTEGER,
                    last_refresh_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS proxies (
                    id TEXT PRIMARY KEY,
                    subscription_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    proxy_type TEXT NOT NULL,
                    server TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    config_json TEXT NOT NULL,
                    is_valid BOOLEAN NOT NULL DEFAULT FALSE,
                    local_port INTEGER,
                    error_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    last_validated TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    orphaned_at TEXT
                );

                ALTER TABLE proxies ADD COLUMN IF NOT EXISTS orphaned_at TEXT;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS refresh_interval_mins INTEGER;
                ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_refresh_at TEXT;

                CREATE TABLE IF NOT EXISTS proxy_quality (
                    proxy_id TEXT PRIMARY KEY,
                    ip_address TEXT,
                    country TEXT,
                    ip_type TEXT,
                    is_residential BOOLEAN NOT NULL DEFAULT FALSE,
                    chatgpt_accessible BOOLEAN NOT NULL DEFAULT FALSE,
                    google_accessible BOOLEAN NOT NULL DEFAULT FALSE,
                    risk_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,
                    risk_level TEXT NOT NULL DEFAULT 'Unknown',
                    extra_json TEXT,
                    checked_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    name TEXT,
                    avatar_template TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    trust_level INTEGER NOT NULL DEFAULT 0,
                    silenced BOOLEAN NOT NULL DEFAULT FALSE,
                    is_banned BOOLEAN NOT NULL DEFAULT FALSE,
                    api_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
                CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
                CREATE INDEX IF NOT EXISTS idx_proxies_subscription_id ON proxies(subscription_id);
                CREATE INDEX IF NOT EXISTS idx_proxies_is_valid ON proxies(is_valid);
                CREATE INDEX IF NOT EXISTS idx_proxies_last_validated ON proxies(last_validated);
                CREATE INDEX IF NOT EXISTS idx_proxies_error_count ON proxies(error_count);
                CREATE INDEX IF NOT EXISTS idx_proxies_proxy_type ON proxies(proxy_type);
                CREATE INDEX IF NOT EXISTS idx_proxies_hot_selection
                    ON proxies(orphaned_at ASC, error_count ASC, last_validated DESC, updated_at DESC)
                    WHERE is_valid = TRUE;
                CREATE INDEX IF NOT EXISTS idx_proxies_untested_selection
                    ON proxies(error_count ASC, created_at DESC)
                    WHERE is_valid = FALSE AND last_validated IS NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_invalid_retry
                    ON proxies(error_count ASC, updated_at DESC)
                    WHERE is_valid = FALSE AND last_validated IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_proxies_orphaned_at ON proxies(orphaned_at);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_country ON proxy_quality(country);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_chatgpt ON proxy_quality(chatgpt_accessible);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_google ON proxy_quality(google_accessible);
                CREATE INDEX IF NOT EXISTS idx_proxy_quality_residential ON proxy_quality(is_residential);
                ",
            )?;
            Ok(())
        })
    }

    pub fn insert_subscription(&self, sub: &Subscription) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO subscriptions (
                    id, name, sub_type, url, content, proxy_count,
                    refresh_interval_mins, last_refresh_at, created_at, updated_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6,
                    $7, $8, $9, $10
                 )",
                &[
                    &sub.id,
                    &sub.name,
                    &sub.sub_type,
                    &sub.url,
                    &sub.content,
                    &sub.proxy_count,
                    &sub.refresh_interval_mins,
                    &sub.last_refresh_at,
                    &sub.created_at,
                    &sub.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_subscriptions(&self) -> Result<Vec<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, name, sub_type, url, content, proxy_count,
                        refresh_interval_mins, last_refresh_at, created_at, updated_at
                 FROM subscriptions ORDER BY created_at DESC",
                &[],
            )?;
            Ok(rows.iter().map(subscription_from_row).collect())
        })
    }

    pub fn get_subscription(&self, id: &str) -> Result<Option<Subscription>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, name, sub_type, url, content, proxy_count,
                        refresh_interval_mins, last_refresh_at, created_at, updated_at
                 FROM subscriptions WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(subscription_from_row))
        })
    }

    pub fn delete_subscription(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies WHERE subscription_id = $1
                 )",
                &[&id],
            )?;
            conn.execute("DELETE FROM proxies WHERE subscription_id = $1", &[&id])?;
            conn.execute("DELETE FROM subscriptions WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn update_subscription_refresh_settings(
        &self,
        sub_id: &str,
        refresh_interval_mins: i32,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE subscriptions
                 SET refresh_interval_mins = $1, updated_at = $2
                 WHERE id = $3",
                &[&refresh_interval_mins, &now, &sub_id],
            )?;
            Ok(())
        })
    }

    pub fn get_subscription_default_refresh_interval_mins(
        &self,
        fallback: u64,
    ) -> Result<u64, postgres::Error> {
        self.with_conn(|conn| {
            let value: Option<String> = conn
                .query_opt(
                    "SELECT value FROM app_settings WHERE key = $1",
                    &[&SETTING_SUBSCRIPTION_DEFAULT_REFRESH_INTERVAL_MINS],
                )?
                .map(|row| row.get(0));

            Ok(value
                .as_deref()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(fallback))
        })
    }

    pub fn set_subscription_default_refresh_interval_mins(
        &self,
        refresh_interval_mins: u64,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let value = refresh_interval_mins.to_string();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO app_settings (key, value, updated_at)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at",
                &[
                    &SETTING_SUBSCRIPTION_DEFAULT_REFRESH_INTERVAL_MINS,
                    &value,
                    &now,
                ],
            )?;
            Ok(())
        })
    }

    pub fn mark_subscription_refreshed(
        &self,
        sub_id: &str,
        count: i32,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE subscriptions
                 SET proxy_count = $1, last_refresh_at = $2, updated_at = $2
                 WHERE id = $3",
                &[&count, &now, &sub_id],
            )?;
            Ok(())
        })
    }

    pub fn insert_proxy(&self, proxy: &ProxyRow) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO proxies (
                    id, subscription_id, name, proxy_type, server, port, config_json,
                    is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at, orphaned_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12, $13, $14, $15
                 )
                 ON CONFLICT (id) DO UPDATE SET
                    subscription_id = EXCLUDED.subscription_id,
                    name = EXCLUDED.name,
                    proxy_type = EXCLUDED.proxy_type,
                    server = EXCLUDED.server,
                    port = EXCLUDED.port,
                    config_json = EXCLUDED.config_json,
                    is_valid = EXCLUDED.is_valid,
                    local_port = EXCLUDED.local_port,
                    error_count = EXCLUDED.error_count,
                    last_error = EXCLUDED.last_error,
                    last_validated = EXCLUDED.last_validated,
                    created_at = EXCLUDED.created_at,
                    updated_at = EXCLUDED.updated_at,
                    orphaned_at = EXCLUDED.orphaned_at",
                &[
                    &proxy.id,
                    &proxy.subscription_id,
                    &proxy.name,
                    &proxy.proxy_type,
                    &proxy.server,
                    &proxy.port,
                    &proxy.config_json,
                    &proxy.is_valid,
                    &proxy.local_port,
                    &proxy.error_count,
                    &proxy.last_error,
                    &proxy.last_validated,
                    &proxy.created_at,
                    &proxy.updated_at,
                    &proxy.orphaned_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn insert_proxies_batch(&self, proxies: &[ProxyRow]) -> Result<(), postgres::Error> {
        if proxies.is_empty() {
            return Ok(());
        }

        self.with_conn(|conn| {
            let mut tx = conn.transaction()?;
            let stmt = tx.prepare(
                "INSERT INTO proxies (
                    id, subscription_id, name, proxy_type, server, port, config_json,
                    is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at, orphaned_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12, $13, $14, $15
                 )
                 ON CONFLICT (id) DO UPDATE SET
                    subscription_id = EXCLUDED.subscription_id,
                    name = EXCLUDED.name,
                    proxy_type = EXCLUDED.proxy_type,
                    server = EXCLUDED.server,
                    port = EXCLUDED.port,
                    config_json = EXCLUDED.config_json,
                    is_valid = EXCLUDED.is_valid,
                    local_port = EXCLUDED.local_port,
                    error_count = EXCLUDED.error_count,
                    last_error = EXCLUDED.last_error,
                    last_validated = EXCLUDED.last_validated,
                    created_at = EXCLUDED.created_at,
                    updated_at = EXCLUDED.updated_at,
                    orphaned_at = EXCLUDED.orphaned_at",
            )?;

            for proxy in proxies {
                tx.execute(
                    &stmt,
                    &[
                        &proxy.id,
                        &proxy.subscription_id,
                        &proxy.name,
                        &proxy.proxy_type,
                        &proxy.server,
                        &proxy.port,
                        &proxy.config_json,
                        &proxy.is_valid,
                        &proxy.local_port,
                        &proxy.error_count,
                        &proxy.last_error,
                        &proxy.last_validated,
                        &proxy.created_at,
                        &proxy.updated_at,
                        &proxy.orphaned_at,
                    ],
                )?;
            }

            tx.commit()?;
            Ok(())
        })
    }

    pub fn get_all_proxies(&self) -> Result<Vec<ProxyRow>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM proxies ORDER BY created_at DESC",
                &[],
            )?;
            Ok(rows.iter().map(proxy_from_row).collect())
        })
    }

    pub fn get_proxy_record(
        &self,
        id: &str,
    ) -> Result<Option<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 WHERE p.id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(proxy_record_from_join_row))
        })
    }

    pub fn get_hot_proxy_records(
        &self,
        limit: usize,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 WHERE p.is_valid = TRUE
                 ORDER BY p.orphaned_at ASC NULLS FIRST, p.error_count ASC, p.last_validated DESC NULLS LAST, p.updated_at DESC
                 LIMIT $1",
                &[&limit],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_random_valid_proxy_records(
        &self,
        filter: &crate::pool::manager::ProxyFilter,
        limit: usize,
        recent_error_before: Option<&str>,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit.max(1) as i64;
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        let where_clause = build_fetch_proxy_where(filter, &mut params, true);
        let order_by_clause =
            build_random_valid_proxy_order_by(&mut params, recent_error_before);
        params.push(Box::new(limit));
        let limit_idx = params.len();

        self.with_conn(|conn| {
            let param_refs: Vec<&(dyn ToSql + Sync)> =
                params.iter().map(|p| &**p as &(dyn ToSql + Sync)).collect();
            let sql = format!(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 {where_clause}
                 ORDER BY {order_by_clause}
                 LIMIT ${limit_idx}"
            );
            let rows = conn.query(&sql, &param_refs)?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_due_quality_proxy_records(
        &self,
        limit: usize,
        stale_before: &str,
        _max_incomplete_retries: u8,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit.max(1) as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 WHERE p.is_valid = TRUE
                   AND (
                        q.proxy_id IS NULL
                        OR q.checked_at <= $1
                        OR (q.country IS NULL OR q.ip_type IS NULL OR q.ip_address IS NULL OR q.risk_level = 'Unknown')
                   )
                 ORDER BY
                    CASE WHEN p.local_port IS NULL THEN 1 ELSE 0 END ASC,
                    q.checked_at ASC NULLS FIRST,
                    p.last_validated DESC NULLS LAST,
                    p.updated_at DESC
                 LIMIT $2",
                &[&stale_before, &limit],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_untested_proxy_records(
        &self,
        limit: usize,
    ) -> Result<Vec<(ProxyRow, Option<ProxyQuality>)>, postgres::Error> {
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.config_json,
                    p.is_valid, p.local_port, p.error_count, p.last_error, p.last_validated,
                    p.created_at, p.updated_at, p.orphaned_at,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 WHERE p.is_valid = FALSE
                   AND p.last_validated IS NULL
                   AND p.orphaned_at IS NULL
                 ORDER BY
                    CASE WHEN p.error_count > 0 THEN 0 ELSE 1 END ASC,
                    p.error_count DESC,
                    p.created_at ASC
                 LIMIT $1",
                &[&limit],
            )?;
            Ok(rows.iter().map(proxy_record_from_join_row).collect())
        })
    }

    pub fn get_valid_with_errors_ids(
        &self,
        min_error_count: u32,
    ) -> Result<Vec<String>, postgres::Error> {
        let min_error_count = min_error_count as i32;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id
                 FROM proxies
                 WHERE is_valid = TRUE AND error_count >= $1
                 ORDER BY error_count DESC, updated_at DESC",
                &[&min_error_count],
            )?;
            Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
        })
    }

    pub fn get_invalid_retry_ids(
        &self,
        max_error_count: u32,
        retry_before: &str,
        limit: usize,
    ) -> Result<Vec<String>, postgres::Error> {
        let max_error_count = max_error_count as i32;
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id
                 FROM proxies
                 WHERE is_valid = FALSE
                   AND last_validated IS NOT NULL
                   AND error_count < $1
                   AND orphaned_at IS NULL
                   AND updated_at <= $2
                 ORDER BY error_count ASC, updated_at ASC
                 LIMIT $3",
                &[&max_error_count, &retry_before, &limit],
            )?;
            Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
        })
    }

    pub fn delete_orphaned_non_valid_before(
        &self,
        cutoff: &str,
    ) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies
                    WHERE is_valid = FALSE
                      AND orphaned_at IS NOT NULL
                      AND orphaned_at <= $1
                 )",
                &[&cutoff],
            )?;
            let count = conn.execute(
                "DELETE FROM proxies
                 WHERE is_valid = FALSE
                   AND orphaned_at IS NOT NULL
                   AND orphaned_at <= $1",
                &[&cutoff],
            )?;
            Ok(count as usize)
        })
    }

    pub fn get_orphaned_valid_recheck_ids(
        &self,
        cutoff: &str,
        limit: usize,
    ) -> Result<Vec<String>, postgres::Error> {
        let limit = limit as i64;
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id
                 FROM proxies
                 WHERE is_valid = TRUE
                   AND orphaned_at IS NOT NULL
                   AND orphaned_at <= $1
                   AND (last_validated IS NULL OR last_validated <= $1)
                 ORDER BY orphaned_at ASC, last_validated ASC NULLS FIRST, updated_at ASC
                 LIMIT $2",
                &[&cutoff, &limit],
            )?;
            Ok(rows.iter().map(|row| row.get::<_, String>(0)).collect())
        })
    }

    pub fn count_all_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn.query_one("SELECT COUNT(*) FROM proxies", &[])?.get(0);
            Ok(count as usize)
        })
    }

    pub fn count_valid_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_one("SELECT COUNT(*) FROM proxies WHERE is_valid = TRUE", &[])?
                .get(0);
            Ok(count as usize)
        })
    }

    pub fn count_untested_proxies(&self) -> Result<usize, postgres::Error> {
        self.with_conn(|conn| {
            let count: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM proxies WHERE is_valid = FALSE AND last_validated IS NULL",
                    &[],
                )?
                .get(0);
            Ok(count as usize)
        })
    }

    pub fn list_proxy_page(
        &self,
        query: &ProxyListQuery,
    ) -> Result<ProxyListPage, postgres::Error> {
        let page_size = query.page_size.clamp(1, 200);
        let page = query.page.max(1);
        let offset = ((page - 1) * page_size) as i64;

        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();
        let where_clause = build_proxy_list_where(query, &mut params);
        let sort_expr = proxy_list_sort_expr(query.sort.as_deref());
        let dir = if matches!(query.dir.as_deref(), Some("desc")) {
            "DESC"
        } else {
            "ASC"
        };

        let count_params = params;
        let filtered = self.with_conn(|conn| {
            let count_refs: Vec<&(dyn ToSql + Sync)> =
                count_params.iter().map(|p| &**p as &(dyn ToSql + Sync)).collect();
            let sql = format!(
                "SELECT COUNT(*)
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 {where_clause}"
            );
            let count: i64 = conn.query_one(&sql, &count_refs)?.get(0);
            Ok(count as usize)
        })?;

        let total = self.count_all_proxies()?;
        let total_pages = if filtered == 0 {
            0
        } else {
            filtered.div_ceil(page_size)
        };

        let mut select_params = count_params;
        select_params.push(Box::new(page_size as i64));
        select_params.push(Box::new(offset));
        let limit_idx = select_params.len() - 1;
        let offset_idx = select_params.len();

        self.with_conn(|conn| {
            let param_refs: Vec<&(dyn ToSql + Sync)> =
                select_params.iter().map(|p| &**p as &(dyn ToSql + Sync)).collect();
            let sql = format!(
                "SELECT
                    p.id, p.subscription_id, p.name, p.proxy_type, p.server, p.port, p.local_port,
                    p.error_count, p.is_valid, p.last_validated,
                    q.proxy_id, q.ip_address, q.country, q.ip_type, q.is_residential,
                    q.chatgpt_accessible, q.google_accessible, q.risk_score, q.risk_level,
                    q.extra_json, q.checked_at
                 FROM proxies p
                 LEFT JOIN proxy_quality q ON q.proxy_id = p.id
                 {where_clause}
                 ORDER BY {sort_expr} {dir}, p.id ASC
                 LIMIT ${limit_idx} OFFSET ${offset_idx}"
            );
            let rows = conn.query(&sql, &param_refs)?;
            let proxies = rows.iter().map(proxy_list_item_from_row).collect();
            Ok(ProxyListPage {
                proxies,
                total,
                filtered,
                page,
                page_size,
                total_pages,
            })
        })
    }

    pub fn get_proxies_by_subscription(
        &self,
        sub_id: &str,
    ) -> Result<Vec<ProxyRow>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                        is_valid, local_port, error_count, last_error, last_validated,
                        created_at, updated_at, orphaned_at
                 FROM proxies WHERE subscription_id = $1 ORDER BY name",
                &[&sub_id],
            )?;
            Ok(rows.iter().map(proxy_from_row).collect())
        })
    }

    pub fn delete_proxy(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM proxy_quality WHERE proxy_id = $1", &[&id])?;
            conn.execute("DELETE FROM proxies WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn delete_proxies_by_subscription(&self, sub_id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies WHERE subscription_id = $1
                 )",
                &[&sub_id],
            )?;
            conn.execute("DELETE FROM proxies WHERE subscription_id = $1", &[&sub_id])?;
            Ok(())
        })
    }

    pub fn update_proxy_validation(
        &self,
        id: &str,
        is_valid: bool,
        error: Option<&str>,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            if is_valid {
                conn.execute(
                    "UPDATE proxies
                     SET is_valid = TRUE, error_count = 0, last_error = NULL, last_validated = $1, updated_at = $1
                     WHERE id = $2",
                    &[&now, &id],
                )?;
            } else {
                let err = error.map(|s| s.to_string());
                conn.execute(
                    "UPDATE proxies
                     SET is_valid = FALSE, error_count = error_count + 1, last_error = $1, last_validated = $2, updated_at = $2
                     WHERE id = $3",
                    &[&err, &now, &id],
                )?;
            }
            Ok(())
        })
    }

    pub fn mark_proxy_relay_failed(
        &self,
        id: &str,
        error: &str,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        let err = error.to_string();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET is_valid = FALSE,
                     error_count = error_count + 1,
                     last_error = $1,
                     last_validated = NULL,
                     local_port = NULL,
                     updated_at = $2
                 WHERE id = $3",
                &[&err, &now, &id],
            )?;
            Ok(())
        })
    }

    pub fn reset_proxy_to_untested(&self, id: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET is_valid = FALSE, last_error = NULL, last_validated = NULL, local_port = NULL, updated_at = $1
                 WHERE id = $2",
                &[&now, &id],
            )?;
            Ok(())
        })
    }

    pub fn update_proxy_local_port(&self, id: &str, local_port: i32) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies SET local_port = $1 WHERE id = $2",
                &[&local_port, &id],
            )?;
            Ok(())
        })
    }

    pub fn increment_proxy_error_count(&self, id: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies SET error_count = error_count + 1, updated_at = $1 WHERE id = $2",
                &[&now, &id],
            )?;
            Ok(())
        })
    }

    pub fn update_proxy_config(
        &self,
        id: &str,
        name: &str,
        config_json: &str,
    ) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET name = $1, config_json = $2, orphaned_at = NULL, updated_at = $3
                 WHERE id = $4",
                &[&name, &config_json, &now, &id],
            )?;
            Ok(())
        })
    }

    pub fn mark_proxy_orphaned(&self, id: &str, orphaned_at: &str) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies
                 SET orphaned_at = COALESCE(orphaned_at, $1), updated_at = $2
                 WHERE id = $3",
                &[&orphaned_at, &now, &id],
            )?;
            Ok(())
        })
    }

    pub fn delete_proxy_if_orphaned(&self, id: &str) -> Result<bool, postgres::Error> {
        self.with_conn(|conn| {
            let orphaned = conn
                .query_opt("SELECT orphaned_at FROM proxies WHERE id = $1", &[&id])?
                .and_then(|row| row.get::<_, Option<String>>(0))
                .is_some();

            if !orphaned {
                return Ok(false);
            }

            conn.execute("DELETE FROM proxy_quality WHERE proxy_id = $1", &[&id])?;
            conn.execute("DELETE FROM proxies WHERE id = $1", &[&id])?;
            Ok(true)
        })
    }

    pub fn update_proxy_local_port_null(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("UPDATE proxies SET local_port = NULL WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn clear_all_proxy_local_ports(&self) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE proxies SET local_port = NULL WHERE local_port IS NOT NULL",
                &[],
            )?;
            Ok(())
        })
    }

    pub fn cleanup_high_error_proxies(&self, threshold: u32) -> Result<usize, postgres::Error> {
        let threshold = threshold as i32;
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM proxy_quality WHERE proxy_id IN (
                    SELECT id FROM proxies WHERE error_count >= $1
                 )",
                &[&threshold],
            )?;
            let count = conn.execute("DELETE FROM proxies WHERE error_count >= $1", &[&threshold])?;
            Ok(count as usize)
        })
    }

    pub fn upsert_quality(&self, q: &ProxyQuality) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO proxy_quality (
                    proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible,
                    google_accessible, risk_score, risk_level, extra_json, checked_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6,
                    $7, $8, $9, $10, $11
                 )
                 ON CONFLICT (proxy_id) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    country = EXCLUDED.country,
                    ip_type = EXCLUDED.ip_type,
                    is_residential = EXCLUDED.is_residential,
                    chatgpt_accessible = EXCLUDED.chatgpt_accessible,
                    google_accessible = EXCLUDED.google_accessible,
                    risk_score = EXCLUDED.risk_score,
                    risk_level = EXCLUDED.risk_level,
                    extra_json = EXCLUDED.extra_json,
                    checked_at = EXCLUDED.checked_at",
                &[
                    &q.proxy_id,
                    &q.ip_address,
                    &q.country,
                    &q.ip_type,
                    &q.is_residential,
                    &q.chatgpt_accessible,
                    &q.google_accessible,
                    &q.risk_score,
                    &q.risk_level,
                    &q.extra_json,
                    &q.checked_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_quality(&self, proxy_id: &str) -> Result<Option<ProxyQuality>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT proxy_id, ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score, risk_level,
                        extra_json, checked_at
                 FROM proxy_quality WHERE proxy_id = $1",
                &[&proxy_id],
            )?;
            Ok(row.as_ref().map(quality_from_row))
        })
    }

    pub fn get_all_qualities(&self) -> Result<Vec<ProxyQuality>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT proxy_id, ip_address, country, ip_type, is_residential,
                        chatgpt_accessible, google_accessible, risk_score, risk_level,
                        extra_json, checked_at
                 FROM proxy_quality",
                &[],
            )?;
            Ok(rows.iter().map(quality_from_row).collect())
        })
    }

    pub fn get_stats(&self) -> Result<serde_json::Value, postgres::Error> {
        self.with_conn(|conn| {
            let total: i64 = conn.query_one("SELECT COUNT(*) FROM proxies", &[])?.get(0);
            let valid: i64 = conn
                .query_one("SELECT COUNT(*) FROM proxies WHERE is_valid = TRUE", &[])?
                .get(0);
            let untested: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM proxies WHERE is_valid = FALSE AND last_validated IS NULL",
                    &[],
                )?
                .get(0);
            let invalid: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM proxies WHERE is_valid = FALSE AND last_validated IS NOT NULL",
                    &[],
                )?
                .get(0);
            let subs: i64 = conn
                .query_one("SELECT COUNT(*) FROM subscriptions", &[])?
                .get(0);
            let quality_checked: i64 = conn
                .query_one("SELECT COUNT(*) FROM proxy_quality", &[])?
                .get(0);
            let chatgpt_accessible: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM proxy_quality WHERE chatgpt_accessible = TRUE",
                    &[],
                )?
                .get(0);
            let google_accessible: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM proxy_quality WHERE google_accessible = TRUE",
                    &[],
                )?
                .get(0);
            let residential: i64 = conn
                .query_one(
                    "SELECT COUNT(*) FROM proxy_quality WHERE is_residential = TRUE",
                    &[],
                )?
                .get(0);

            let by_type_rows = conn.query(
                "SELECT proxy_type, COUNT(*) FROM proxies GROUP BY proxy_type",
                &[],
            )?;
            let by_country_rows = conn.query(
                "SELECT country, COUNT(*) FROM proxy_quality
                 WHERE country IS NOT NULL
                 GROUP BY country
                 ORDER BY COUNT(*) DESC",
                &[],
            )?;

            let by_type = by_type_rows
                .iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
                .collect::<std::collections::HashMap<_, _>>();
            let by_country = by_country_rows
                .iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
                .collect::<std::collections::HashMap<_, _>>();

            Ok(serde_json::json!({
                "total_proxies": total,
                "valid_proxies": valid,
                "untested_proxies": untested,
                "invalid_proxies": invalid,
                "subscriptions": subs,
                "quality_checked": quality_checked,
                "chatgpt_accessible": chatgpt_accessible,
                "google_accessible": google_accessible,
                "residential": residential,
                "by_type": by_type,
                "by_country": by_country,
            }))
        })
    }

    pub fn upsert_user(&self, user: &User) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO users (
                    id, username, name, avatar_template, active, trust_level, silenced,
                    is_banned, api_key, created_at, updated_at
                 ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11
                 )
                 ON CONFLICT (id) DO UPDATE SET
                    username = EXCLUDED.username,
                    name = EXCLUDED.name,
                    avatar_template = EXCLUDED.avatar_template,
                    active = EXCLUDED.active,
                    trust_level = EXCLUDED.trust_level,
                    silenced = EXCLUDED.silenced,
                    updated_at = EXCLUDED.updated_at",
                &[
                    &user.id,
                    &user.username,
                    &user.name,
                    &user.avatar_template,
                    &user.active,
                    &user.trust_level,
                    &user.silenced,
                    &user.is_banned,
                    &user.api_key,
                    &user.created_at,
                    &user.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn get_user_by_id(&self, id: &str) -> Result<Option<User>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                        is_banned, api_key, created_at, updated_at
                 FROM users WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(user_from_row))
        })
    }

    pub fn get_user_by_api_key(&self, api_key: &str) -> Result<Option<User>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                        is_banned, api_key, created_at, updated_at
                 FROM users WHERE api_key = $1",
                &[&api_key],
            )?;
            Ok(row.as_ref().map(user_from_row))
        })
    }

    pub fn get_all_users(&self) -> Result<Vec<User>, postgres::Error> {
        self.with_conn(|conn| {
            let rows = conn.query(
                "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                        is_banned, api_key, created_at, updated_at
                 FROM users ORDER BY created_at DESC",
                &[],
            )?;
            Ok(rows.iter().map(user_from_row).collect())
        })
    }

    pub fn delete_user(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE user_id = $1", &[&id])?;
            conn.execute("DELETE FROM users WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn set_user_banned(&self, id: &str, banned: bool) -> Result<(), postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE users SET is_banned = $1, updated_at = $2 WHERE id = $3",
                &[&banned, &now, &id],
            )?;
            if banned {
                conn.execute("DELETE FROM sessions WHERE user_id = $1", &[&id])?;
            }
            Ok(())
        })
    }

    pub fn regenerate_api_key(&self, user_id: &str) -> Result<String, postgres::Error> {
        let new_key = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE users SET api_key = $1, updated_at = $2 WHERE id = $3",
                &[&new_key, &now, &user_id],
            )?;
            Ok(new_key)
        })
    }

    pub fn create_session(&self, user_id: &str) -> Result<Session, postgres::Error> {
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::days(7);
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        };
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sessions (id, user_id, created_at, expires_at)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &session.id,
                    &session.user_id,
                    &session.created_at,
                    &session.expires_at,
                ],
            )?;
            Ok(session)
        })
    }

    pub fn get_session(&self, id: &str) -> Result<Option<Session>, postgres::Error> {
        self.with_conn(|conn| {
            let row = conn.query_opt(
                "SELECT id, user_id, created_at, expires_at FROM sessions WHERE id = $1",
                &[&id],
            )?;
            Ok(row.as_ref().map(session_from_row))
        })
    }

    pub fn delete_session(&self, id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE id = $1", &[&id])?;
            Ok(())
        })
    }

    pub fn delete_user_sessions(&self, user_id: &str) -> Result<(), postgres::Error> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE user_id = $1", &[&user_id])?;
            Ok(())
        })
    }

    pub fn cleanup_expired_sessions(&self) -> Result<usize, postgres::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        self.with_conn(|conn| {
            let count = conn.execute("DELETE FROM sessions WHERE expires_at < $1", &[&now])?;
            Ok(count as usize)
        })
    }
}

fn subscription_from_row(row: &Row) -> Subscription {
    Subscription {
        id: row.get(0),
        name: row.get(1),
        sub_type: row.get(2),
        url: row.get(3),
        content: row.get(4),
        proxy_count: row.get(5),
        refresh_interval_mins: row.get(6),
        last_refresh_at: row.get(7),
        created_at: row.get(8),
        updated_at: row.get(9),
    }
}

fn proxy_from_row(row: &Row) -> ProxyRow {
    ProxyRow {
        id: row.get(0),
        subscription_id: row.get(1),
        name: row.get(2),
        proxy_type: row.get(3),
        server: row.get(4),
        port: row.get(5),
        config_json: row.get(6),
        is_valid: row.get(7),
        local_port: row.get(8),
        error_count: row.get(9),
        last_error: row.get(10),
        last_validated: row.get(11),
        created_at: row.get(12),
        updated_at: row.get(13),
        orphaned_at: row.get(14),
    }
}

fn proxy_from_join_row(row: &Row) -> ProxyRow {
    ProxyRow {
        id: row.get(0),
        subscription_id: row.get(1),
        name: row.get(2),
        proxy_type: row.get(3),
        server: row.get(4),
        port: row.get(5),
        config_json: row.get(6),
        is_valid: row.get(7),
        local_port: row.get(8),
        error_count: row.get(9),
        last_error: row.get(10),
        last_validated: row.get(11),
        created_at: row.get(12),
        updated_at: row.get(13),
        orphaned_at: row.get(14),
    }
}

fn quality_from_join_row(row: &Row, start: usize) -> Option<ProxyQuality> {
    let proxy_id: Option<String> = row.get(start);
    proxy_id.map(|proxy_id| ProxyQuality {
        proxy_id,
        ip_address: row.get(start + 1),
        country: row.get(start + 2),
        ip_type: row.get(start + 3),
        is_residential: row.get(start + 4),
        chatgpt_accessible: row.get(start + 5),
        google_accessible: row.get(start + 6),
        risk_score: row.get(start + 7),
        risk_level: row.get(start + 8),
        extra_json: row.get(start + 9),
        checked_at: row.get(start + 10),
    })
}

fn proxy_record_from_join_row(row: &Row) -> (ProxyRow, Option<ProxyQuality>) {
    (proxy_from_join_row(row), quality_from_join_row(row, 15))
}

fn quality_from_row(row: &Row) -> ProxyQuality {
    ProxyQuality {
        proxy_id: row.get(0),
        ip_address: row.get(1),
        country: row.get(2),
        ip_type: row.get(3),
        is_residential: row.get(4),
        chatgpt_accessible: row.get(5),
        google_accessible: row.get(6),
        risk_score: row.get(7),
        risk_level: row.get(8),
        extra_json: row.get(9),
        checked_at: row.get(10),
    }
}

fn user_from_row(row: &Row) -> User {
    User {
        id: row.get(0),
        username: row.get(1),
        name: row.get(2),
        avatar_template: row.get(3),
        active: row.get(4),
        trust_level: row.get(5),
        silenced: row.get(6),
        is_banned: row.get(7),
        api_key: row.get(8),
        created_at: row.get(9),
        updated_at: row.get(10),
    }
}

fn session_from_row(row: &Row) -> Session {
    Session {
        id: row.get(0),
        user_id: row.get(1),
        created_at: row.get(2),
        expires_at: row.get(3),
    }
}

fn proxy_list_item_from_row(row: &Row) -> ProxyListItem {
    let is_valid: bool = row.get(8);
    let last_validated: Option<String> = row.get(9);
    let quality = quality_from_join_row(row, 10);
    let status = if is_valid {
        "valid"
    } else if last_validated.is_some() {
        "invalid"
    } else {
        "untested"
    };

    ProxyListItem {
        id: row.get(0),
        subscription_id: row.get(1),
        name: row.get(2),
        proxy_type: row.get(3),
        server: row.get(4),
        port: row.get(5),
        local_port: row.get(6),
        status: status.to_string(),
        error_count: row.get(7),
        quality,
    }
}

fn build_proxy_list_where(
    query: &ProxyListQuery,
    params: &mut Vec<Box<dyn ToSql + Sync>>,
) -> String {
    let mut conditions = Vec::new();

    if let Some(search) = query.search.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        params.push(Box::new(format!("%{search}%")));
        let idx = params.len();
        conditions.push(format!(
            "(p.name ILIKE ${idx} OR p.server ILIKE ${idx} OR COALESCE(q.ip_address, '') ILIKE ${idx})"
        ));
    }

    if let Some(status) = query.status.as_deref() {
        match status {
            "valid" => conditions.push("p.is_valid = TRUE".to_string()),
            "invalid" => conditions.push(
                "p.is_valid = FALSE AND p.last_validated IS NOT NULL".to_string(),
            ),
            "untested" => conditions.push(
                "p.is_valid = FALSE AND p.last_validated IS NULL".to_string(),
            ),
            _ => {}
        }
    }

    if let Some(proxy_type) = query
        .proxy_type
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(proxy_type.to_string()));
        let idx = params.len();
        conditions.push(format!("p.proxy_type = ${idx}"));
    }

    if let Some(quality) = query.quality.as_deref() {
        match quality {
            "chatgpt" => conditions.push("q.chatgpt_accessible = TRUE".to_string()),
            "google" => conditions.push("q.google_accessible = TRUE".to_string()),
            "residential" => conditions.push("q.is_residential = TRUE".to_string()),
            "unchecked" => conditions.push("q.proxy_id IS NULL".to_string()),
            _ => {}
        }
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn build_fetch_proxy_where(
    filter: &crate::pool::manager::ProxyFilter,
    params: &mut Vec<Box<dyn ToSql + Sync>>,
    only_valid: bool,
) -> String {
    let mut conditions = Vec::new();

    if only_valid {
        conditions.push("p.is_valid = TRUE".to_string());
    }

    if let Some(proxy_type) = filter
        .proxy_type
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(proxy_type.to_string()));
        let idx = params.len();
        conditions.push(format!("p.proxy_type = ${idx}"));
    }

    if filter.chatgpt {
        conditions.push("q.chatgpt_accessible = TRUE".to_string());
    }

    if filter.google {
        conditions.push("q.google_accessible = TRUE".to_string());
    }

    if filter.residential {
        conditions.push("q.is_residential = TRUE".to_string());
    }

    if let Some(max_risk) = filter.risk_max {
        params.push(Box::new(max_risk));
        let idx = params.len();
        conditions.push(format!("q.risk_score <= ${idx}"));
    }

    if let Some(country) = filter
        .country
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        params.push(Box::new(country.to_string()));
        let idx = params.len();
        conditions.push(format!("LOWER(q.country) = LOWER(${idx})"));
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn build_random_valid_proxy_order_by(
    params: &mut Vec<Box<dyn ToSql + Sync>>,
    recent_error_before: Option<&str>,
) -> String {
    if let Some(cutoff) = recent_error_before {
        params.push(Box::new(cutoff.to_string()));
        let idx = params.len();
        format!(
            "CASE \
                WHEN p.error_count = 0 THEN 0 \
                WHEN p.updated_at <= ${idx} THEN 1 \
                ELSE 2 \
             END ASC, p.error_count ASC, RANDOM()"
        )
    } else {
        "p.error_count ASC, RANDOM()".to_string()
    }
}

fn parse_rfc3339_utc(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn proxy_list_sort_expr(sort: Option<&str>) -> &'static str {
    match sort {
        Some("type") => "p.proxy_type",
        Some("server") => "p.server",
        Some("status") | Some("is_valid") => {
            "CASE WHEN p.is_valid THEN 0 WHEN p.last_validated IS NULL THEN 1 ELSE 2 END"
        }
        Some("error_count") => "p.error_count",
        Some("country") => "COALESCE(q.country, 'ZZZ')",
        Some("risk") => "COALESCE(q.risk_score, 2.0)",
        _ => "p.name",
    }
}

#[cfg(test)]
mod tests {
    use super::{build_fetch_proxy_where, build_random_valid_proxy_order_by};
    use crate::pool::manager::ProxyFilter;
    use postgres::types::ToSql;

    #[test]
    fn build_fetch_proxy_where_does_not_exclude_recent_error_proxies() {
        let filter = ProxyFilter::default();
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let clause = build_fetch_proxy_where(&filter, &mut params, true);

        assert_eq!(clause, "WHERE p.is_valid = TRUE");
        assert!(params.is_empty());
    }

    #[test]
    fn build_random_valid_proxy_order_by_deprioritizes_recent_failures_without_dropping_them() {
        let mut params: Vec<Box<dyn ToSql + Sync>> = Vec::new();

        let clause = build_random_valid_proxy_order_by(
            &mut params,
            Some("2026-03-26T00:00:00+00:00"),
        );

        assert!(clause.contains("WHEN p.error_count = 0 THEN 0"));
        assert!(clause.contains("WHEN p.updated_at <= $1 THEN 1"));
        assert!(clause.contains("ELSE 2"));
        assert!(clause.contains("RANDOM()"));
        assert_eq!(params.len(), 1);
    }
}

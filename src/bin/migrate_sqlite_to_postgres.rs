use postgres::{Client, NoTls, Transaction};
use rusqlite::{Connection, OpenFlags};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse()?;
    let db_name = validate_db_name(&args.db_name)?;

    let mut admin = Client::connect(&args.admin_url, NoTls)?;
    ensure_database_exists(&mut admin, db_name)?;

    let target_url = with_database_name(&args.admin_url, db_name)?;
    let mut pg = Client::connect(&target_url, NoTls)?;
    init_schema(&mut pg)?;

    let existing: i64 = pg.query_one("SELECT COUNT(*) FROM subscriptions", &[])?.get(0);
    if existing > 0 {
        return Err(format!("target database '{db_name}' is not empty").into());
    }

    let sqlite = Connection::open_with_flags(&args.sqlite_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut tx = pg.transaction()?;
    migrate_subscriptions(&sqlite, &mut tx)?;
    let repaired = migrate_proxies(&sqlite, &mut tx)?;
    migrate_proxy_quality(&sqlite, &mut tx)?;
    migrate_users(&sqlite, &mut tx)?;
    migrate_sessions(&sqlite, &mut tx)?;
    tx.commit()?;

    println!("migration complete");
    println!("target database: {db_name}");
    println!("target url: {target_url}");
    println!("repaired proxies reset from 'binding creation failed': {repaired}");

    Ok(())
}

struct Args {
    admin_url: String,
    db_name: String,
    sqlite_path: String,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut admin_url = None;
        let mut db_name = String::from("zenproxy");
        let mut sqlite_path = String::from("data/zenproxy.db");

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--admin-url" => admin_url = args.next(),
                "--db-name" => {
                    db_name = args
                        .next()
                        .ok_or("--db-name requires a value")?;
                }
                "--sqlite-path" => {
                    sqlite_path = args
                        .next()
                        .ok_or("--sqlite-path requires a value")?;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }

        let admin_url = admin_url.ok_or("--admin-url is required")?;

        Ok(Self {
            admin_url,
            db_name,
            sqlite_path,
        })
    }
}

fn print_usage() {
    eprintln!(
        "Usage: migrate_sqlite_to_postgres --admin-url <postgresql://.../postgres> [--db-name zenproxy] [--sqlite-path data/zenproxy.db]"
    );
}

fn validate_db_name(db_name: &str) -> Result<&str, Box<dyn Error>> {
    if db_name.is_empty() {
        return Err("database name cannot be empty".into());
    }
    if db_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Ok(db_name)
    } else {
        Err("database name may only contain letters, numbers, and underscores".into())
    }
}

fn with_database_name(admin_url: &str, db_name: &str) -> Result<String, Box<dyn Error>> {
    let mut url = url::Url::parse(admin_url)?;
    url.set_path(&format!("/{db_name}"));
    Ok(url.to_string())
}

fn ensure_database_exists(admin: &mut Client, db_name: &str) -> Result<(), Box<dyn Error>> {
    let exists = admin
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&db_name])?
        .is_some();
    if !exists {
        admin.batch_execute(&format!("CREATE DATABASE \"{db_name}\""))?;
    }
    Ok(())
}

fn init_schema(pg: &mut Client) -> Result<(), Box<dyn Error>> {
    pg.batch_execute(
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
            updated_at TEXT NOT NULL
        );

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
        CREATE INDEX IF NOT EXISTS idx_proxy_quality_country ON proxy_quality(country);
        ",
    )?;
    Ok(())
}

fn migrate_subscriptions(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO subscriptions (
            id, name, sub_type, url, content, proxy_count,
            refresh_interval_mins, last_refresh_at, created_at, updated_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, name, sub_type, url, content, proxy_count, created_at, updated_at
         FROM subscriptions ORDER BY created_at ASC",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, i32>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;

    for row in rows {
        let (id, name, sub_type, url, content, proxy_count, created_at, updated_at) = row?;
        let refresh_interval_mins: Option<i32> = None;
        let last_refresh_at = Some(updated_at.clone());
        tx.execute(
            &stmt,
            &[
                &id,
                &name,
                &sub_type,
                &url,
                &content,
                &proxy_count,
                &refresh_interval_mins,
                &last_refresh_at,
                &created_at,
                &updated_at,
            ],
        )?;
    }

    Ok(())
}

fn migrate_proxies(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<usize, Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO proxies (
            id, subscription_id, name, proxy_type, server, port, config_json,
            is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13, $14
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, subscription_id, name, proxy_type, server, port, config_json,
                is_valid, local_port, error_count, last_error, last_validated, created_at, updated_at
         FROM proxies ORDER BY created_at ASC",
    )?;

    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i32>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, i32>(7)? != 0,
            row.get::<_, Option<i32>>(8)?,
            row.get::<_, i32>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, Option<String>>(11)?,
            row.get::<_, String>(12)?,
            row.get::<_, String>(13)?,
        ))
    })?;

    let mut repaired = 0usize;

    for row in rows {
        let (
            id,
            subscription_id,
            name,
            proxy_type,
            server,
            port,
            config_json,
            mut is_valid,
            mut local_port,
            mut error_count,
            mut last_error,
            mut last_validated,
            created_at,
            updated_at,
        ) = row?;

        if last_error.as_deref() == Some("binding creation failed") {
            is_valid = false;
            local_port = None;
            error_count = 0;
            last_error = None;
            last_validated = None;
            repaired += 1;
        }

        tx.execute(
            &stmt,
            &[
                &id,
                &subscription_id,
                &name,
                &proxy_type,
                &server,
                &port,
                &config_json,
                &is_valid,
                &local_port,
                &error_count,
                &last_error,
                &last_validated,
                &created_at,
                &updated_at,
            ],
        )?;
    }

    Ok(repaired)
}

fn migrate_proxy_quality(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO proxy_quality (
            proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible,
            google_accessible, risk_score, risk_level, extra_json, checked_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT proxy_id, ip_address, country, ip_type, is_residential,
                chatgpt_accessible, google_accessible, risk_score, risk_level, extra_json, checked_at
         FROM proxy_quality",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i32>(4)? != 0,
            row.get::<_, i32>(5)? != 0,
            row.get::<_, i32>(6)? != 0,
            row.get::<_, f64>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, String>(10)?,
        ))
    })?;

    for row in rows {
        let (proxy_id, ip_address, country, ip_type, is_residential, chatgpt_accessible, google_accessible, risk_score, risk_level, extra_json, checked_at) = row?;
        tx.execute(
            &stmt,
            &[
                &proxy_id,
                &ip_address,
                &country,
                &ip_type,
                &is_residential,
                &chatgpt_accessible,
                &google_accessible,
                &risk_score,
                &risk_level,
                &extra_json,
                &checked_at,
            ],
        )?;
    }

    Ok(())
}

fn migrate_users(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO users (
            id, username, name, avatar_template, active, trust_level, silenced,
            is_banned, api_key, created_at, updated_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11
         )",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, username, name, avatar_template, active, trust_level, silenced,
                is_banned, api_key, created_at, updated_at
         FROM users ORDER BY created_at ASC",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i32>(4)? != 0,
            row.get::<_, i32>(5)?,
            row.get::<_, i32>(6)? != 0,
            row.get::<_, i32>(7)? != 0,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, String>(10)?,
        ))
    })?;

    for row in rows {
        let (id, username, name, avatar_template, active, trust_level, silenced, is_banned, api_key, created_at, updated_at) = row?;
        tx.execute(
            &stmt,
            &[
                &id,
                &username,
                &name,
                &avatar_template,
                &active,
                &trust_level,
                &silenced,
                &is_banned,
                &api_key,
                &created_at,
                &updated_at,
            ],
        )?;
    }

    Ok(())
}

fn migrate_sessions(sqlite: &Connection, tx: &mut Transaction<'_>) -> Result<(), Box<dyn Error>> {
    let stmt = tx.prepare(
        "INSERT INTO sessions (id, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4)",
    )?;

    let mut query = sqlite.prepare(
        "SELECT id, user_id, created_at, expires_at
         FROM sessions ORDER BY created_at ASC",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    for row in rows {
        let (id, user_id, created_at, expires_at) = row?;
        tx.execute(&stmt, &[&id, &user_id, &created_at, &expires_at])?;
    }

    Ok(())
}

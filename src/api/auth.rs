use crate::db::User;
use crate::error::AppError;
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

const AUTHORIZE_URL: &str = "https://discord.com/oauth2/authorize";
const TOKEN_URL: &str = "https://discord.com/api/oauth2/token";
const USERINFO_URL: &str = "https://discord.com/api/users/@me";
const USER_GUILDS_URL: &str = "https://discord.com/api/users/@me/guilds";
const OAUTH_SCOPE: &str = "identify guilds";
pub const COOKIE_NAME: &str = "zenproxy_session";

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    discriminator: Option<String>,
    global_name: Option<String>,
    avatar: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscordGuild {
    id: String,
}

pub async fn login(State(state): State<Arc<AppState>>) -> Response {
    if let Some(resp) = oauth_config_error_response(&state) {
        return resp;
    }

    let client_id = &state.config.oauth.client_id;
    let redirect_uri = &state.config.oauth.redirect_uri;
    let mut url = match url::Url::parse(AUTHORIZE_URL) {
        Ok(url) => url,
        Err(_) => {
            return message_page(
                "OAuth Error",
                "OAuth Not Available",
                "Failed to build the Discord OAuth URL.",
            );
        }
    };
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", OAUTH_SCOPE);

    Redirect::temporary(url.as_str()).into_response()
}

pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    if let Some(resp) = oauth_config_error_response(&state) {
        return Ok(resp);
    }

    if let Some(error) = query.error.as_deref() {
        let description = query
            .error_description
            .as_deref()
            .unwrap_or("Discord did not complete the authorization flow.");
        return Ok(message_page(
            "Login Failed",
            "Discord Login Failed",
            &format!("{error}: {description}"),
        ));
    }

    let code = match query.code.as_deref() {
        Some(code) if !code.is_empty() => code,
        _ => {
            return Ok(message_page(
                "Login Failed",
                "Missing OAuth Code",
                "Discord did not return an authorization code.",
            ));
        }
    };

    let client = reqwest::Client::new();

    // Exchange code for token
    let token_resp = client
        .post(TOKEN_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &state.config.oauth.client_id),
            ("client_secret", &state.config.oauth.client_secret),
            ("redirect_uri", &state.config.oauth.redirect_uri),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let body = token_resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("Token exchange error: {body}")));
    }

    let token: TokenResponse = token_resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Token parse error: {e}")))?;

    // Fetch user info
    let user_resp = client
        .get(USERINFO_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("User info fetch failed: {e}")))?;

    if !user_resp.status().is_success() {
        let body = user_resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("User info error: {body}")));
    }

    let discord_user: DiscordUser = user_resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("User info parse error: {e}")))?;

    let guilds_resp = client
        .get(USER_GUILDS_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Guild fetch failed: {e}")))?;

    if !guilds_resp.status().is_success() {
        let body = guilds_resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("Guild fetch error: {body}")));
    }

    let guilds: Vec<DiscordGuild> = guilds_resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Guild parse error: {e}")))?;

    if !guilds
        .iter()
        .any(|guild| guild.id == state.config.oauth.required_guild_id)
    {
        return Ok(message_page(
            "Access Denied",
            "Guild Membership Required",
            "Join the required Discord server before logging in.",
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let user_id = discord_user.id.clone();

    // Check if user exists to preserve api_key
    let api_key = match state.db.get_user_by_id(&user_id)? {
        Some(existing) => {
            if existing.is_banned {
                return Ok(message_page(
                    "Account Banned",
                    "Account Banned",
                    "Your account has been banned by the administrator.",
                ));
            }
            existing.api_key
        }
        None => uuid::Uuid::new_v4().to_string(),
    };

    let username = discord_login_name(&discord_user);
    let user = User {
        id: user_id.clone(),
        username,
        name: discord_user.global_name.clone(),
        avatar_template: discord_avatar_url(&discord_user),
        active: true,
        trust_level: 1,
        silenced: false,
        is_banned: false,
        api_key,
        created_at: now.clone(),
        updated_at: now,
    };

    state.db.upsert_user(&user)?;

    // Create session
    let session = state.db.create_session(&user_id)?;

    // Set cookie and redirect
    let secure = if state.config.oauth.redirect_uri.starts_with("https") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{secure}",
        session.id
    );
    let mut response = Redirect::temporary("/").into_response();
    response
        .headers_mut()
        .insert("Set-Cookie", HeaderValue::from_str(&cookie).unwrap());
    Ok(response)
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = extract_session_user(&state, &headers).await?;
    Ok(Json(json!({
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "avatar_template": user.avatar_template,
        "trust_level": user.trust_level,
        "api_key": user.api_key,
        "created_at": user.created_at,
    })))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(session_id) = extract_session_id(&headers) {
        state.db.delete_session(&session_id)?;
    }
    let secure = if state.config.oauth.redirect_uri.starts_with("https") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}");
    let mut response = Json(json!({ "message": "Logged out" })).into_response();
    response
        .headers_mut()
        .insert("Set-Cookie", HeaderValue::from_str(&cookie).unwrap());
    Ok(response)
}

pub async fn regenerate_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let user = extract_session_user(&state, &headers).await?;
    let new_key = state.db.regenerate_api_key(&user.id)?;
    Ok(Json(json!({ "api_key": new_key })))
}

// --- Helper functions ---

pub fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{COOKIE_NAME}=")) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub async fn extract_session_user(state: &AppState, headers: &HeaderMap) -> Result<User, AppError> {
    let session_id = extract_session_id(headers)
        .ok_or_else(|| AppError::Unauthorized("No session cookie".into()))?;

    let session = state
        .db
        .get_session(&session_id)?
        .ok_or_else(|| AppError::Unauthorized("Invalid session".into()))?;

    // Check expiry
    let expires = chrono::DateTime::parse_from_rfc3339(&session.expires_at)
        .map_err(|_| AppError::Unauthorized("Invalid session expiry".into()))?;
    if chrono::Utc::now() > expires {
        state.db.delete_session(&session_id)?;
        return Err(AppError::Unauthorized("Session expired".into()));
    }

    let user = state
        .db
        .get_user_by_id(&session.user_id)?
        .ok_or_else(|| AppError::Unauthorized("User not found".into()))?;

    if user.is_banned {
        state.db.delete_user_sessions(&user.id)?;
        return Err(AppError::Unauthorized("Account banned".into()));
    }

    Ok(user)
}

pub async fn extract_api_key_user(
    state: &AppState,
    headers: &HeaderMap,
    query_api_key: Option<&str>,
) -> Result<User, AppError> {
    // Try Authorization: Bearer <api_key> header first
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| query_api_key.map(|s| s.to_string()));

    if let Some(key) = api_key {
        let user = state
            .db
            .get_user_by_api_key(&key)?
            .ok_or_else(|| AppError::Unauthorized("Invalid API key".into()))?;

        if user.is_banned {
            return Err(AppError::Unauthorized("Account banned".into()));
        }

        return Ok(user);
    }

    Err(AppError::Unauthorized("No API key provided".into()))
}

/// Cache TTL for auth lookups — avoids hitting DB mutex on every relay request.
const AUTH_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// Try API key first, then session cookie. Uses in-memory cache.
pub async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    query_api_key: Option<&str>,
) -> Result<User, AppError> {
    // Try API key (from header or query)
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| query_api_key.map(|s| s.to_string()));

    if let Some(ref key) = api_key {
        let cache_key = format!("ak:{key}");
        if let Some(user) = get_cached_user(state, &cache_key) {
            return Ok(user);
        }
        if let Ok(user) = extract_api_key_user(state, headers, query_api_key).await {
            cache_user(state, &cache_key, &user);
            return Ok(user);
        }
    }

    // Try session cookie
    if let Some(session_id) = extract_session_id(headers) {
        let cache_key = format!("ss:{session_id}");
        if let Some(user) = get_cached_user(state, &cache_key) {
            return Ok(user);
        }
        if let Ok(user) = extract_session_user(state, headers).await {
            cache_user(state, &cache_key, &user);
            return Ok(user);
        }
    }

    Err(AppError::Unauthorized(
        "Authentication required. Provide an API key or login via Discord OAuth.".into(),
    ))
}

fn get_cached_user(state: &AppState, cache_key: &str) -> Option<User> {
    let entry = state.auth_cache.get(cache_key)?;
    let (user, expires) = entry.value();
    if tokio::time::Instant::now() < *expires {
        Some(user.clone())
    } else {
        // Don't remove here — avoids TOCTOU race where a concurrent insert
        // could be deleted. Let the periodic cleanup task handle expired entries.
        None
    }
}

fn cache_user(state: &AppState, cache_key: &str, user: &User) {
    let expires = tokio::time::Instant::now() + AUTH_CACHE_TTL;
    state.auth_cache.insert(cache_key.to_string(), (user.clone(), expires));
}

fn oauth_config_error_response(state: &AppState) -> Option<Response> {
    if state.config.oauth.client_id.is_empty()
        || state.config.oauth.client_secret.is_empty()
        || state.config.oauth.redirect_uri.is_empty()
    {
        return Some(message_page(
            "OAuth Error",
            "OAuth Not Configured",
            "Set oauth.client_id, oauth.client_secret, and oauth.redirect_uri first.",
        ));
    }

    if state.config.oauth.required_guild_id.is_empty() {
        return Some(message_page(
            "OAuth Error",
            "Guild Not Configured",
            "Set oauth.required_guild_id before enabling Discord login.",
        ));
    }

    None
}

fn message_page(title: &str, heading: &str, message: &str) -> Response {
    let title = escape_html(title);
    let heading = escape_html(heading);
    let message = escape_html(message);
    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{title}</title>
        <style>body{{font-family:system-ui;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
        .box{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:16px;padding:40px;text-align:center;max-width:440px}}
        h2{{color:#ef4444;margin-bottom:12px}}p{{line-height:1.6}}a{{color:#6c63ff}}</style></head>
        <body><div class="box"><h2>{heading}</h2>
        <p>{message}</p>
        <p style="margin-top:16px"><a href="/">Back</a></p></div></body></html>"#
    );
    axum::response::Html(html).into_response()
}

fn discord_login_name(user: &DiscordUser) -> String {
    match user.discriminator.as_deref() {
        Some(discriminator) if !discriminator.is_empty() && discriminator != "0" => {
            format!("{}#{discriminator}", user.username)
        }
        _ => user.username.clone(),
    }
}

fn discord_avatar_url(user: &DiscordUser) -> Option<String> {
    let avatar = user.avatar.as_deref()?;
    let ext = if avatar.starts_with("a_") { "gif" } else { "png" };
    Some(format!(
        "https://cdn.discordapp.com/avatars/{}/{avatar}.{ext}?size=256",
        user.id
    ))
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

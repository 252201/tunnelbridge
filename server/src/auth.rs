use std::time::{Duration, Instant};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::http::{HeaderMap, Method, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    error::AppError,
    state::{AdminSession, LoginWindow, SharedState, session_expiry},
};

pub struct DeviceIdentity {
    pub id: Uuid,
    pub name: String,
}

pub fn random_secret(bytes: usize) -> String {
    let mut data = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut data);
    URL_SAFE_NO_PAD.encode(data)
}

pub fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

pub fn verify_password(encoded: &str, candidate: &str) -> bool {
    PasswordHash::new(encoded)
        .ok()
        .and_then(|hash| {
            Argon2::default()
                .verify_password(candidate.as_bytes(), &hash)
                .ok()
        })
        .is_some()
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let mut salt_bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error.to_string())))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|value| value.to_string())
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error.to_string())))
}

pub fn login_allowed(state: &SharedState, key: &str) -> bool {
    let now = Instant::now();
    if let Some(mut window) = state.login_attempts.get_mut(key) {
        if now.duration_since(window.started_at) > Duration::from_secs(60) {
            *window = LoginWindow {
                started_at: now,
                attempts: 1,
            };
            return true;
        }
        if window.attempts >= 5 {
            return false;
        }
        window.attempts += 1;
        true
    } else {
        state.login_attempts.insert(
            key.to_owned(),
            LoginWindow {
                started_at: now,
                attempts: 1,
            },
        );
        true
    }
}

pub fn create_session(state: &SharedState, username: String) -> (String, String) {
    let session_id = random_secret(32);
    let csrf_token = random_secret(24);
    state.sessions.insert(
        session_id.clone(),
        AdminSession {
            username,
            csrf_token: csrf_token.clone(),
            expires_at: session_expiry(state.config.session_ttl),
        },
    );
    (session_id, csrf_token)
}

pub fn session_cookie(state: &SharedState, session_id: &str) -> String {
    let secure = if state.config.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    format!(
        "tb_session={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        state.config.session_ttl.as_secs(),
        secure
    )
}

pub fn clear_session_cookie(state: &SharedState) -> String {
    let secure = if state.config.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    format!("tb_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
}

pub fn require_admin(
    state: &SharedState,
    headers: &HeaderMap,
    method: &Method,
) -> Result<(String, String), AppError> {
    let session_id = cookie_value(headers, "tb_session").ok_or(AppError::Unauthorized)?;
    let session = state
        .sessions
        .get(&session_id)
        .ok_or(AppError::Unauthorized)?;
    if session.expires_at <= Instant::now() {
        drop(session);
        state.sessions.remove(&session_id);
        return Err(AppError::Unauthorized);
    }
    if !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Forbidden)?;
        if csrf != session.csrf_token {
            return Err(AppError::Forbidden);
        }
        if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let host = headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            let origin_authority = origin
                .parse::<http::Uri>()
                .ok()
                .and_then(|uri| uri.authority().map(|value| value.as_str().to_owned()));
            if !origin_authority.is_some_and(|authority| authority.eq_ignore_ascii_case(host)) {
                return Err(AppError::Forbidden);
            }
        }
    }
    Ok((session.username.clone(), session.csrf_token.clone()))
}

pub fn remove_session(state: &SharedState, headers: &HeaderMap) {
    if let Some(id) = cookie_value(headers, "tb_session") {
        state.sessions.remove(&id);
    }
}

pub async fn require_device(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<DeviceIdentity, AppError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    let row =
        sqlx::query("SELECT id, name FROM devices WHERE token_hash = ? AND revoked = 0 LIMIT 1")
            .bind(hash_token(token))
            .fetch_optional(&state.db)
            .await?
            .ok_or(AppError::Unauthorized)?;
    let id =
        Uuid::parse_str(row.get::<String, _>("id").as_str()).map_err(|_| AppError::Unauthorized)?;
    Ok(DeviceIdentity {
        id,
        name: row.get("name"),
    })
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

use anyhow::{Context, Result, bail};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::RngCore;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};

use crate::config::Config;

pub async fn connect(config: &Config) -> Result<SqlitePool> {
    if let Some(path) = config.database_url.strip_prefix("sqlite://") {
        let path = path.split('?').next().unwrap_or(path);
        if let Some(parent) = std::path::Path::new(path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(&config.database_url)
        .await
        .context("connect sqlite")?;
    sqlx::query("PRAGMA journal_mode = WAL")
        .execute(&pool)
        .await?;
    migrate(&pool).await?;
    bootstrap_admin(&pool, config.admin_password.as_deref()).await?;
    Ok(pool)
}

async fn migrate(pool: &SqlitePool) -> Result<()> {
    for statement in [
        r#"CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            revoked INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT,
            created_at TEXT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS tunnels (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            local_host TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            remote_port INTEGER NOT NULL UNIQUE,
            access_mode TEXT NOT NULL,
            allowed_cidrs TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            subject TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"#,
        r#"CREATE TABLE IF NOT EXISTS connection_history (
            id TEXT PRIMARY KEY,
            tunnel_id TEXT NOT NULL,
            peer_addr TEXT NOT NULL,
            opened_at TEXT NOT NULL,
            closed_at TEXT NOT NULL,
            bytes_up INTEGER NOT NULL,
            bytes_down INTEGER NOT NULL
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_tunnels_agent ON tunnels(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_connection_history_closed ON connection_history(closed_at)",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

async fn bootstrap_admin(pool: &SqlitePool, password: Option<&str>) -> Result<()> {
    let exists: i64 = sqlx::query("SELECT COUNT(*) AS count FROM admins")
        .fetch_one(pool)
        .await?
        .get("count");
    if exists > 0 {
        return Ok(());
    }
    let Some(password) = password else {
        bail!("first launch requires TB_ADMIN_PASSWORD (minimum 12 characters)");
    };
    if password.len() < 12 {
        bail!("TB_ADMIN_PASSWORD must contain at least 12 characters");
    }
    let mut salt_bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string();
    sqlx::query(
        "INSERT INTO admins (id, username, password_hash, created_at) VALUES (1, 'admin', ?, ?)",
    )
    .bind(hash)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

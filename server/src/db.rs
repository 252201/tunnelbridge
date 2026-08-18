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
        "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_connection_history_closed ON connection_history(closed_at)",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }
    migrate_tunnels_v2(pool).await?;
    Ok(())
}

async fn migrate_tunnels_v2(pool: &SqlitePool) -> Result<()> {
    let exists: i64 = sqlx::query(
        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'tunnels'",
    )
    .fetch_one(pool)
    .await?
    .get("count");
    if exists == 0 {
        create_tunnels_v2(pool).await?;
        return Ok(());
    }

    let columns = sqlx::query("PRAGMA table_info(tunnels)")
        .fetch_all(pool)
        .await?;
    if columns
        .iter()
        .any(|row| row.get::<String, _>("name") == "kind")
    {
        create_tunnel_indexes(pool).await?;
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    sqlx::query("ALTER TABLE tunnels RENAME TO tunnels_v1")
        .execute(&mut *tx)
        .await?;
    sqlx::query(TUNNELS_V2_SCHEMA).execute(&mut *tx).await?;
    sqlx::query(
        r#"INSERT INTO tunnels
        (id, agent_id, name, local_host, local_port, kind, local_scheme, remote_port,
         hostname, access_mode, allowed_cidrs, enabled, created_at, updated_at)
        SELECT id, agent_id, name, local_host, local_port, 'tcp', 'tcp', remote_port,
         NULL, access_mode, allowed_cidrs, enabled, created_at, updated_at
        FROM tunnels_v1"#,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("DROP TABLE tunnels_v1")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    create_tunnel_indexes(pool).await?;
    Ok(())
}

const TUNNELS_V2_SCHEMA: &str = r#"CREATE TABLE tunnels (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    local_host TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('tcp', 'udp', 'web')),
    local_scheme TEXT NOT NULL CHECK (local_scheme IN ('tcp', 'udp', 'http', 'https')),
    remote_port INTEGER,
    hostname TEXT,
    access_mode TEXT NOT NULL,
    allowed_cidrs TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK ((kind IN ('tcp', 'udp') AND remote_port IS NOT NULL AND hostname IS NULL)
        OR (kind = 'web' AND remote_port IS NULL AND hostname IS NOT NULL))
)"#;

async fn create_tunnels_v2(pool: &SqlitePool) -> Result<()> {
    sqlx::query(TUNNELS_V2_SCHEMA).execute(pool).await?;
    create_tunnel_indexes(pool).await
}

async fn create_tunnel_indexes(pool: &SqlitePool) -> Result<()> {
    for statement in [
        "CREATE INDEX IF NOT EXISTS idx_tunnels_agent ON tunnels(agent_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_tcp_port ON tunnels(remote_port) WHERE kind = 'tcp'",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_udp_port ON tunnels(remote_port) WHERE kind = 'udp'",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_hostname ON tunnels(lower(hostname)) WHERE kind = 'web'",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrates_v1_tcp_tunnels_without_losing_endpoint() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            r#"CREATE TABLE devices (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
                revoked INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT, created_at TEXT NOT NULL
            )"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"CREATE TABLE tunnels (
                id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, name TEXT NOT NULL,
                local_host TEXT NOT NULL, local_port INTEGER NOT NULL,
                remote_port INTEGER NOT NULL UNIQUE, access_mode TEXT NOT NULL,
                allowed_cidrs TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO devices VALUES ('agent', 'Mac', 'hash', 0, NULL, 'now')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tunnels VALUES ('tunnel', 'agent', 'SSH', '127.0.0.1', 22, 20000, 'public', '[]', 1, 'now', 'now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        migrate(&pool).await.unwrap();
        let row = sqlx::query("SELECT kind, local_scheme, remote_port, hostname FROM tunnels")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("kind"), "tcp");
        assert_eq!(row.get::<String, _>("local_scheme"), "tcp");
        assert_eq!(row.get::<i64, _>("remote_port"), 20000);
        assert_eq!(row.get::<Option<String>, _>("hostname"), None);
        sqlx::query(
            "INSERT INTO tunnels VALUES ('udp', 'agent', 'DNS', '127.0.0.1', 53, 'udp', 'udp', 20000, NULL, 'public', '[]', 1, 'now', 'now')",
        )
        .execute(&pool)
        .await
        .expect("TCP and UDP may share the same numeric port");
        let duplicate_tcp = sqlx::query(
            "INSERT INTO tunnels VALUES ('tcp2', 'agent', 'SSH2', '127.0.0.1', 22, 'tcp', 'tcp', 20000, NULL, 'public', '[]', 1, 'now', 'now')",
        )
        .execute(&pool)
        .await;
        assert!(duplicate_tcp.is_err());
    }
}

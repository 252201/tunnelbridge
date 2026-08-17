use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use http::HeaderValue;
use sqlx::SqlitePool;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
use tunnelbridge_protocol::{
    AccessMode, AgentControlMessage, CreateTunnelRequest, DATA_FRAME_BYTES, LoginResponse,
};
use uuid::Uuid;

use crate::{
    api, auth,
    config::Config,
    db, gateway,
    state::{AppState, SharedState},
    tunnels,
};

#[tokio::test]
async fn relays_real_tcp_bytes_through_authenticated_websockets() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let public_port = unused_port().await?;
    let config = test_config(temporary.path().join("test.db"), public_port);
    let pool = db::connect(&config).await?;
    let (agent_id, token) = insert_device(&pool).await?;
    let state = AppState::new(config, pool);
    let tunnel = tunnels::create(
        &state,
        agent_id,
        CreateTunnelRequest {
            name: "echo".into(),
            local_host: "127.0.0.1".into(),
            local_port: 9,
            remote_port: Some(public_port),
            access_mode: AccessMode::Public,
            allowed_cidrs: vec![],
            enabled: true,
            allow_lan_target: false,
        },
    )
    .await
    .map_err(|error| anyhow::anyhow!(error))?;
    gateway::reconcile_listener(state.clone(), tunnel).await;

    let http = TcpListener::bind("127.0.0.1:0").await?;
    let http_addr = http.local_addr()?;
    let app = api::router(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(
            http,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });

    let mut control_request =
        format!("ws://{http_addr}/api/v1/agent/control").into_client_request()?;
    control_request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    let (mut control, _) = connect_async(control_request).await?;
    wait_for_config(&mut control).await?;

    let mut public = connect_with_retry(public_port).await?;
    let (connection_id, ticket) = wait_for_open(&mut control).await?;
    let mut data_request =
        format!("ws://{http_addr}/api/v1/agent/data/{connection_id}").into_client_request()?;
    data_request.headers_mut().insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    data_request
        .headers_mut()
        .insert("x-tunnel-ticket", HeaderValue::from_str(&ticket)?);
    let (mut data, _) = connect_async(data_request).await?;

    public.write_all(b"tunnelbridge").await?;
    let frame = tokio::time::timeout(Duration::from_secs(2), data.next())
        .await
        .context("data channel did not receive public bytes")?
        .context("data channel closed")??;
    let Message::Binary(frame) = frame else {
        anyhow::bail!("expected binary data frame")
    };
    assert_eq!(frame.first(), Some(&DATA_FRAME_BYTES));
    assert_eq!(&frame[1..], b"tunnelbridge");
    data.send(Message::Binary(frame)).await?;

    let mut echoed = [0_u8; 12];
    tokio::time::timeout(Duration::from_secs(2), public.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"tunnelbridge");

    gateway::stop_listener(&state, tunnel_id_from_state(&state).await?);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn admin_mutations_require_a_valid_csrf_token() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let port = unused_port().await?;
    let config = test_config(temporary.path().join("csrf.db"), port);
    let pool = db::connect(&config).await?;
    let state = AppState::new(config, pool);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = api::router(state);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });
    let client = reqwest::Client::new();
    let login_response = client
        .post(format!("http://{address}/api/v1/auth/login"))
        .json(&serde_json::json!({"username":"admin","password":"integration-test-password"}))
        .send()
        .await?;
    assert!(login_response.status().is_success());
    let cookie = login_response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .context("login did not set a cookie")?
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let login: LoginResponse = login_response.json().await?;

    let denied = client
        .post(format!("http://{address}/api/v1/admin/devices"))
        .header(reqwest::header::COOKIE, &cookie)
        .header(reqwest::header::ORIGIN, format!("http://{address}"))
        .json(&serde_json::json!({"name":"csrf-test"}))
        .send()
        .await?;
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);

    let allowed = client
        .post(format!("http://{address}/api/v1/admin/devices"))
        .header(reqwest::header::COOKIE, cookie)
        .header(reqwest::header::ORIGIN, format!("http://{address}"))
        .header("x-csrf-token", login.csrf_token)
        .json(&serde_json::json!({"name":"csrf-test"}))
        .send()
        .await?;
    assert_eq!(allowed.status(), reqwest::StatusCode::CREATED);
    server.abort();
    Ok(())
}

async fn wait_for_config<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    for _ in 0..4 {
        let message = socket.next().await.context("control socket closed")??;
        if let Message::Text(text) = message
            && matches!(
                serde_json::from_str::<AgentControlMessage>(&text)?,
                AgentControlMessage::ConfigSync { .. }
            )
        {
            return Ok(());
        }
    }
    anyhow::bail!("server did not send config sync")
}

async fn wait_for_open<S>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
) -> Result<(Uuid, String)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .context("waiting for open connection timed out")?
            .context("control socket closed")??;
        if let Message::Text(text) = message
            && let AgentControlMessage::OpenConnection {
                connection_id,
                ticket,
                ..
            } = serde_json::from_str(&text)?
        {
            return Ok((connection_id, ticket));
        }
    }
}

async fn connect_with_retry(port: u16) -> Result<TcpStream> {
    for _ in 0..20 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return Ok(stream);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("public tunnel listener did not start")
}

async fn unused_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok(listener.local_addr()?.port())
}

fn test_config(database: PathBuf, port: u16) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}?mode=rwc", database.display()),
        admin_dist: PathBuf::from("missing"),
        admin_password: Some("integration-test-password".into()),
        port_start: port,
        port_end: port,
        ticket_ttl: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(5),
        session_ttl: Duration::from_secs(60),
        audit_retention_days: 30,
        secure_cookies: false,
    }
}

async fn insert_device(pool: &SqlitePool) -> Result<(Uuid, String)> {
    let id = Uuid::new_v4();
    let token = auth::random_secret(32);
    sqlx::query("INSERT INTO devices (id, name, token_hash, revoked, created_at) VALUES (?, 'test-agent', ?, 0, ?)")
        .bind(id.to_string())
        .bind(auth::hash_token(&token))
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(pool)
        .await?;
    Ok((id, token))
}

async fn tunnel_id_from_state(state: &SharedState) -> Result<Uuid> {
    Ok(tunnels::list_all(&state.db)
        .await
        .map_err(|error| anyhow::anyhow!(error))?[0]
        .id)
}

mod api;
mod auth;
mod config;
mod db;
mod error;
mod gateway;
mod geoip;
mod kcp;
mod quic;
mod state;
mod transport_identity;
mod tunnels;
mod udp;

#[cfg(test)]
mod e2e_tests;

use std::path::Path;

use anyhow::Result;
use axum::Router;
use config::Config;
use state::AppState;
use tower_http::{
    compression::CompressionLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tunnelbridge_server=info,tower_http=info".into()),
        )
        .json()
        .with_current_span(false)
        .init();

    let config = Config::from_env()?;
    transport_identity::initialize(&config)?;
    let db = db::connect(&config).await?;
    let state = AppState::new(config.clone(), db);
    gateway::restore_listeners(&state).await?;
    tokio::spawn(quic::serve(state.clone()));
    tokio::spawn(kcp::serve(state.clone()));
    tokio::spawn(api::cleanup(state.clone()));

    let mut app = Router::new().merge(api::router(state));
    if Path::new(&config.admin_dist).join("index.html").exists() {
        app = app.fallback_service(
            ServeDir::new(&config.admin_dist)
                .not_found_service(ServeFile::new(config.admin_dist.join("index.html"))),
        );
    }
    let app = app
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(address = %config.listen_addr, "TunnelBridge server ready");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

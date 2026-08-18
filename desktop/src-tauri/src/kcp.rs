use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use dashmap::DashMap;
use kcp_tokio::{KcpConfig, KcpStream};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, sync::mpsc};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tunnelbridge_protocol::{
    ActiveTransport, AgentControlMessage, CarrierCapabilities, DirectCarrierAuth, PROTOCOL_VERSION,
};
use url::Url;
use uuid::Uuid;

use crate::{
    agent::{
        DIRECT_RECORD_BINARY, DIRECT_RECORD_CONTROL, LocalStreams, Outbound,
        dispatch_control_message, read_direct_record, write_direct_record,
    },
    config::{AgentConfig, load_transport_certificate, load_transport_fingerprint},
    runtime::{AgentStatus, RuntimeState},
};

pub async fn run(
    state: Arc<RuntimeState>,
    config: &AgentConfig,
    token: &str,
    cancellation: CancellationToken,
) -> Result<()> {
    let certificate_der =
        STANDARD.decode(load_transport_certificate(config.installation_id)?.trim())?;
    let expected = load_transport_fingerprint(config.installation_id)?;
    let actual = hex::encode(Sha256::digest(&certificate_der));
    anyhow::ensure!(actual == expected, "传输证书指纹与注册记录不匹配");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(certificate_der))?;
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));
    let url = Url::parse(&config.server_url)?;
    let host = url.host_str().context("服务器地址缺少主机")?;
    let port = if config.kcp_port == 0 {
        4000
    } else {
        config.kcp_port
    };
    let address = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .context("无法解析 KCP 服务器地址")?;
    let stream =
        KcpStream::connect(address, KcpConfig::new().fast_mode().stream_mode(true)).await?;
    let server_name = rustls::pki_types::ServerName::try_from("tunnelbridge-transport")?;
    let stream = connector.connect(server_name, stream).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let hello = AgentControlMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
        agent_id: config.installation_id,
        name: config.device_name.clone(),
        capabilities: CarrierCapabilities {
            transports: vec![ActiveTransport::Kcp],
            tunnel_kinds: vec![
                tunnelbridge_protocol::TunnelKind::Tcp,
                tunnelbridge_protocol::TunnelKind::Udp,
                tunnelbridge_protocol::TunnelKind::Web,
            ],
            ..CarrierCapabilities::default()
        },
        config_version: 0,
    };
    write_direct_record(
        &mut writer,
        DIRECT_RECORD_CONTROL,
        &serde_json::to_vec(&DirectCarrierAuth {
            token: token.to_owned(),
            hello,
        })?,
    )
    .await?;
    let streams: LocalStreams = Arc::new(DashMap::<Uuid, mpsc::Sender<(u8, Vec<u8>)>>::new());
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Outbound>(256);
    let writer_task = tauri::async_runtime::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            match message {
                Outbound::Control(message) => {
                    write_direct_record(
                        &mut writer,
                        DIRECT_RECORD_CONTROL,
                        &serde_json::to_vec(&message)?,
                    )
                    .await?;
                }
                Outbound::Binary(frame) => {
                    write_direct_record(&mut writer, DIRECT_RECORD_BINARY, &frame).await?;
                }
                Outbound::Close => {
                    writer.shutdown().await?;
                    break;
                }
            }
        }
        anyhow::Ok(())
    });
    state
        .set_status(AgentStatus::Online, "KCP 承载已连接")
        .await;
    state.set_transport(ActiveTransport::Kcp, None).await;
    state.log("info", "已通过 KCP/TLS 连接中继服务器").await;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = heartbeat.tick() => {
                outbound_tx.send(Outbound::control(AgentControlMessage::Ping { sent_at: chrono::Utc::now() })).await?;
            }
            record = read_direct_record(&mut reader) => {
                let (kind, payload) = record?;
                if kind == DIRECT_RECORD_BINARY {
                    if let Some((frame_kind, id, frame_payload)) = tunnelbridge_protocol::decode_carrier_frame(&payload)
                        && let Some(sender) = streams.get(&id)
                    {
                        let _ = sender.send((frame_kind, frame_payload.to_vec())).await;
                    }
                } else {
                    dispatch_control_message(
                        state.clone(), outbound_tx.clone(), streams.clone(), serde_json::from_slice(&payload)?,
                    ).await?;
                }
            }
        }
    }
    let _ = outbound_tx.send(Outbound::Close).await;
    writer_task.abort();
    Ok(())
}

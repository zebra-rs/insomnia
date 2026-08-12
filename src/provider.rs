//! Show-provider client (`zebra.show.v1`).
//!
//! Registers the `firewall` and `ipsec` show trees with zebra-rs and
//! pumps its orders to the backend tasks: `show firewall …` typed at
//! the zebra-rs CLI is answered from this process. Re-registers with
//! backoff whenever the stream drops (zebra-rs restart), so provider
//! coverage follows the daemon's lifetime.

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

use crate::api::ShowRequest;
use crate::endpoint::{RECONNECT_DELAY, connect_retry};
use crate::pb::show::show_provider_service_client::ShowProviderServiceClient;
use crate::pb::show::{ProviderMessage, Register, ShowChunk, ShowOrder, provider_message};

fn register_message() -> ProviderMessage {
    ProviderMessage {
        msg: Some(provider_message::Msg::Register(Register {
            name: vec!["firewall".to_string(), "ipsec".to_string()],
        })),
    }
}

fn chunk_message(id: u64, text: String) -> ProviderMessage {
    ProviderMessage {
        msg: Some(provider_message::Msg::Chunk(ShowChunk {
            id,
            text,
            eof: true,
        })),
    }
}

pub async fn run(
    host: String,
    firewall_tx: mpsc::Sender<ShowRequest>,
    ipsec_tx: mpsc::Sender<ShowRequest>,
) {
    loop {
        let channel = connect_retry(&host).await;
        let mut client = ShowProviderServiceClient::new(channel);

        let (out_tx, out_rx) = mpsc::channel::<ProviderMessage>(16);
        if out_tx.send(register_message()).await.is_err() {
            continue;
        }
        let mut orders = match client.provide(ReceiverStream::new(out_rx)).await {
            Ok(response) => response.into_inner(),
            Err(err) => {
                tracing::warn!("show provider registration failed: {err}; retrying");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        tracing::info!("show provider registered (firewall, ipsec)");

        loop {
            match orders.message().await {
                Ok(Some(order)) => dispatch(order, &firewall_tx, &ipsec_tx, &out_tx).await,
                Ok(None) => break,
                Err(err) => {
                    tracing::warn!("show provider stream error: {err}");
                    break;
                }
            }
        }
        tracing::warn!("show provider stream ended; re-registering");
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Route one order to its backend and spawn the answer relay. The
/// relay task keeps the order loop free while the backend renders,
/// and guarantees exactly one eof chunk per order even when the
/// backend is gone (dropped oneshot).
async fn dispatch(
    order: ShowOrder,
    firewall_tx: &mpsc::Sender<ShowRequest>,
    ipsec_tx: &mpsc::Sender<ShowRequest>,
    out_tx: &mpsc::Sender<ProviderMessage>,
) {
    let backend = if order.path.starts_with("/show/firewall") {
        Some(firewall_tx)
    } else if order.path.starts_with("/show/vpn/ipsec") {
        Some(ipsec_tx)
    } else {
        None
    };
    let Some(backend) = backend else {
        let _ = out_tx
            .send(chunk_message(
                order.id,
                String::from("% Unknown show command\n"),
            ))
            .await;
        return;
    };

    let (resp_tx, resp_rx) = oneshot::channel();
    let request = ShowRequest {
        path: order.path,
        args: order.args,
        json: order.json,
        resp: resp_tx,
    };
    if backend.send(request).await.is_err() {
        let _ = out_tx
            .send(chunk_message(
                order.id,
                String::from("% show handler not running\n"),
            ))
            .await;
        return;
    }
    let out_tx = out_tx.clone();
    let id = order.id;
    tokio::spawn(async move {
        let text = resp_rx
            .await
            .unwrap_or_else(|_| String::from("% show handler not running\n"));
        let _ = out_tx.send(chunk_message(id, text)).await;
    });
}

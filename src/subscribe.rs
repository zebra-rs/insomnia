//! Running-config subscription client (`zebra.config.v1`).

use crate::endpoint::{RECONNECT_DELAY, connect_retry};
use crate::pb::config::config_service_client::ConfigServiceClient;
use crate::pb::config::{ConfigEvent, Format, SubscribeRequest};

/// Open a JSON-format subscription for the config subtree at `path`,
/// retrying until it succeeds. The stream's first event is the
/// snapshot of the current running config, so the caller resyncs by
/// simply processing events in order.
pub async fn subscribe_json(host: &str, path: &[&str]) -> tonic::Streaming<ConfigEvent> {
    loop {
        let channel = connect_retry(host).await;
        let mut client = ConfigServiceClient::new(channel);
        let request = SubscribeRequest {
            format: Format::Json as i32,
            path: path.iter().map(|s| s.to_string()).collect(),
        };
        match client.subscribe(request).await {
            Ok(response) => return response.into_inner(),
            Err(err) => {
                tracing::warn!("subscribe /{}: {err}; retrying", path.join("/"));
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

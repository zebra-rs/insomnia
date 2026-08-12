//! In-process seams between the gRPC plumbing and the backends.
//!
//! These mirror the channel types the backends consumed when they
//! lived inside zebra-rs, so the firewall/IPsec code is moved rather
//! than rewritten: one JSON batch per touching commit, and one show
//! request per vty order.

use tokio::sync::oneshot;

/// One JSON batch delivery: the whole post-commit config subtree at
/// `path`, marshaled as JSON. `"{}"` means the subtree no longer
/// exists. The first delivery after (re)subscribing is the snapshot
/// of the current running config — reapplying it is what resyncs the
/// dataplane after a zebra-rs restart.
#[derive(Debug)]
pub struct JsonConfigUpdate {
    pub path: Vec<String>,
    pub json: String,
}

/// One vty show order, pre-split by zebra-rs exactly as
/// `path_from_command` split it for the in-process handlers:
/// `path` is the slash-joined command skeleton
/// (`/show/firewall/ipv4/name`), `args` the matched key/value tokens
/// in command order.
#[derive(Debug)]
pub struct ShowRequest {
    pub path: String,
    pub args: Vec<String>,
    /// Render JSON instead of the human table (`vtyctl show -j`).
    pub json: bool,
    /// Answer channel — every request must be answered exactly once
    /// (an empty string is a legitimate answer; a dropped sender
    /// surfaces to the operator as an unanswered command).
    pub resp: oneshot::Sender<String>,
}

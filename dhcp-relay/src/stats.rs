//! Per-interface counters, served as JSON on the control socket
//! (`show dhcp relay statistics`).
//!
//! Counters are keyed by family, VRF and the interface a packet arrived
//! on: requests count on their listen interface, replies on the
//! upstream interface they came in through. Every packet that is the
//! relay's business ends either `forwarded` or under one `dropped`
//! reason, so `received` = `forwarded` + the sum of `dropped`. Packets
//! that are not the relay's business (another host's DHCP traffic seen
//! through a shared socket) are not counted at all.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn name(self) -> &'static str {
        match self {
            Family::V4 => "dhcp4",
            Family::V6 => "dhcp6",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Counters {
    pub received: u64,
    /// Sent to at least one server, or delivered toward the client.
    pub forwarded: u64,
    /// Failed send calls: one per server a request could not reach.
    pub send_errors: u64,
    /// DHCPv4 requests forwarded without option 82 because of
    /// `max-size`.
    pub agent_option_omitted: u64,
    pub dropped: BTreeMap<&'static str, u64>,
}

impl Counters {
    pub fn drop(&mut self, reason: &'static str) {
        *self.dropped.entry(reason).or_default() += 1;
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    by_interface: BTreeMap<(Family, String, String), Counters>,
}

#[derive(Serialize)]
struct Row<'a> {
    vrf: &'a str,
    interface: &'a str,
    #[serde(flatten)]
    counters: &'a Counters,
}

impl Stats {
    pub fn entry(&mut self, family: Family, vrf: &str, interface: &str) -> &mut Counters {
        self.by_interface
            .entry((family, vrf.to_string(), interface.to_string()))
            .or_default()
    }

    /// `{"dhcp4": [rows], "dhcp6": [rows]}`, rows sorted by VRF, then
    /// interface.
    pub fn to_json(&self) -> serde_json::Value {
        let rows = |family: Family| -> Vec<serde_json::Value> {
            self.by_interface
                .iter()
                .filter(|((f, _, _), _)| *f == family)
                .map(|((_, vrf, interface), counters)| {
                    serde_json::to_value(Row {
                        vrf,
                        interface,
                        counters,
                    })
                    .unwrap_or_default()
                })
                .collect()
        };
        let mut out = serde_json::Map::new();
        for family in [Family::V4, Family::V6] {
            out.insert(family.name().to_string(), rows(family).into());
        }
        out.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape() {
        let mut stats = Stats::default();
        let c = stats.entry(Family::V4, "default", "eth1");
        c.received += 2;
        c.forwarded += 1;
        c.drop("hop-limit");
        stats.entry(Family::V6, "default", "eth0").received += 1;
        assert_eq!(
            stats.to_json(),
            serde_json::json!({
                "dhcp4": [{
                    "vrf": "default", "interface": "eth1", "received": 2, "forwarded": 1,
                    "send-errors": 0, "agent-option-omitted": 0, "dropped": {"hop-limit": 1}
                }],
                "dhcp6": [{
                    "vrf": "default", "interface": "eth0", "received": 1, "forwarded": 0,
                    "send-errors": 0, "agent-option-omitted": 0, "dropped": {}
                }]
            })
        );
    }
}

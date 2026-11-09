#!/bin/bash
# Stop what dhcp_node.sh and kea_server.sh started in one namespace:
# insomnia, the relay agent and every Kea instance (kea4, kea6, and the
# per-VRF kea4-<vrf> / kea6-<vrf>). zebra-rs is stopped by the regular
# "I stop zebra-rs" step. The pid files are host-global even though the
# daemons live in private namespaces; the clean-environment check fails
# on any left behind. Always exits 0 — the "I execute" step treats a
# non-zero exit as a scenario failure, and an already-gone daemon is fine
# at teardown.
NS="$1"
for f in "/tmp/$NS.insomnia.pid" "/tmp/$NS.relay.pid" /tmp/"$NS".kea*.pid; do
    if [ -f "$f" ]; then
        kill "$(cat "$f")" 2>/dev/null
        rm -f "$f"
    fi
done
rm -rf "/tmp/$NS.kea"
exit 0

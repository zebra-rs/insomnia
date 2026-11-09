#!/bin/bash
# Stop what dhcp_node.sh and kea_server.sh started in one namespace:
# insomnia, the relay agent and any Kea. zebra-rs is stopped by the
# regular "I stop zebra-rs" step. The pid files are host-global even
# though the daemons live in private namespaces; the clean-environment
# check fails on any left behind. Always exits 0 — the "I execute" step
# treats a non-zero exit as a scenario failure, and an already-gone
# daemon is fine at teardown.
NS="$1"
for d in insomnia relay kea4 kea6; do
    if [ -f "/tmp/$NS.$d.pid" ]; then
        kill "$(cat "/tmp/$NS.$d.pid")" 2>/dev/null
        rm -f "/tmp/$NS.$d.pid"
    fi
done
rm -rf "/tmp/$NS.kea"
exit 0

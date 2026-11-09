#!/bin/bash
# Stop the keepalived and insomnia started by vrrp_node.sh. zebra-rs is
# stopped by the regular "I stop zebra-rs" step; pids are host-global
# even though the daemons live in private namespaces. keepalived gets
# SIGTERM, which withdraws its virtual addresses before it exits. Always
# exits 0 — the "I execute" step treats a non-zero exit as a scenario
# failure, and an already-gone daemon is fine at teardown.
NS="$1"
# insomnia, the default instance's keepalived, and every per-VRF one
# (vrrp_node.sh … keepalived-vrf VRF).
for f in "/tmp/$NS.insomnia.pid" /tmp/"$NS".keepalived*.pid; do
    if [ -f "$f" ]; then
        kill "$(cat "$f")" 2>/dev/null
        rm -f "$f"
    fi
done
exit 0

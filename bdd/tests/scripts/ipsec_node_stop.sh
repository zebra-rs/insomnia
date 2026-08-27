#!/bin/bash
# Stop the charon and insomnia started by ipsec_node.sh. zebra-rs is
# stopped by the regular "I stop zebra-rs" step; pids are host-global
# even though the daemons live in private namespaces. Always exits 0 —
# the "I execute" step treats a non-zero exit as a scenario failure,
# and an already-gone daemon is fine at teardown.
NS="$1"
for d in insomnia charon; do
    if [ -f "/tmp/$NS.$d.pid" ]; then
        kill "$(cat "/tmp/$NS.$d.pid")" 2>/dev/null
        rm -f "/tmp/$NS.$d.pid"
    fi
done
exit 0

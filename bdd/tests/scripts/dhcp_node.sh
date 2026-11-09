#!/bin/bash
# One DHCP router for the dhcp_* BDD features: the insomnia-dhcp-relay
# agent, zebra-rs (the config owner, `--feature insomnia`) and insomnia
# (which renders relay.json, SIGHUPs the agent and answers
# `show dhcp[v6] relay statistics`), together inside a PRIVATE MOUNT
# NAMESPACE with tmpfs over /run, as vrrp_node.sh does.
#
# Why the mount namespace: network namespaces do not isolate the
# filesystem, and insomnia's paths are fixed (/run/insomnia/dhcp-relay,
# the agent's control socket in /run/insomnia-dhcp-relay), so two routers
# on one host would collide. /etc/swanctl gets a tmpfs too: insomnia's
# IPsec backend renders /etc/swanctl/swanctl.conf on every snapshot, and
# that must never land on the host's real strongSwan configuration.
#
# The agent is started here, on no config, before insomnia: insomnia runs
# in signal mode (`--dhcp-relay-control signal`), which only ever SIGHUPs
# the pid in /run/insomnia/dhcp-relay/relay.pid. A missing relay.json is
# an empty config, so the agent idles until the first render arrives.
# keepalived is not started; insomnia's VRRP backend just finds it absent.
set -e

NS="$1" # scoped namespace name, e.g. dhcp_relay_r1

if [ -z "$DHCP_NODE_INNER" ]; then
    export DHCP_NODE_INNER=1
    exec unshare -m "$0" "$@"
fi

mount -t tmpfs tmpfs /run
mkdir -p /run/lock /run/insomnia/dhcp-relay
mount -t tmpfs tmpfs /etc/swanctl

# Debug logging: the features read the agent's per-packet decisions
# ("reply relayed to lan2 (broadcast)") from logs/$NS.relay.log.
RUST_LOG=debug setsid insomnia-dhcp-relay \
    --pid-file /run/insomnia/dhcp-relay/relay.pid \
    >>"logs/$NS.relay.log" 2>&1 </dev/null &
echo $! >"/tmp/$NS.relay.pid"
for _ in $(seq 1 50); do
    [ -s /run/insomnia/dhcp-relay/relay.pid ] && break
    sleep 0.1
done

# zebra-rs, with the harness argv conventions vrrp_node.sh replicates (pid
# file, log path, /dev/null config, the staged YANG tree next to the
# staged binary). `--daemon` forks inside this namespace, so the child
# keeps the private mounts.
ZEBRA="$(command -v zebra-rs)"
YANG="$(cd "$(dirname "$ZEBRA")/../share/zebra-rs/yang" && pwd)"
"$ZEBRA" --feature insomnia --daemon \
    --log-output=file --log-file="logs/$NS.log" \
    --pid-file="/tmp/$NS.pid" -c /dev/null --yang-path "$YANG"

# insomnia in the same mount namespace. Every connection retries forever,
# so the start order against zebra-rs does not matter.
setsid insomnia --keepalived-control signal --dhcp-relay-control signal \
    >>"logs/$NS.insomnia.log" 2>&1 </dev/null &
echo $! >"/tmp/$NS.insomnia.pid"

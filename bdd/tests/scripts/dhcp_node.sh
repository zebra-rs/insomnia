#!/bin/bash
# One DHCP router for the dhcp_* BDD features: the insomnia-dhcp-relay
# agent, zebra-rs (the config owner, `--feature insomnia`) and insomnia
# (which renders relay.json and Kea's configurations and answers
# `show dhcp[v6] …`), together inside a PRIVATE MOUNT NAMESPACE with
# tmpfs over /run, as vrrp_node.sh does.
#
#   dhcp_node.sh NS                 a relay router
#   dhcp_node.sh NS kea             … that also runs the default VRF's Kea
#                                   (kea-dhcp4 and kea-dhcp6)
#   dhcp_node.sh NS kea-vrf VRF     start VRF's Kea pair on a running node,
#                                   under `ip vrf exec VRF`
#   dhcp_node.sh NS stop-insomnia   stop insomnia only (Kea and the agent
#                                   keep serving)
#   dhcp_node.sh NS start-insomnia  start it again
#
# Why the mount namespace: network namespaces do not isolate the
# filesystem, and insomnia's paths are fixed (/run/insomnia/dhcp-relay,
# /run/insomnia/kea, the agent's control socket in
# /run/insomnia-dhcp-relay), so two routers on one host would collide.
# /etc/swanctl gets a tmpfs too: insomnia's IPsec backend renders
# /etc/swanctl/swanctl.conf on every snapshot, and that must never land
# on the host's real strongSwan configuration. The later subcommands
# re-enter the node's mount namespace through the agent's pid.
#
# The agent is started here, on no config, before insomnia: insomnia runs
# in signal mode (`--dhcp-relay-control signal`), which only ever SIGHUPs
# the pid in /run/insomnia/dhcp-relay/relay.pid. A missing relay.json is
# an empty config, so the agent idles until the first render arrives.
#
# Kea runs in insomnia's socket mode (`--kea-control socket`): this
# script starts each instance on a bootstrap configuration at the paths
# insomnia renders to (/run/insomnia/kea/<vrf>/kea-dhcp{4,6}.conf, the
# control socket beside it, the leases under /run/insomnia/kea-state/
# <vrf>), listening nowhere; insomnia's config-test and config-reload
# replace it, as SIGHUP replaces the agent's empty config. keepalived is
# not started; insomnia's VRRP backend just finds it absent.
set -e

NS="$1" # scoped namespace name, e.g. dhcp_server_r1
MODE="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

. "$HERE/kea_env.sh"

# insomnia, in the node's mount namespace. Every connection retries
# forever, so the start order against zebra-rs does not matter.
start_insomnia() {
    setsid insomnia --keepalived-control signal --dhcp-relay-control signal \
        --kea-control socket --kea-state-dir /run/insomnia/kea-state \
        --kea-hooks-dir "$KEA_HOOKS" --kea-notify "$STAGE_BIN/insomnia-kea-notify" \
        >>"logs/$NS.insomnia.log" 2>&1 </dev/null &
    echo $! >"/tmp/$NS.insomnia.pid"
}

# start_kea 4|6 VRF: one instance on its bootstrap configuration. Logs to
# logs/NS.kea4.log (default VRF) or logs/NS.kea4-<vrf>.log, pid in the
# matching /tmp/NS.kea4[-<vrf>].pid.
start_kea() {
    local f="$1" vrf="$2" suffix="" exec=()
    local dir="/run/insomnia/kea/$vrf" state="/run/insomnia/kea-state/$vrf"
    if [ "$vrf" != default ]; then
        suffix="-$vrf"
        exec=(ip vrf exec "$vrf")
    fi
    mkdir -p "$dir" "$state"
    local lease="$state/kea-leases$f.csv" sock="$dir/kea$f-ctrl-socket"
    local extra=""
    if [ "$f" = 6 ]; then
        extra="\"data-directory\": \"$state\", \"server-id\": { \"type\": \"EN\", \"persist\": true },"
    fi
    # insomnia may already have rendered the instance's configuration (it
    # writes the file even when no Kea answers yet); start on that.
    [ -s "$dir/kea-dhcp$f.conf" ] || cat >"$dir/kea-dhcp$f.conf" <<EOF
{ "Dhcp$f": {
    "interfaces-config": { "interfaces": [] },
    "control-socket": { "socket-type": "unix", "socket-name": "$sock" },
    "lease-database": { "type": "memfile", "persist": true, "name": "$lease" },
    $extra
    "hooks-libraries": [
        { "library": "$KEA_HOOKS/libdhcp_lease_cmds.so", "parameters": {} },
        { "library": "$KEA_HOOKS/libdhcp_stat_cmds.so", "parameters": {} }
    ],
    "loggers": [ { "name": "kea-dhcp$f", "severity": "INFO",
        "output_options": [ { "output": "stdout", "pattern": "%-5p %m\n" } ] } ]
} }
EOF
    # shellcheck disable=SC2086 # KEA_ENV is a list of assignments
    setsid env $KEA_ENV KEA_LOCKFILE_DIR="$dir" KEA_PIDFILE_DIR="$dir" \
        "${exec[@]}" "$KEA_SBIN/kea-dhcp$f" -c "$dir/kea-dhcp$f.conf" \
        >>"logs/$NS.kea$f$suffix.log" 2>&1 </dev/null &
    echo $! >"/tmp/$NS.kea$f$suffix.pid"
    for _ in $(seq 1 50); do
        [ -S "$sock" ] && return 0
        sleep 0.1
    done
    echo "dhcp_node: kea-dhcp$f ($vrf) did not open $sock" >&2
    return 1
}

# Re-enter the node's private mount namespace (from a later `I execute`).
in_node() {
    exec nsenter -t "$(cat "/tmp/$NS.relay.pid")" -m --wd="$PWD" -- env DHCP_NODE_INNER=1 "$0" "$@"
}

case "$MODE" in
kea-vrf | stop-insomnia | start-insomnia)
    if [ -z "$DHCP_NODE_INNER" ]; then
        in_node "$@"
    fi
    case "$MODE" in
    kea-vrf)
        start_kea 4 "$3"
        start_kea 6 "$3"
        ;;
    stop-insomnia)
        kill "$(cat "/tmp/$NS.insomnia.pid")"
        rm -f "/tmp/$NS.insomnia.pid"
        ;;
    start-insomnia)
        start_insomnia
        ;;
    esac
    exit 0
    ;;
"" | kea) ;;
*)
    echo "usage: dhcp_node.sh NS [kea | kea-vrf VRF | stop-insomnia | start-insomnia]" >&2
    exit 2
    ;;
esac

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

if [ "$MODE" = kea ]; then
    start_kea 4 default
    start_kea 6 default
fi

# zebra-rs, with the harness argv conventions vrrp_node.sh replicates (pid
# file, log path, /dev/null config, the staged YANG tree next to the
# staged binary). `--daemon` forks inside this namespace, so the child
# keeps the private mounts.
ZEBRA="$(command -v zebra-rs)"
YANG="$(cd "$(dirname "$ZEBRA")/../share/zebra-rs/yang" && pwd)"
# ZEBRA_HOSTNAME_STUB_DIR: with --feature insomnia zebra-rs makes `system
# hostname` the system's host name, and this network namespace shares the
# HOST's. zebra-rs refuses outside the default network namespace by itself;
# the stand-in directory (the path bdd/src/netns.rs gives its own daemons)
# keeps this one off the real name a second time. Under /run, where only
# root creates entries: zebra-rs writes there as root, and a predictable
# name under /tmp could be a symbolic link somebody else put there.
ZEBRA_HOSTNAME_STUB_DIR="/run/zebra-rs-bdd/hostname/$NS" \
    "$ZEBRA" --feature insomnia --daemon \
    --log-output=file --log-file="logs/$NS.log" \
    --pid-file="/tmp/$NS.pid" -c /dev/null --yang-path "$YANG"

start_insomnia

#!/bin/bash
# One VRRP router for the vrrp_pair BDD feature: keepalived, zebra-rs
# (the config owner, `--feature iso`) and insomnia (the enforcement
# daemon that renders keepalived.conf, reloads keepalived and answers
# `show vrrp`), together inside a PRIVATE MOUNT NAMESPACE with tmpfs
# over /run.
#
# Why the mount namespace: network namespaces do not isolate the
# filesystem, and insomnia's keepalived instance directory
# (/run/insomnia/vrrp/default — config, pid files, JSON dump) is one
# fixed path, so two routers on one host would collide on the very same
# files. Inside `unshare -m` every router sees the stock path on its
# own tmpfs, which keeps insomnia's defaults entirely stock and keeps
# the routers clear of any keepalived service the host itself runs.
# /etc/swanctl gets a tmpfs too: insomnia's IPsec backend renders
# /etc/swanctl/swanctl.conf on every snapshot (empty here), and that
# must never land on the host's real strongSwan configuration.
#
# keepalived is started here, on an empty config, before insomnia:
# insomnia runs in signal mode (`--keepalived-control signal`), which
# only ever SIGHUPs the pid it finds in the instance directory. On an
# empty file keepalived idles ("no configuration to run") until the
# first render arrives.
#
# Requires keepalived installed on the host — see the Makefile target
# comment.
set -e

NS="$1" # scoped namespace name, e.g. vrrp_pair_r1

if [ -z "$VRRP_NODE_INNER" ]; then
    command -v keepalived >/dev/null || {
        echo "vrrp_node: keepalived not installed on this host" >&2
        exit 1
    }
    export VRRP_NODE_INNER=1
    exec unshare -m "$0" "$@"
fi

mount -t tmpfs tmpfs /run
mkdir -p /run/lock
mount -t tmpfs tmpfs /etc/swanctl

# insomnia's default instance directory (--keepalived-dir /run/insomnia/vrrp,
# instance `default`). TMPDIR steers keepalived's fixed-name dump files
# (keepalived.json, .data, .stats) into it; every pid path is explicit
# so nothing lands under /run's global names. --log-console goes to the
# harness's log file for this node.
INST=/run/insomnia/vrrp/default
mkdir -p "$INST"
: >"$INST/keepalived.conf"
TMPDIR="$INST" setsid keepalived --dont-fork \
    --use-file "$INST/keepalived.conf" \
    --pid "$INST/keepalived.pid" \
    --vrrp_pid "$INST/keepalived_vrrp.pid" \
    --checkers_pid "$INST/keepalived_checkers.pid" \
    --log-console --log-detail >>"logs/$NS.keepalived.log" 2>&1 </dev/null &
echo $! >"/tmp/$NS.keepalived.pid"
for _ in $(seq 1 50); do
    [ -s "$INST/keepalived.pid" ] && break
    sleep 0.1
done

# The harness starts zebra-rs itself everywhere else; here the daemon
# must live in this mount namespace, so the wrapper replicates the
# harness argv conventions (pid file, log path, /dev/null config) and
# its stage resolution: PATH already leads with <stage>/bin, and the
# staged YANG tree sits next to it. `--daemon` forks inside the
# namespace, so the daemonized child keeps the private mounts.
ZEBRA="$(command -v zebra-rs)"
YANG="$(cd "$(dirname "$ZEBRA")/../share/zebra-rs/yang" && pwd)"
"$ZEBRA" --feature iso --daemon \
    --log-output=file --log-file="logs/$NS.log" \
    --pid-file="/tmp/$NS.pid" -c /dev/null --yang-path "$YANG"

# insomnia in the same mount namespace: --keepalived-dir defaults to the
# private /run/insomnia/vrrp, and --host unix:zebra-rs/vty reaches this
# network namespace's zebra-rs (abstract sockets are per-netns). It
# retries every connection forever, so start order against zebra-rs
# does not matter. setsid detaches it from the harness's session the way
# --daemon does for zebra-rs; the pid file is swept by the harness and
# by vrrp_node_stop.sh. Logs append across runs like every other daemon
# log here; the harness reads them from the mark it took when this node
# was spawned.
setsid insomnia --keepalived-control signal \
    >>"logs/$NS.insomnia.log" 2>&1 </dev/null &
echo $! >"/tmp/$NS.insomnia.pid"

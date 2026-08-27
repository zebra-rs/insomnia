#!/bin/bash
# One IPsec node for the ipsec_s2s BDD feature: charon-systemd, zebra-rs
# (the config owner, `--feature iso`) and insomnia (the enforcement
# daemon that renders swanctl.conf and answers `show vpn ipsec`),
# together inside a PRIVATE MOUNT NAMESPACE with tmpfs over /run and
# /etc/swanctl.
#
# Why the mount namespace: network namespaces do not isolate the
# filesystem, and the strongSwan paths are effectively fixed —
# swanctl's enforced AppArmor profile allows config reads only under
# /etc/swanctl/** and the vici socket only at /run/charon.vici — so
# two nodes on one host would collide on the very same files. Inside
# `unshare -m` every instance sees the stock paths on its own tmpfs,
# which keeps insomnia, swanctl AND the AppArmor profiles entirely
# stock. (/var/run resolves through the /run symlink, so insomnia's
# default --vici-socket lands on the private tmpfs too.)
#
# Requires charon-systemd and strongswan-swanctl installed on the
# host — see the Makefile target comment.
set -e

NS="$1" # scoped namespace name, e.g. ipsec_s2s_z1

if [ -z "$IPSEC_NODE_INNER" ]; then
    command -v charon-systemd >/dev/null || {
        echo "ipsec_node: charon-systemd not installed on this host" >&2
        exit 1
    }
    export IPSEC_NODE_INNER=1
    exec unshare -m "$0" "$@"
fi

mount -t tmpfs tmpfs /run
mkdir -p /run/lock
mount -t tmpfs tmpfs /etc/swanctl

# charon-systemd logs only to the journal, and the private /run hides
# journald's socket — so without this its log is lost entirely. Give it
# a filelog instead: the harness's logs/$NS.charon.log is bind-mounted
# at /run/charon.$NS.log (the profile's `/run/charon.*` rw rule covers
# it, and the bind keeps it the same inode the harness reads), and a
# strongswan.conf that adds the filelog is bind-mounted over
# /etc/strongswan.conf — both mounts private to this namespace.
: >"logs/$NS.charon.log"
: >"/run/charon.$NS.log"
mount --bind "logs/$NS.charon.log" "/run/charon.$NS.log"
cat >/run/charon.strongswan.conf <<EOF
charon-systemd {
    load_modular = yes
    plugins {
        include /etc/strongswan.d/charon/*.conf
    }
    journal {
        default = -1
    }
    filelog {
        charon {
            path = /run/charon.$NS.log
            time_format = %b %e %T
            ike_name = yes
            default = 1
            ike = 2
            cfg = 2
            knl = 1
            net = 1
        }
    }
}
include /etc/strongswan.d/*.conf
EOF
mount --bind /run/charon.strongswan.conf /etc/strongswan.conf

charon-systemd >>"logs/$NS.charon.log" 2>&1 &
echo $! >"/tmp/$NS.charon.pid"
for _ in $(seq 1 50); do
    [ -S /run/charon.vici ] && break
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

# insomnia in the same mount namespace, so its defaults — --swanctl-dir
# /etc/swanctl, --vici-socket /var/run/charon.vici — land on the private
# tmpfs, and --host unix:zebra-rs/vty reaches this network namespace's
# zebra-rs (abstract sockets are per-netns). It retries every connection
# forever, so start order against zebra-rs does not matter. setsid
# detaches it from the harness's session the way --daemon does for
# zebra-rs; the pid file is swept by the harness and by ipsec_node_stop.sh.
# Logs append across runs like every other daemon log here; the harness
# reads them from the mark it took when this node was spawned.
setsid insomnia >>"logs/$NS.insomnia.log" 2>&1 </dev/null &
echo $! >"/tmp/$NS.insomnia.pid"

#!/bin/bash
# kea_server.sh NS 4|6 CONFIG: a standalone Kea for the relay features —
# the server the relay forwards to, not managed by insomnia. CONFIG is a
# tests/configs/<tag>/*.json file; every @DIR@ in it becomes this
# server's state directory (/tmp/NS.kea), which holds the rendered
# config, Kea's lock and pid files and the DHCPv6 data directory.
# Logging goes to stdout, appended to logs/NS.kea4.log / kea6.log.
#
# Kea comes from the host (apt install kea-dhcp4-server kea-dhcp6-server)
# or, when `make -C bdd stage KEA_PREFIX=<tree>` recorded an unpacked
# copy of the Ubuntu packages, from that tree. The harness reaches this
# script through `sudo ip netns exec … env PATH=<stage>/bin:…`, which
# drops every other environment variable, so the prefix travels in the
# stage directory rather than in the environment.
set -e

NS="$1" FAMILY="$2" CONFIG="$3"
case "$FAMILY" in
4 | 6) ;;
*)
    echo "usage: kea_server.sh NS 4|6 CONFIG" >&2
    exit 2
    ;;
esac

STAGE_BIN="$(dirname "$(command -v insomnia)")"
LIBS=""
if [ -s "$STAGE_BIN/../kea-prefix" ]; then
    KP="$(cat "$STAGE_BIN/../kea-prefix")"
    BIN="$KP/usr/sbin/kea-dhcp$FAMILY"
    LIBS="$(dirname "$(ls "$KP"/usr/lib/*/libkea-dhcpsrv.so.* | head -1)")"
else
    BIN="$(command -v "kea-dhcp$FAMILY")" || {
        echo "kea_server: kea-dhcp$FAMILY not installed on this host (or stage with KEA_PREFIX=…)" >&2
        exit 1
    }
fi

if [ "$FAMILY" = 6 ]; then
    # kea-dhcp6 joins ff02::1:2 through a socket on each interface's
    # link-local address. Started while that address is still tentative,
    # it fails the bind ("Failed to open link-local socket"), never
    # retries, and silently serves unicast only. Wait for DAD.
    for _ in $(seq 1 50); do
        [ -z "$(ip -6 -o addr show tentative)" ] && break
        sleep 0.1
    done
fi

DIR="/tmp/$NS.kea"
mkdir -p "$DIR"
sed "s|@DIR@|$DIR|g" "$CONFIG" >"$DIR/kea$FAMILY.json"
setsid env ${LIBS:+LD_LIBRARY_PATH=$LIBS} KEA_LOCKFILE_DIR="$DIR" KEA_PIDFILE_DIR="$DIR" \
    "$BIN" -c "$DIR/kea$FAMILY.json" >>"logs/$NS.kea$FAMILY.log" 2>&1 </dev/null &
echo $! >"/tmp/$NS.kea$FAMILY.pid"

#!/bin/bash
# dhcp_client.sh [-t SECONDS] IFACE 4|6 [CONF-LINE…]: one dhcpcd run on
# IFACE, inside the client's network namespace, printing what it got.
#
# dhcpcd runs inside its own mount namespace with tmpfs over /run and
# /var/lib/dhcpcd: the development host runs its own dhcpcd, whose
# control sockets, pid file and lease database live at those fixed paths.
# The config is written here, so a run never reads the host's
# /etc/dhcpcd.conf:
#   - v4: a client identifier of hardware type 1 and the interface's MAC
#     address, so a client keeps its identity across runs. (`clientid ""`
#     sends a 1-byte identifier on dhcpcd 10.0.6, which Kea refuses.)
#   - v6: `duid ll` and `ia_na 1`, a DUID from the hardware address, no
#     router solicitation (nothing sends RAs in these topologies);
#   - each extra argument is one more line, e.g. `broadcast`, or a
#     literal `duid 00:03:00:01:…` to appear as a different client.
#
# Output, for the harness steps to parse: one `address: <addr>/<len>`
# line per global address on IFACE afterwards, the lease variables as
# `lease: <name>=<value>` lines, and a final `result: lease` or
# `result: none`. The variables come from dhcpcd's hook, which gets them
# as `new_*` environment variables on every bind: dhcpcd 10's `-U` asks
# a running daemon, and a one-shot run has exited by then. Exits 0
# unless the arguments are wrong, so a failed lease is a parsed result,
# not a step error.
set -e

TIMEOUT=25
if [ "$1" = "-t" ]; then
    TIMEOUT="$2"
    shift 2
fi
IFACE="$1" FAMILY="$2"
shift 2 || {
    echo "usage: dhcp_client.sh [-t SECONDS] IFACE 4|6 [CONF-LINE…]" >&2
    exit 2
}
case "$FAMILY" in
4 | 6) ;;
*)
    echo "usage: dhcp_client.sh [-t SECONDS] IFACE 4|6 [CONF-LINE…]" >&2
    exit 2
    ;;
esac

if [ -z "$DHCP_CLIENT_INNER" ]; then
    export DHCP_CLIENT_INNER=1
    exec unshare -m "$0" -t "$TIMEOUT" "$IFACE" "$FAMILY" "$@"
fi

mount -t tmpfs tmpfs /run
mkdir -p /var/lib/dhcpcd
mount -t tmpfs tmpfs /var/lib/dhcpcd

CONF=/run/dhcp-client.conf
if [ "$FAMILY" = 4 ]; then
    printf 'clientid 01:%s\n' "$(cat "/sys/class/net/$IFACE/address")" >"$CONF"
else
    printf 'noipv6rs\nduid ll\nia_na 1\n' >"$CONF"
fi
for line in "$@"; do
    printf '%s\n' "$line" >>"$CONF"
done

HOOK=/run/dhcp-client-hook
LEASE=/run/dhcp-client.lease
cat >"$HOOK" <<'EOF'
#!/bin/sh
# dhcpcd hook: keep the variables of the lease just bound.
case "$reason" in
BOUND | BOUND6 | REBOOT | REBOOT6 | RENEW | RENEW6 | REBIND | REBIND6)
    env | grep '^new_' >/run/dhcp-client.lease
    ;;
esac
EOF
chmod +x "$HOOK"

# Start from no address, so what is printed afterwards is this run's.
ip -"$FAMILY" addr flush dev "$IFACE" scope global
if [ "$FAMILY" = 6 ]; then
    # DHCPv6 is sent from the link-local address, which must have
    # finished duplicate address detection.
    for _ in $(seq 1 50); do
        ip -6 addr show dev "$IFACE" scope link | grep -q tentative || break
        sleep 0.1
    done
fi

rc=0
timeout $((TIMEOUT + 15)) dhcpcd -B -1 -L -c "$HOOK" -t "$TIMEOUT" -f "$CONF" \
    -"$FAMILY" "$IFACE" >/dev/null 2>&1 || rc=$?

ip -o -"$FAMILY" addr show dev "$IFACE" scope global |
    awk '{ print "address: " $4 }'
if [ -f "$LEASE" ]; then
    sed 's/^new_/lease: /' "$LEASE"
fi
if [ "$rc" = 0 ]; then
    echo "result: lease"
else
    echo "result: none (dhcpcd exit $rc)"
fi

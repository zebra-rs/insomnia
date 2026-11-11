#!/bin/bash
# vrf_units.sh STAGE KEA_PREFIX: the systemd half of design/process.md, run
# by hand as root (the BDD features run in signal mode and never touch
# systemd). Everything it creates is removed at the end.
#
# It runs zebra-rs and insomnia (`--kea-control systemd`) inside a scratch
# network namespace `pvt`, installs the shipped Kea template units into
# /run/systemd/system with a drop-in that only adapts them to this host
# (Kea from an unpacked tree, root for the absent _kea user, the unit's
# sockets in `pvt`), and checks:
#   1. a `service dhcp-server vrf red …` commit makes insomnia pin red's
#      socket program and start insomnia-kea-dhcp4@red.service;
#   2. Kea's sockets are bound to VRF red, and a client on red's member
#      gets a lease;
#   3. `show process` lists the instance; `stop process` holds it down,
#      `restart process` is refused while held, `start process` brings it
#      back;
#   4. a missing pin refuses the start (AssertPathExists= in [Unit]);
#   5. the VRF deleted and re-created under a new interface index is
#      re-pinned and the instance runs bound to the new device;
#   6. `vrrp vrf red …` starts insomnia-keepalived@red.service (the shipped
#      template, keepalived from the host) bound the same way, holding
#      the virtual address on red's member, and back after the VRF is
#      re-created.
#
#   STAGE       bdd/.stage (zebra-rs, vtyctl, insomnia; `make -C bdd stage`)
#   KEA_PREFIX  an unpacked copy of Ubuntu's Kea packages (dpkg-deb -x)
set -u

STAGE="$(cd "$1" && pwd)"
KP="$(cd "$2" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$(dirname "$(ls "$KP"/usr/lib/*/libkea-dhcpsrv.so.* | head -1)")"
LOGS="$(mktemp -d /tmp/vrf_units.XXXXXX)"
UNITS=/run/systemd/system
PASS=0
FAIL=0

ok() { echo "PASS  $*"; PASS=$((PASS + 1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL + 1)); }
check() { # check DESCRIPTION COMMAND…
    local what="$1"
    shift
    if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi
}
eventually() { # eventually DESCRIPTION COMMAND…: up to 20 s
    local what="$1"
    shift
    for _ in $(seq 1 40); do
        if "$@" >/dev/null 2>&1; then
            ok "$what"
            return 0
        fi
        sleep 0.5
    done
    bad "$what"
}
vty() { ip netns exec pvt "$STAGE/bin/vtyctl" "$@"; }
show() { vty show "$1" 2>&1; }
contains() { # contains NEEDLE COMMAND…
    local needle="$1"
    shift
    "$@" 2>&1 | grep -qF -- "$needle"
}
matches() { # matches REGEX COMMAND…
    local re="$1"
    shift
    "$@" 2>&1 | grep -qE -- "$re"
}

cleanup() {
    [ -f "$LOGS/insomnia.pid" ] && kill "$(cat "$LOGS/insomnia.pid")" 2>/dev/null
    [ -f "$LOGS/zebra.pid" ] && kill "$(cat "$LOGS/zebra.pid")" 2>/dev/null
    for u in $(systemctl list-units --all --plain --no-legend 'insomnia-kea-dhcp*@*' | awk '{print $1}'); do
        systemctl stop "$u" 2>/dev/null
        systemctl reset-failed "$u" 2>/dev/null
    done
    for u in $(systemctl list-units --all --plain --no-legend 'insomnia-keepalived@*' | awk '{print $1}'); do
        systemctl stop "$u" 2>/dev/null
        systemctl reset-failed "$u" 2>/dev/null
    done
    rm -rf "$UNITS"/insomnia-kea-dhcp4@.service "$UNITS"/insomnia-kea-dhcp4@.service.d
    rm -rf "$UNITS"/insomnia-keepalived@.service "$UNITS"/insomnia-keepalived@.service.d
    systemctl daemon-reload
    rm -rf /sys/fs/bpf/insomnia /run/insomnia /var/lib/insomnia /run/insomnia-pvt
    ip netns del pvt 2>/dev/null
    ip netns del pvtc 2>/dev/null
}
cleanup
trap cleanup EXIT

# --- topology: VRF red is configured through zebra-rs below -----------
ip netns add pvt
ip netns add pvtc
ip link add c0 netns pvtc type veth peer name lanred netns pvt
ip -n pvt link set lo up
ip -n pvt link set lanred up
ip -n pvtc link set lo up
ip -n pvtc link set c0 up

# --- the shipped template, adapted to this host by a drop-in -----------
install -m 0644 "$HERE/../../../packaging/systemd/insomnia-kea-dhcp4@.service" "$UNITS/"
mkdir -p "$UNITS/insomnia-kea-dhcp4@.service.d"
cat >"$UNITS/insomnia-kea-dhcp4@.service.d/test.conf" <<EOF
# vrf_units.sh: Kea from an unpacked tree, root for the absent _kea user,
# the scratch network namespace. Everything about the VRF binding is the
# shipped template's.
[Service]
User=root
Group=root
NetworkNamespacePath=/run/netns/pvt
BindReadOnlyPaths=$KP/usr/sbin:/opt/kea/sbin $LIB:/opt/kea/lib $LIB/kea/hooks:/opt/kea/hooks
Environment=LD_LIBRARY_PATH=/opt/kea/lib KEA_LFC_EXECUTABLE=/opt/kea/sbin/kea-lfc
ExecStart=
ExecStart=/bin/sh -c "exec /opt/kea/sbin/kea-dhcp4 -c /run/insomnia/kea/%i/kea-dhcp4.conf"
EOF
# keepalived from the host, as shipped; only the namespace is the test's.
install -m 0644 "$HERE/../../../packaging/systemd/insomnia-keepalived@.service" "$UNITS/"
mkdir -p "$UNITS/insomnia-keepalived@.service.d"
cat >"$UNITS/insomnia-keepalived@.service.d/test.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/pvt
EOF
systemctl daemon-reload

# --- zebra-rs and insomnia in pvt --------------------------------------
YANG="$STAGE/share/zebra-rs/yang"
# ZEBRA_HOSTNAME_STUB_DIR: with --feature insomnia zebra-rs makes `system
# hostname` the system's host name, and `pvt` shares the HOST's. zebra-rs
# refuses outside the default network namespace by itself; the stand-in
# directory keeps this one off the real name a second time. Under /run,
# where only root creates entries: zebra-rs writes there as root.
ip netns exec pvt env ZEBRA_HOSTNAME_STUB_DIR=/run/zebra-rs-bdd/hostname/pvt \
    "$STAGE/bin/zebra-rs" --feature insomnia --daemon \
    --log-output=file --log-file="$LOGS/zebra.log" \
    --pid-file="$LOGS/zebra.pid" -c /dev/null --yang-path "$YANG"
mkdir -p /run/insomnia-pvt
# nsenter --net, not `ip netns exec`: the latter remounts /sys, which hides
# the host's bpffs (/sys/fs/bpf) where insomnia pins the programs systemd
# attaches. A real insomnia runs in the host's mount namespace too.
nsenter --net=/run/netns/pvt env RUST_LOG=info "$STAGE/bin/insomnia" \
    --kea-control systemd --kea-hooks-dir /opt/kea/hooks \
    --keepalived-control systemd \
    --dhcp-relay-control signal --dhcp-relay-dir /run/insomnia-pvt/relay \
    --swanctl-dir /run/insomnia-pvt/swanctl --vici-socket /run/insomnia-pvt/charon.vici \
    >"$LOGS/insomnia.log" 2>&1 &
echo $! >"$LOGS/insomnia.pid"
eventually "insomnia registered with zebra-rs" contains "show provider registered" cat "$LOGS/insomnia.log"

cat >"$LOGS/red.conf" <<'EOF'
set vrf red
set interface lanred vrf red
set interface lanred ipv4 address 10.1.0.1/24
set service dhcp-server vrf red shared-network-name T subnet 10.1.0.0/24 subnet-id 1
set service dhcp-server vrf red shared-network-name T subnet 10.1.0.0/24 range 0 start 10.1.0.100
set service dhcp-server vrf red shared-network-name T subnet 10.1.0.0/24 range 0 stop 10.1.0.149
set vrrp vrf red group G interface lanred
set vrrp vrf red group G vrid 10
set vrrp vrf red group G address 10.1.0.254/24
EOF
vty apply -f "$LOGS/red.conf" >/dev/null

# --- 1. pin and start ---------------------------------------------------
eventually "red's program is pinned" test -e /sys/fs/bpf/insomnia/vrf/red
RED=$(ip -n pvt -o link show red | awk -F': ' '{print $1}')
check "the pin records red's interface index ($RED)" grep -qx "$RED" /run/insomnia/vrf/red.ifindex
eventually "insomnia-kea-dhcp4@red.service is active" systemctl is-active --quiet insomnia-kea-dhcp4@red.service
check "the unit attaches the pinned program" contains "sock_create:/sys/fs/bpf/insomnia/vrf/red" \
    systemctl show -p BPFProgram insomnia-kea-dhcp4@red.service

# --- 2. bound to red, and serving ----------------------------------------
eventually "Kea's UDP socket is bound to VRF red" contains "%red" ip netns exec pvt ss -ulnp sport = :67
check "a client on red's member gets a lease" contains "address: 10.1.0.100/24" \
    ip netns exec pvtc "$HERE/dhcp_client.sh" -t 15 c0 4

# --- 3. show / stop / restart / start process ----------------------------
check "show process lists kea-dhcp4@red running" matches "^kea-dhcp4@red +red +running +up +[0-9]+" \
    show "show process"
check "stop process holds it" contains "Stopped kea-dhcp4@red" show "stop process kea-dhcp4@red"
check "the unit is stopped" sh -c '! systemctl is-active --quiet insomnia-kea-dhcp4@red.service'
check "the hold is on disk" test -e /run/insomnia/holds/kea-dhcp4@red
check "show process says stopped, held" matches "^kea-dhcp4@red +red +stopped +held" \
    show "show process kea-dhcp4@red"
check "restart process is refused while held" contains "was stopped by an operator" \
    show "restart process kea-dhcp4@red"
vty apply -c "set service dhcp-server vrf red shared-network-name T subnet 10.1.0.0/24 lease 600" >/dev/null
sleep 2
check "a commit keeps a held instance down" sh -c '! systemctl is-active --quiet insomnia-kea-dhcp4@red.service'
check "start process brings it back" contains "Started kea-dhcp4@red" show "start process kea-dhcp4@red"
eventually "the unit is active again" systemctl is-active --quiet insomnia-kea-dhcp4@red.service
check "on the configuration committed while held" grep -q '"valid-lifetime": 600' /run/insomnia/kea/red/kea-dhcp4.conf
check "restart process restarts it" contains "Restarted kea-dhcp4@red" show "restart process kea-dhcp4@red"
check "show process for an unknown name" contains '% No process "nope"' show "show process nope"

# --- 4. a missing pin refuses the start ----------------------------------
check "an instance whose VRF has no pin is refused" sh -c \
    '! systemctl start insomnia-kea-dhcp4@blue.service 2>/dev/null'
check "… by its assert (AssertPathExists= on the pin)" contains "AssertResult=no" \
    systemctl show -p AssertResult insomnia-kea-dhcp4@blue.service

# --- 6a. keepalived in red -------------------------------------------------
eventually "insomnia-keepalived@red.service is active" systemctl is-active --quiet insomnia-keepalived@red.service
check "the unit attaches red's program" contains "sock_create:/sys/fs/bpf/insomnia/vrf/red" \
    systemctl show -p BPFProgram insomnia-keepalived@red.service
eventually "keepalived@red holds the virtual address on red's member" contains "10.1.0.254/24" \
    ip -n pvt -4 addr show dev lanred
check "show process lists keepalived@red running" matches "^keepalived@red +red +running +up +[0-9]+" \
    show "show process keepalived@red"
check "show vrrp vrf red reads that instance" contains "MASTER" show "show vrrp vrf red"

# --- 5. the VRF deleted and re-created ------------------------------------
vty apply -c "delete interface lanred vrf" >/dev/null
vty apply -c "delete vrf red" >/dev/null
eventually "a deleted VRF is unpinned" sh -c '! test -e /sys/fs/bpf/insomnia/vrf/red'
eventually "and its instance stopped" sh -c '! systemctl is-active --quiet insomnia-kea-dhcp4@red.service'
vty apply -f "$LOGS/red.conf" >/dev/null
eventually "the re-created VRF is pinned again" test -e /sys/fs/bpf/insomnia/vrf/red
RED2=$(ip -n pvt -o link show red | awk -F': ' '{print $1}')
check "for its new interface index ($RED → $RED2)" grep -qx "$RED2" /run/insomnia/vrf/red.ifindex
eventually "the instance runs again" systemctl is-active --quiet insomnia-kea-dhcp4@red.service
eventually "bound to the new VRF device" contains "%red" ip netns exec pvt ss -ulnp sport = :67
check "and serves" contains "address: 10.1.0." ip netns exec pvtc "$HERE/dhcp_client.sh" -t 15 c0 4

# --- 6b. keepalived after the VRF came back ----------------------------------
eventually "insomnia-keepalived@red.service runs again" systemctl is-active --quiet insomnia-keepalived@red.service
eventually "and holds the virtual address again" contains "10.1.0.254/24" \
    ip -n pvt -4 addr show dev lanred

echo
echo "$PASS passed, $FAIL failed (logs in $LOGS)"
[ "$FAIL" = 0 ]

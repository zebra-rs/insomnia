# kea_env.sh: sourced by the scripts that start Kea (kea_server.sh,
# dhcp_node.sh). Sets, for this host or the staged KEA_PREFIX tree:
#   KEA_SBIN   directory holding kea-dhcp4 / kea-dhcp6 / kea-lfc
#   KEA_HOOKS  Kea's hook libraries (lease_cmds, stat_cmds, run_script)
#   KEA_ENV    the environment Kea needs: LD_LIBRARY_PATH for an
#              unpacked tree, and KEA_LFC_EXECUTABLE (a persistent memfile
#              refuses to load without kea-lfc at its built-in path,
#              /usr/sbin/kea-lfc)
#
# Kea comes from the host (apt install kea-dhcp4-server kea-dhcp6-server)
# or, when `make -C bdd stage KEA_PREFIX=<tree>` recorded an unpacked copy
# of the Ubuntu packages, from that tree. The harness reaches the scripts
# through `sudo ip netns exec … env PATH=<stage>/bin:…`, which drops every
# other environment variable, so the prefix travels in the stage directory
# rather than in the environment.
STAGE_BIN="$(dirname "$(command -v insomnia)")"
KEA_ENV=""
if [ -s "$STAGE_BIN/../kea-prefix" ]; then
    KP="$(cat "$STAGE_BIN/../kea-prefix")"
    KEA_SBIN="$KP/usr/sbin"
    KEA_LIBDIR="$(dirname "$(ls "$KP"/usr/lib/*/libkea-dhcpsrv.so.* | head -1)")"
    KEA_HOOKS="$KEA_LIBDIR/kea/hooks"
    KEA_ENV="LD_LIBRARY_PATH=$KEA_LIBDIR KEA_LFC_EXECUTABLE=$KEA_SBIN/kea-lfc"
else
    KEA_SBIN="$(dirname "$(command -v kea-dhcp4 || echo /usr/sbin/kea-dhcp4)")"
    KEA_HOOKS="$(ls -d /usr/lib/*/kea/hooks 2>/dev/null | head -1)"
fi

# Address, Network and Port Groups

Groups give a set of addresses, networks, ports, interfaces or MAC
addresses one name, referenced from any number of rules. Updating the
group updates every rule that uses it in the same commit.

```console
set firewall group address-group SERVERS address 10.0.0.1
set firewall group address-group SERVERS address 10.0.0.2-10.0.0.5
set firewall group network-group RFC1918 network 10.0.0.0/8
set firewall group network-group RFC1918 network 172.16.0.0/12
set firewall group network-group RFC1918 network 192.168.0.0/16
set firewall group port-group WEB port 80
set firewall group port-group WEB port 443
set firewall group port-group WEB port 8000-8080
set firewall group interface-group WAN interface eth0
set firewall group interface-group WAN interface ppp*
set firewall group mac-group PRINTERS mac-address 00:11:22:33:44:55
```

Seven group types exist:

| Type                 | Members                          | Used by |
|----------------------|----------------------------------|---------|
| `address-group`      | IPv4 hosts and ranges            | `source`/`destination group address-group` |
| `ipv6-address-group` | IPv6 hosts and ranges            | ditto, in the ipv6 tree |
| `network-group`      | IPv4 prefixes                    | `group network-group` |
| `ipv6-network-group` | IPv6 prefixes                    | ditto |
| `port-group`         | ports, names, ranges             | `group port-group` |
| `interface-group`    | interface names (wildcards ok)   | `inbound-/outbound-interface group` |
| `mac-group`          | MAC addresses                    | `group mac-group` |

Reference from a rule:

```console
set firewall ipv4 forward filter rule 20 destination group address-group SERVERS
set firewall ipv4 forward filter rule 20 destination group port-group WEB
```

## Nesting

A group can include another group of the same type; members are
flattened at commit:

```console
set firewall group address-group DMZ include SERVERS
set firewall group address-group DMZ address 10.0.1.100
```

## Inspecting

```console
$ show firewall group
Firewall Groups

 Name                 Type                 References  Members
 ----                 ----                 ----------  -------
 SERVERS              address-group                 1  10.0.0.1
                                                       10.0.0.2-10.0.0.5
 WEB                  port-group                    1  80
                                                       443
```

`References` counts the rules using the group. In the rendered
nftables ruleset groups become named sets with a type prefix
(`A_SERVERS`, `N_RFC1918`, `P_WEB`, `I_WAN`, `M_PRINTERS`; IPv6
groups use `A6_`/`N6_`) — that is what appears in the `Conditions`
column of `show firewall`.

Dynamic groups, domain (FQDN) groups and remote groups from newer
VyOS releases are not implemented yet.

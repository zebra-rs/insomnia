# Actions

Every rule needs an `action`; the rule set's `default-action` covers
packets no rule matched.

```console
set firewall ipv4 forward filter rule 10 action accept
```

| Action     | Effect |
|------------|--------|
| `accept`   | Allow the packet; evaluation of this rule set ends. |
| `drop`     | Discard silently. |
| `reject`   | Discard and send an ICMP error (or TCP RST) back. |
| `continue` | Count/log the packet, then keep evaluating — for accounting and logging rules. |
| `jump`     | Continue in the custom chain named by `jump-target`. |
| `return`   | Leave the current custom chain, resume after the jump. |
| `queue`    | Hand the packet to a userspace program via NFQUEUE. |
| `notrack`  | Skip connection tracking — raw chains only. |

## jump

`jump` requires a target:

```console
set firewall ipv4 forward filter rule 20 action jump
set firewall ipv4 forward filter rule 20 jump-target WEB-IN
```

The target must be a custom chain of the same address family
(`firewall ipv4 name WEB-IN`). If the chain does not exist at commit
time the whole ruleset is rejected by nftables and the previous
ruleset stays active — create the chain first.

## queue

```console
set firewall ipv4 input filter rule 30 action queue
set firewall ipv4 input filter rule 30 queue 0
set firewall ipv4 input filter rule 30 queue 0-3
set firewall ipv4 input filter rule 30 queue-options bypass
set firewall ipv4 input filter rule 30 queue-options fanout
```

`queue` selects the NFQUEUE number (a range load-balances);
`bypass` accepts packets when no program is listening instead of
dropping them, `fanout` distributes by flow across a queue range.

## Choosing drop vs reject

`reject` is friendlier inside your own network — clients fail fast
instead of timing out. `drop` reveals nothing to a scanner and is the
usual choice on internet-facing rule sets.

## Where actions differ

- Base chains (`forward`/`input`/`output` filter) restrict
  `default-action` to `accept` or `drop`.
- Custom chains allow the full set as default, plus
  `default-jump-target`.
- Raw chains add `notrack` and, running before conntrack, are also
  where early `drop` costs the least.

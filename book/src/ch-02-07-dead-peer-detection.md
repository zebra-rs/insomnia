# Dead Peer Detection

Dead peer detection (DPD, RFC 3706) probes the peer over the IKE
channel so a dead tunnel is noticed and acted on instead of silently
black-holing traffic. DPD is configured per IKE group and is off
until an action is set:

```console
set vpn ipsec ike-group IKE-A dead-peer-detection action restart
set vpn ipsec ike-group IKE-A dead-peer-detection interval 15
set vpn ipsec ike-group IKE-A dead-peer-detection timeout 60
```

- **action** — what happens when the peer stops answering:
  - `clear` (default) — tear the connection down and leave it down.
  - `trap` — tear it down but install trap policies, so the next
    packet that matches the tunnel re-negotiates it.
  - `restart` — re-negotiate immediately.
- **interval** — seconds between keep-alive probes (default 30).
- **timeout** — seconds without any reply before the peer is declared
  dead (default 120; IKEv1 only — IKEv2 uses its own retransmission
  schedule to decide liveness).

Choose the action to match the peer's `connection-type`: an
initiating router usually wants `restart`, a responder `clear` or
`trap`.

DPD interacts with the IKE group's `close-action`, which covers the
complementary case — the peer *deliberately* closing a CHILD SA
rather than going silent. `close-action trap | start` re-arms or
re-negotiates the tunnel; `none` (the default) accepts the closure.

## Verifying

The negotiated DPD settings appear in charon's view of the
connection:

```console
$ show vpn ipsec connections
```

and a peer flap is visible in `show vpn ipsec sa` — the SA row
disappears (`clear`), returns on traffic (`trap`) or re-establishes
with a fresh uptime (`restart`).

# Signed BPF upatches, shirudo-compatible — plan

Status: plan, 2026-11-23, second version. Nothing is implemented and no
spike has been run. The first version planned to run shirudo itself
beside insomnia; §1 records why that was dropped. Read against shirudo
`1e81ff59`, cradle-rs `5cdc41d`, insomnia `19ac3b0`. What is inferred
and still to be tried is marked *to confirm* and collected in §9.

The direction: **shirudo's binary does not run on our targets.** We take
its design and its artifacts, and we implement the target side
ourselves, so that a upatch an operator builds and signs with shirudo's
own tools is recognised, authenticated and loaded by our stack.

## Decisions at a glance

| # | Question | Recommendation |
|:--|:--|:--|
| U1 | What stays compatible | The `.upatch` artifact, its signature and its trust model (§2). The operator keeps using `shirudo build` unchanged |
| U2 | What we do not take | shirudo's target runtime: the lockdown, the runtime and config images, the initrd `init`, the TPM register, the timers (§1) |
| U3 | Where the loader lives | cradle-rs. It already owns BPF on the box. insomnia fronts it: config, trust set, `show` (§3) |
| U4 | Who verifies the signature | cradle-rs in userspace, always. The kernel as well, where it has the signed-loader ABI (§4) |
| U5 | Lockdown against root | Not in this plan. It is a separate decision with its own cost (§4, U9) |
| U6 | First artifact source | Local `.upatch` files named in the configuration. Packages and registries later (§7) |
| U7 | First step | The spike of §9, which needs real artifacts from shirudo's build |

## 1. Why not shirudo as it is

From the first version of this plan, kept because it is the reason for
this one:

- **Its lockdown refuses our own BPF.** After `shirudo init`, a program
  loads only through an operator-signed loader, and maps are created,
  written and attached only by executables on shirudo's dm-verity
  runtime image. cradle-rs loads its XDP and TC programs with aya,
  creates its maps from userspace and writes them on every route
  change: all refused. So is the VRF socket program insomnia pins,
  `default` included, which would keep keepalived and Kea from starting.
- **No signed route for them either.** shirudo has no TC attach kind and
  no cgroup socket kind, and only its own binary may write a map.
- **Its configuration is not ours to render.** A target's repositories,
  keys and settings live in an operator-signed image, because root on
  the target is its adversary. zebra-rs's store and insomnia are root.
- **Its platform.** A bpf-next kernel with shirudo's patches, a TPM, a
  UKI and a dracut initrd.

Running our own target side removes the first three: we decide who may
load, and the configuration is ours again.

## 2. The compatibility contract

"Compatible" means one direction: **we accept what shirudo's operator
tools produce.** It does not mean every published upatch runs on our
kernel (§4), and it says nothing about shirudo targets accepting ours,
though they would accept anything signed the same way.

| Piece | shirudo's definition | We implement |
|:--|:--|:--|
| Container | `.upatch` version 1: a 360-byte little-endian header (`PANUDRHS`, name, `payload_sha256`, region offsets), the loader instructions, the signature, and `data` ending in signed sections, a directory and a trailer | A reader with shirudo's validation and admission rules, in Rust |
| Signed bytes | `loader_insns ‖ data`, exactly as stored. The header is outside the signature and is checked against the signed `NAME` section and the digest | The same checks |
| Signature | Detached DER CMS `SignedData`, ML-DSA-87, signer named by subject key identifier, with or without signed attributes depending on the OpenSSL that built the writer | Verification of both forms |
| Trust set | A primary certificate, further certificates each carrying a vouch signed by a trusted key, minus revoked ones (by SHA-256 of the public key) | The same set and rules |
| Payload | A `BPF_PROG_TYPE_SYSCALL` loader from libbpf's gen_loader, plus its data blob holding the real programs and maps | The same load sequence: the one-element `__loader.map`, the loader's load, one test run, descriptors read back |
| Attach | The signed `UPGM` section: per program an attach kind and target | Attach from `UPGM`, never from the unsigned header |
| Unload | A directive: a `.upatch` with the unload flag and the digest of what it removes | Verify it, compare the digest, detach |

Sections we refuse at first, each with a named reason in the answer:

- `SHPL`: binds to shirudo's own policy maps, which do not exist here.
- `PTYP`/`JAVA`: Java agents, verified in userspace by shirudo too.
- `DCDB` (Lua decoders for map export) is read past, not used.

## 3. Who does what

```
operator host                         router
shirudo build  ──  x.upatch  ──▶  insomnia ──gRPC──▶ cradle ──bpf()──▶ kernel
(unchanged)                       trust set, which     reads, verifies,
                                  upatches, show       loads, attaches, holds
zebra-rs: the `upatch` config tree and the show grammar
```

- **cradle-rs is the upatch host.** One process then owns every BPF
  object on the box and can arbitrate the one thing two owners would
  fight over, the XDP slot of a port (§6). It gains a reader, the
  authentication, the loader and a small gRPC surface (load, unload,
  list). It needs its own note under cradle-rs `docs/design/`.
- **insomnia is the front**, in its usual shape: it subscribes to the
  `upatch` subtree, renders the trust set, hands cradle the artifacts and
  answers `show upatch`. This is its first engine reached over gRPC
  instead of a file and a reload.
- **zebra-rs** owns the schema. It already has a cradle client; whether
  it or insomnia should drive cradle here is decision U8.

Unlike with shirudo as it is, the insomnia pattern fits: under our
threat model (§4) the box's administrator chooses the trusted keys, so
they belong in the configuration. Certificates are public; the tree
holds no secret.

```
upatch                                   insomnia-gated, top level
├── trusted-key <name>
│   ├── certificate <base64 DER>         ML-DSA-87
│   └── vouch <base64>                   absent on the primary
├── revoked-key <fingerprint>
├── require-kernel-verification          empty; refuse to load on level 1 only (§4)
└── load <name>
    └── file <path>                      the artifact; its signed name must equal <name>

show upatch                  name, state, kind, digest, signer, verified by
show upatch <name>           programs, attach points, maps
show upatch key              the trust set, vouched by, revoked
```

## 4. What the signature is worth: three levels

| Level | Who checks | Needs | Stops |
|:--|:--|:--|:--|
| 1. Userspace | cradle-rs verifies the CMS signature over the bytes it then loads | Today's kernel (6.8 here) | An artifact that was tampered with, or signed by a key the box does not trust. Not root, who can load BPF without asking cradle |
| 2. Kernel-verified | The same load passes the signature and the `.bpf` keyring; the kernel verifies inside `BPF_PROG_LOAD`, with the data in an exclusive, frozen map | A kernel with the signed-loader ABI, and the certificates enrolled in `.bpf` | The same, with the check on the very bytes the kernel loads |
| 3. Lockdown | LSM programs refuse every load that level 2 did not verify | Level 2, plus our own guards, written so that cradle's data plane and insomnia's VRF program are admitted | Root without the signing key. This is shirudo's guarantee |

- **Level 1 first.** It runs on the kernels we ship, and it is honest
  about what it is: authenticity of what *we* load, not a boundary
  against root. shirudo's own documentation explains why a userspace
  check cannot be that boundary.
- **Level 2 when the kernel allows**, chosen by a probe at start, shown
  per upatch in `show upatch`, and required by
  `require-kernel-verification`.
- **Level 3 is not planned here** (U9). It is the part of shirudo that
  locked us out, and building our own means signing cradle's programs
  too, an authority rule for our daemons, and a boot chain to trust.

**Kernel reach.** shirudo builds for a bpf-next kernel (`-mcpu=v4`,
recent kfuncs, arena maps for state). An artifact can be authentic and
still be refused by an older verifier. That is a per-upatch result,
reported as such, never a reason to skip the signature check. Which of
shirudo's own upatches load on 6.8 is spike item 4.

## 5. Loader details that matter

- **One read.** The file is read once into memory; the digest, the
  signature check, the load and the kept copy all use those bytes.
- **Order.** Reader and admission checks, then the signature, and only
  then the first `bpf()` call.
- **Signed metadata only.** Name, attach kinds and targets come from the
  signed sections.
- **State.** cradle keeps the loaded set and the artifacts under its
  state directory and restores them at start. Whether links are held as
  descriptors or pinned decides what survives a cradle restart: *to
  decide* in the cradle note, with its existing rule that a killed
  daemon leaves no stale datapath behind.
- **What is not copied.** No TPM extend, no eventlog chain, no seal
  labels. A plain log line per load and unload, with name, digest and
  signer.

## 6. Attach kinds, and cradle's own programs

| Kind | First release | Note |
|:--|:--|:--|
| fentry, fexit, fmod_ret, lsm, tp_btf | yes | No contact with cradle's programs |
| kprobe, kretprobe and their multi forms | yes | |
| uprobe family | later | shirudo also checks the target's build ID |
| netfilter, cgroup_skb | yes | Packets cradle forwards at TC never reach netfilter (`vyos-gap.md` §4.7) |
| xdp/`<mask>` | later | A port holds one XDP program. cradle must decide per port whether its own stage or the upatch runs, and say so in `show` |
| serializer and test programs (`syscall`) | later | Map export is not in scope yet |

## 7. Later, in order of likely demand

1. Packages and registries: shirudo's `.bee` archive, signed index and
   OCI pull, so that `bpm push` on the operator side feeds our routers.
2. XDP upatches, with the arbitration of §6.
3. The upatch tree, shirudo's signed desired state by node labels.
4. Measurement: an eventlog and a TPM register an operator can verify.
5. Level 3.

## 8. Changes by repository

| Repo | Content |
|:--|:--|
| cradle-rs | `upatch` reader with fixtures and a fuzz target; trust set and CMS/ML-DSA-87 verification; the loader and attach kinds of §6; unload directives; state and restore; gRPC `LoadUpatch`, `UnloadUpatch`, `ListUpatches`; `cradle dump` view; design note |
| zebra-rs | `upatch` grouping and the insomnia-gated top-level node; `show upatch` grammar and routing |
| insomnia | `src/upatch.rs`: model, trust-set rendering, cradle client (the vendored part of `cradle.proto`), show provider; golden and stub tests; book chapter |
| shirudo | None. We read its formats; we do not change or ship it |

Licensing: shirudo is BSD-2-Clause and its formats are documented. We
write our own reader from that documentation; cradle-rs and insomnia
stay AGPL-3.0-or-later.

## 9. Spike first

1. Build shirudo's operator tools (its container or test VM), make a
   key with `shirudo genkey`, and build three artifacts: a trivial
   fentry upatch, one from `upatches/kernel-obs`, and an unload
   directive. These become the fixtures.
2. Verify their signatures in Rust, with and without signed attributes.
   Ubuntu 24.04's OpenSSL 3.0 has no ML-DSA, so this needs a Rust
   implementation; which crate, and whether it handles the CMS form, is
   the question.
3. Run the trivial artifact's loader on 6.8 without a signature: create
   `__loader.map`, load, test run, attach. Does gen_loader's output from
   shirudo's libbpf run there?
4. Try shirudo's own upatches on 6.8 and list which the verifier takes.
5. On a kernel with the signed-loader ABI (shirudo's test kernel), do
   the same load at level 2 from a plain root process: enrol the
   certificate in `.bpf`, pass the signature. Without shirudo's LSM
   nothing should refuse it.

## 10. Open decisions

| # | Decision |
|:--|:--|
| U1 | Is the reading right: no shirudo binary on the target, compatibility at the artifact |
| U4 | Is level 1 acceptable for a first release, or is kernel verification required, which brings the bpf-next kernel back as a prerequisite |
| U8 | Does insomnia drive cradle for upatches, or zebra-rs, which already has the client |
| U9 | Is lockdown (level 3) a goal at all. If yes it shapes level 2 now: cradle's own programs would have to be signed loads from the start |
| U10 | Top-level `upatch`, or under a broader node |
| U11 | Where trusted keys come from at first boot of an appliance image, before any configuration |

## 11. References

- shirudo `1e81ff59`: `Documentation/reference/formats/upatch-format.rst`
  (container, signature, sections, admission),
  `internals/signed-loader.rst` (the load sequence and its checks),
  `concepts/background/bpf-signing.rst` (what the kernel verifies),
  `operate/maintain/keys.rst` and `reference/cli/keys.rst` (trust set,
  vouch, revoke), `reference/cli/build.rst`,
  `upatches/write/attach-kinds.rst`,
  `operate/plan/interoperability.rst` (the lockdown of §1),
  `reference/formats/bpm-formats.rst` (§7).
- cradle-rs `5cdc41d`: `AGENTS.md` (the four programs),
  `crates/cradle/src/control.rs` (attach), `proto/cradle.proto`.
- insomnia `19ac3b0`: `src/vrf.rs`, `src/process.rs`,
  `design/vyos-gap.md` §4.7.

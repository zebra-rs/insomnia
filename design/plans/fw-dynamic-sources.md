# Firewall dynamic sources: domain groups, FQDN, remote groups, GeoIP — implementation plan

Status: plan, 2026-10-21. Covers: FW10 (`group domain-group`, rule `fqdn`,
`global-options resolver-cache|resolver-interval`), FW14 (`group
remote-group`), FW11 (`global-options geoip`, rule `geoip`, op `update geoip`)
([vyos-gap](../vyos-gap.md) §5, §6.2 `fqdn`/`domain-group` row, §6.6 geoip
row).
Priority: P2 (FW10, FW11) · P3 (FW14) · Effort: L (FW10 M + FW14 M + FW11 L) ·
Owner: both
Depends on: [nft-common](nft-common.md) (`crate::nft`: `GroupKind`,
`matcher::endpoint`, `Script`/`Origin`, `apply_if_changed`),
[fw-load-safety](fw-load-safety.md) (the X2 reference pass: `RefIndex`,
`plan_table`; X1 `auto-merge`),
[fw-packet-modification](fw-packet-modification.md) (`parse_live` /
`SetElem` live-set reader), [exec-verbs](exec-verbs.md) (`update geoip`, a new
`update` verb), [commit-validation](commit-validation.md)
(`crate::findings`), [secret-redaction](secret-redaction.md)
(`maxmind-license-key`, URL credentials); soft: [fw-opmode](fw-opmode.md)
(the group view this plan adds rows to) ·
Unblocks: [nat](nat.md) (`fqdn` / `domain-group` in NAT rules),
[pbr](pbr.md) (geoip / domain-group in `policy-route`)

This plan **owns the out-of-band set updater** (`src/dynsets.rs`). Every
backend that needs sets filled from DNS, HTTP or the GeoIP database uses it.
None of them resolves, fetches or parses on its own.

## 1. Goal

- `firewall group domain-group`, rule `source|destination fqdn` and
  `group domain-group` match the addresses the names resolve to. They are
  re-resolved every `resolver-interval`; `resolver-cache` keeps the last good
  answer.
- `firewall group remote-group <n> url … interval …` matches an address
  list fetched over HTTP(S). It survives fetch failures and reboots through
  an on-disk cache.
- Rule `source|destination geoip country-code|asn [inverse-match]` matches
  DB-IP (default) or MaxMind ranges. The database refreshes weekly and on
  `update geoip`.
- **No window after a commit.** Every commit, resubscribe or insomnia
  restart loads the dynamic sets already filled, in the same atomic
  transaction as the ruleset. VyOS has a window where they are empty.
- `show firewall group` shows the live members and the freshness of each
  dynamic group.

## 2. Current state

**insomnia @ `ee4dfaa`:**
- **Each apply recreates the table empty.** `render` starts every script
  with `add table` and `delete table` for both families (`firewall.rs:1173-1191`).
  Every apply therefore recreates the table. Any member written out of band
  is gone after the next commit or resubscribe (`firewall.rs:56-82`).
- **The model has no dynamic group kinds.** `Groups` has seven static kinds
  (`firewall.rs:782-793`), and `GroupRef` has `address|network|port|mac-group`
  (`firewall.rs:923-929`).
- **Show.** `show_groups_text` prints Name/Type/References/Members from
  config (`firewall.rs:606-645`).
- **No HTTP client, gzip or zip crate** (`Cargo.toml` `[dependencies]`). The
  unit has `RuntimeDirectory=insomnia` but no `StateDirectory`
  (`packaging/systemd/insomnia.service`).

**zebra-rs @ `141da2fc`:**
- `firewall.yang:31-35` lists fqdn/domain-group, geoip and remote-group as
  deferred. `l3-match-v4/v6` (`:498-598`) have no `fqdn` or `geoip`.

**VyOS `7f2c893`:**
- **Sets are declared empty in the ruleset:**
  - `D_<n>` (`nftables-defines.j2:30-37`, `flags interval`, no `auto-merge`);
  - `R_<n>` / `R6_<n>` (`:38-55`, `auto-merge`);
  - `FQDN_<set>` and `GEOIP_*` (`nftables.j2:182-195`, `:379-392`).
- **They are filled out of band:**
  - `src/services/vyos-domain-resolver` (`:233-286` DNS, `:143-231` remote
    groups) runs `flush set` plus `add element` against every table that
    has the set (`:113-118`, `nft_valid_sets` `:120-135`).
  - `firewall.py:794-802` restarts that service after every firewall
    commit. `firewall.py:804-807` re-runs `/run/nftables-geoip.conf`
    (`geoip_refresh`, `python/vyos/geoip.py:230-242`), or rebuilds it
    (`geoip_update`, `:244-309`).
  - The sets are therefore **empty between the commit and the refill**.
- **Resolver** (`vyos-domain-resolver:79-111`):
  - `getaddrinfo` per family (`python/vyos/firewall.py:80-85`);
  - interval `resolver-interval` (10-3600, default 300,
    `global-options.xml.i:244-255`);
  - with `resolver-cache`, the last good result is used on failure;
    without it, the domain is dropped.
- **FQDN set names** (`firewall.py:53-78`, `parse_rule` `:225-241`):
  - The name is `FQDN_<hook>_<chain>_<rule>_<s|d>`, with hook `forward`,
    `input`, `output`, `prerouting`, `name`, or `name6` for ipv6 custom
    chains.
  - `fqdn_config_parse` only collects forward/input/output/name. A
    prerouting-raw `fqdn`, which the schema allows
    (`common-rule-ipv4-raw.xml.i:28`), references a set that is never
    declared (*code reading*).
- **Remote groups:**
  - per-group `interval` (60 s to 4 weeks, `firewall.xml.in:151-166`);
  - a failed fetch is retried at `min(interval, resolver-interval)`, and
    the cached `/config/firewall/R_<n>.txt` is used meanwhile (`:171-191`);
  - list parsing: the first word of each line, IPv4/IPv6
    address/prefix/range (`:193-208`);
  - URL credentials are redacted in logs (`:180-183`);
  - cache files of deleted groups are removed (`firewall.py:724-731`).
- **GeoIP** (`python/vyos/geoip.py`):
  - **Download:**
    - DB-IP lite CSV: `https://download.db-ip.com/free/dbip-{country,asn}-lite-YYYY-MM.csv.gz`
      (`:27-39`);
    - MaxMind CSV zip: `https://ID:KEY@download.maxmind.com/geoip/databases/{GeoLite2|GeoIP2}-{Country,ASN}-CSV/download?suffix=zip`
      (`:41-56`).
  - **Storage:** the data is imported into sqlite at
    `/var/cache/vyos/geoip-lookup.db` (`:68-208`). A bundled DB under
    `/usr/share/vyos-geoip` seeds the first use (`:254-257`).
  - **Set names:** `GEOIP_CC[6]_<hook>_<chain>_<rule>_<s|d>` and
    `GEOIP_ASN[6]_…` (`:263-276`; `firewall.py:243-264`).
  - **Refresh:** a weekly cron, Monday 04:30 (`src/etc/cron.d/vyos-geoip`),
    and op `update geoip` (`src/helpers/geoip-update.py`).
  - **Options:** `global-options geoip` has `provider` (db-ip, maxmind),
    the maxmind account, license key and `lite`, `source-address` and `vrf`
    (`global-options.xml.i:133-176`).
- **Verify** (`firewall.py:412-446`, `548-551`, `584-593`):
  - at most one of address, fqdn and geoip per side;
  - at most one of asn and country-code;
  - at most one address/network/domain/remote group;
  - maxmind needs both the account id and the key;
  - a remote group needs `url`, and its interval must be in range.

**Measured for this plan** (nftables 1.0.9 in a scratch netns):
- A 60 000-range `interval, auto-merge` set loads in 0.13 s, and re-adding
  it takes 0.32 s.
- `flush set` plus `add element` refills in place.
- `auto-merge` folds overlapping and adjacent elements
  (`10.0.0.0/8` + `10.1.0.0/16` → `10.0.0.0/8`).
- An empty `add element … { }` is not valid nft, so empty fills must be
  omitted.

## 3. Design

**3.1 Central decision: embed in the commit transaction, refill in place.**
- **The firewall renderer stays pure.** `render_with(cfg, &Exclusions)`
  ([fw-load-safety](fw-load-safety.md)) declares the dynamic sets **empty**,
  and that static script is what X12 compares.
- **A second pure function** builds the fill:

  ```rust
  pub fn dyn_sets(cfg: &FirewallConfig) -> Vec<DynSet>;
  pub fn fill(sets: &[DynSet], snap: &dynsets::Snapshot) -> String;
  ```

  `DynSet` is `{ fam, set, source }`. `fill` returns `add element <fam>
  zebra_firewall <set> { … }` lines, omits empty sets, and dedups and sorts
  the elements.
- **One transaction.** The apply sends `script ‖ fill` as one `nft -f -`
  transaction. Fill lines carry `Origin::Set { fam, name }`
  ([nft-common](nft-common.md) `Script`), so `apply_loop` can exclude a bad
  dynamic set the way it excludes a bad static one. A commit therefore never
  exposes an empty dynamic set when the updater already has data.
- **Between commits**, the backend that owns the table refills only the
  changed sets: one transaction of `flush set …` plus `add element …` per
  changed set.
- **Single writer per table.** The updater never runs nft. Only the owning
  backend task writes its table, so a refill cannot race an atomic replace.
- **Rejected:**
  - *VyOS's model.* A separate writer fills the firewall table after the
    commit. That means two writers, a race with the next replace, and an
    empty window on every commit.
  - *A separate long-lived table for the dynamic sets.* nft rules can only
    reference sets in their own table.
  - *A full re-render on every DNS change.* It resets counters and `recent`
    sets (the reason for X12) and reloads the whole ruleset every interval.

**3.2 The updater, `src/dynsets.rs` (owned here; the API is proposed):**

```rust
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source { Dns(String), Url { url: String, every: Duration }, Geo(GeoKey) }
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GeoKey { Country(String), Asn(u32) }
pub struct Options { pub resolver_interval: Duration, pub resolver_cache: bool, pub geoip: GeoipOptions }
pub struct Demand { pub consumer: &'static str, pub sources: BTreeSet<Source>, pub options: Option<Options> }
pub enum Freshness { Pending, Fresh, Stale { since: SystemTime, error: String }, Failed(String), Inherited }
pub struct Entry { pub v4: Arc<[String]>, pub v6: Arc<[String]>, pub freshness: Freshness, pub updated: Option<SystemTime> }
pub struct Snapshot { pub generation: u64, pub entries: HashMap<Source, Entry> }
#[derive(Clone)]
pub struct Handle {
    pub demand: mpsc::Sender<Demand>,
    pub snapshot: watch::Receiver<Arc<Snapshot>>,
    pub cmd: mpsc::Sender<Cmd>,          // Cmd::UpdateGeoip { resp: oneshot::Sender<String> }
}
pub fn spawn(state_dir: PathBuf, geoip_mirror: Option<String>) -> Handle;
```

- **Demand.** Each consumer sends its complete source set after every
  commit, keyed by consumer name (`"firewall"`; later `"nat"`, `"pbr"`). The
  union drives the work. A source that nobody demands any more is dropped
  from the snapshot, along with the remote-group cache file of a deleted
  group.
- **Options** come from the `firewall` consumer, which owns `global-options`.
  Other consumers send `None` and inherit them; VyOS also applies one
  resolver config to firewall and NAT.
- **DNS:**
  - `tokio::net::lookup_host((name, 0))`, which is getaddrinfo with
    AF_UNSPEC. It honours `/etc/hosts` and nsswitch, as VyOS's
    `fqdn_resolve` does. Results are split by family.
  - At most 16 lookups run in parallel, each with a 5 s timeout. Lookups
    happen every `resolver-interval`, and immediately for a newly demanded
    name.
  - Failure: with `resolver-cache`, keep the entry and mark it `Stale`.
    Without it, empty the entry and mark it `Failed`. These are the VyOS
    semantics.
  - TTLs are ignored, as in VyOS.
- **URL** (§3.5) and **Geo** (§3.6) are described below.
- **Publishing.** Changes are coalesced into at most one `watch` publish per
  second. `generation` increments on every publish.

**3.3 Consumer side (firewall first).**
- **On commit:**
  1. `dyn_sets(cfg)` → `Demand`.
  2. Render, then fill from the *current* snapshot, then apply.
  3. Record `applied: HashMap<(Fam, String), Vec<String>>`, the elements
     actually loaded.
- **On `snapshot.changed()`:**
  1. Recompute the elements for the backend's own `DynSet`s.
  2. Diff them against `applied`.
  3. Send one refill transaction.
  4. Update `applied`.

  A refill that fails is logged, and `applied` is left untouched so the
  next change retries. A `No such file or directory` (the table is gone) is
  ignored.
- **X12 interplay** (`nft::apply::apply_if_changed`, [nft-common](nft-common.md);
  semantics from [fw-load-safety](fw-load-safety.md) §3.5):
  - `Applied.rendered` is the static script. `Applied.live` uses
    `nft -s -t`, which drops set contents. So refills never count as drift,
    and a resubscribe with an unchanged config skips the apply and keeps
    the kernel's members.
  - **[nft-common](nft-common.md) §3.1 carries the fill:** `Rendered` has
    `fill: String` plus `fill_origins: Vec<Origin>`. `apply_loop` and
    `apply_if_changed` send `script ‖ fill` to the runner, map diagnostics
    on fill lines to `Origin::Set` exclusions, and compare only `script`.
    Empty for every other consumer.
- **Warm start.** fw-load-safety does not persist `Applied`, so an insomnia
  restart always re-applies.
  - Before the first apply of a process, the backend reads the existing
    dynamic sets with `nft -j list table`, through
    [fw-packet-modification](fw-packet-modification.md)'s `parse_live`. It
    seeds the snapshot with them, marked `Inherited`, until fresh data
    arrives.
  - Upgrades and restarts therefore never open an empty window either. The
    same pre-apply read is the one fw-packet-modification M7 uses to carry
    `DA_` members across, so it is one read for both.
- **Negated references.** A rule such as `ip daddr != @D_x drop` matches
  *everything* while `D_x` is empty. That is the same as VyOS, but it is
  dangerous. The renderer warns once per rule, and show marks the group
  `Pending`/`Failed`.

**3.4 Sets, names and render rules** (VyOS names, so `nft list` and the log
prefixes line up):

| Source | Set | Table(s) | Flags |
|:--|:--|:--|:--|
| `group domain-group N` | `D_N` | ip and ip6 | `interval; auto-merge` (deviation: VyOS has no auto-merge) |
| rule `fqdn` | `FQDN_<hook>_<chain>_<rule>_<s\|d>`; hook ∈ forward, input, output, prerouting, name (name6 for ipv6 custom) | the rule's family | `interval; auto-merge` |
| `group remote-group N` | `R_N`, `R6_N` | ip, ip6 | `interval; auto-merge` |
| rule `geoip` | `GEOIP_CC[6]_<hook>_<chain>_<rule>_<s\|d>`, `GEOIP_ASN[6]_…` | the rule's family | `interval; auto-merge` |

- **Matchers:**
  - `fqdn !x` and `inverse-match` render `!=`;
  - `group domain-group|remote-group` follow the existing `!NAME` handling.
- **Extensions to shared code** (implemented here, in the owners' modules;
  nothing is redefined; both owners list them):
  - [nft-common](nft-common.md) §3.1: `crate::nft::group::GroupKind` gains
    `Domain` (`D_` in ip and ip6) and `Remote` (`R_`, `R6_`), rendered
    empty by `render_sets` (never in the bridge table). `matcher::endpoint`
    gains the `fqdn` and `geoip` branches, in VyOS `parse_rule` order.
  - [fw-load-safety](fw-load-safety.md) §3.2: `plan_table` registers the
    per-rule `FQDN_*` and `GEOIP_*` sets with `RefIndex::register(ObjKind::Set,
    name)`, so the pre-pass and the apply-loop exclusions see them like any
    other set. `D_`/`R_` arrive through the group part of the index. An
    undefined `domain-group` or `remote-group` reference skips the rule:
    `domain-group "X" is not defined`.
  - [commit-validation](commit-validation.md): every skip below is a
    `Findings` warning with `Effect::Skipped("rule skipped")`. Host state
    goes in `firewall::host_findings` ("curl not installed", "geoip
    database not downloaded yet"), never in `render()`.
- **Skip with warning** (VyOS verify): more than one of
  address/fqdn/geoip on a side; both asn and country-code; more than one
  address/network/domain/remote group; a set name over 255 bytes.
- **Fix (deviation): `fqdn` in prerouting and output raw** works, with sets
  declared for every hook.

**3.5 Remote groups.**
- **Fetch** with `curl --fail --silent --show-error --location --max-time 60
  --max-filesize 16M --proto =http,https -o <tmp> <url>`, as a subprocess.
- **Cache:** `/var/lib/insomnia/firewall/R_<name>.txt`, renamed into place
  only on success. This needs `StateDirectory=insomnia`.
- **Scheduling.** The first fetch for a new demand happens immediately. The
  cache is loaded first, so a reboot matches the last list before the
  network is up.
- **Retry** on failure at `min(interval, resolver-interval)`; that is
  VyOS's rule.
- **Parse:**
  - the first whitespace-separated word of each line;
  - IPv4 or IPv6 address/prefix/range goes to `v4`/`v6`;
  - any other alphanumeric first word is counted as invalid and logged
    once per fetch;
  - comments and blank lines are skipped.
- **Redaction.** URLs are redacted (userinfo, query) in logs and in show.
- **Rejected:** reqwest or hyper-rustls. That would bring an in-process TLS
  stack and CA-store handling for one feature, while curl uses the system
  trust store and proxies. Revisit if [pki-x509](pki-x509.md) brings rustls
  anyway.

**3.6 GeoIP.**
- **Providers**, as in VyOS: `db-ip` (default, monthly lite CSV, CC BY 4.0,
  so the docs carry the attribution) and `maxmind` (account id and license
  key; `maxmind-lite` selects GeoLite2).
- **Download** with curl:
  - `source-address` → `--interface <addr>`;
  - `vrf` → `ip vrf exec <vrf> curl …` (*unverified* inside BDD netns;
    fallback `curl --interface <vrf-device>`).
  - Files go to `/var/lib/insomnia/geoip/`, via a temp file, and are kept
    only if they parse to at least 1000 rows. The last good database is
    always kept.
  - DB-IP: if the current month's file returns 404, try the previous month
    (*improvement*; VyOS just fails).
- **Parse:**
  - Stream the CSV and keep only the demanded keys:
    - DB-IP country `start,end,cc`;
    - DB-IP ASN `start,end,asn,"org"`;
    - MaxMind `*-Blocks-IPv4/6.csv` `network,geoname_id` joined with
      `*-Locations-en.csv` `geoname_id → country_iso_code`, and
      `*-ASN-Blocks-*.csv` `network,autonomous_system_number`.
  - Country codes are lower-cased, as VyOS stores them.
  - A newly demanded key re-parses the file in the background; each
    entry stays `Pending` until then.
- **No sqlite** (VyOS imports into one). Only the demanded keys are held in
  memory.
- **New dependencies:** `flate2` (gzip) and `zip` (deflate only, for
  MaxMind). A minimal RFC 4180 field splitter, with tests, replaces a `csv`
  crate. Rejected: `gzip -dc` and `unzip -p` subprocesses, because `unzip`
  is not an essential Debian package.
- **No bundled database** (VyOS ships one). The first demand triggers a
  download. Until it lands, geoip sets stay `Pending`, and the commit logs
  `geoip: database not downloaded yet; rule … matches nothing` (or
  everything, for `inverse-match`).
- **Refresh:** weekly, from the last successful download plus 7 days with a
  random 0-6 h jitter, and on `update geoip`.
- **`--geoip-mirror <URL>`** (new flag): a base URL that replaces the
  provider URLs, with the same file names without the month suffix. It
  serves air-gapped sites and the BDD.
- **`update geoip`** comes through [exec-verbs](exec-verbs.md), routed to the
  firewall backend, which forwards `Cmd::UpdateGeoip`.
  - It needs a fifth verb, `update`, which exec-verbs provides for this
    plan:
    - `op_verb` accepts it;
    - an insomnia-gated `container update { container geoip { presence …; } }`
      in `exec.yang`;
    - the `EXEC_ROUTES` row `update geoip` → key `firewall`.
  - insomnia: `"firewall"` in `EXEC_TREES`, and the `ROUTES` row
    `(Exec, "/update/geoip", Backend::Firewall)`.
  - The handler runs in a spawned task and answers `Answer { text, error }`
    once the download, parse and refill finish, for example
    `GeoIP database updated (db-ip 2026-10; 3 sets refreshed)`, or with
    `error: true` and the cause.
- **Bounded calls** ([exec-verbs](exec-verbs.md) D-8):
  - DNS 5 s per name;
  - remote-group curl `--max-time 60`;
  - geoip curl `--max-time 600`;
  - parsing in `spawn_blocking`;
  - the `update geoip` answer itself bounded at 15 min. A longer run
    answers `error: true` and finishes in the background.

**3.7 Show.**
- `show firewall group` lists `domain-group` and `remote-group` after the
  static kinds:
  - Members are the live elements from `parse_live` (one per row, as
    today).
  - A status row follows, such as `(resolved 12 s ago)`, `(stale since …:
    SERVFAIL)`, `(cache from 2026-10-20 03:00)` or `(pending)`.
  - JSON adds `live-members`, `freshness` and `updated`.
- Rule views show `fqdn x`, `geoip cc jp,kr` or `geoip asn 64500` in the
  Conditions column (`rule_conditions`, `firewall.rs:369-387`).
- How [fw-opmode](fw-opmode.md) lays out `show firewall group` overall stays
  with that plan. This plan provides the rows and the freshness data.

**3.8 Deviations to record (`firewall.rs` and `dynsets.rs` module docs):**
- Dynamic sets are loaded with their current members in the commit
  transaction, and later refilled in place by the owning backend. VyOS
  refills after the commit, out of band.
- `D_` and `FQDN_` sets get `auto-merge`.
- `fqdn` works in the raw hooks.
- There is no sqlite and no bundled GeoIP database. DB-IP falls back to the
  previous month. `--geoip-mirror` exists.
- Members are inherited across insomnia restarts.

## 4. Changes

### zebra-rs

`yang/firewall.yang` (sketch):

```yang
// grouping firewall → container group
list domain-group { key name; leaf name { type string; }
  leaf-list address { ext:help "Domain name (FQDN)"; type inet:domain-name; }
  leaf description { type string { pattern '.*'; } } }
list remote-group { key name; leaf name { type string; }
  leaf url { ext:help "http:// or https:// URL of an address list"; type string; }
  leaf interval { ext:help "Refresh interval: 60-2419200 seconds or <n>[smhdw]… (default: resolver-interval)";
    type union { type uint32 { range "60..2419200"; } type string; } }
  leaf description { type string { pattern '.*'; } } }

// l3-match-v4 / l3-match-v6
leaf fqdn { ext:help "Fully qualified domain name; negate with !"; type string; }
container geoip {
  leaf-list country-code { type enumeration { enum ad; enum ae; /* … the 249 codes of VyOS geoip.xml.i:31 … */ enum zw; } }
  leaf-list asn { type uint32 { range "1..4294967294"; } }
  leaf inverse-match { type empty; } }
// … and in the l3-match `container group`:
leaf domain-group { ext:help "domain-group name; negate with !"; type string; }
leaf remote-group { ext:help "remote-group name; negate with !"; type string; }

// container global-options
leaf resolver-cache { ext:help "Keep the last resolved addresses on failure"; type empty; }
leaf resolver-interval { ext:help "Seconds between re-resolution (VyOS default: 300)";
  type uint32 { range "10..3600"; } }
container geoip {
  leaf provider { type enumeration { enum db-ip; enum maxmind; } }
  leaf maxmind-account-id { type string; }
  leaf maxmind-license-key { type string; }        // secret: secret-redaction
  leaf maxmind-lite { type empty; }
  leaf source-address { type union { type inet:ipv4-address; type inet:ipv6-address; } }
  leaf vrf { ext:dynamic "rib:vrf"; type string; } }
```

- **Notes on the sketch:**
  - Whether `inet:domain-name` is a pattern type that consumes the rest of
    the line in this CLI is *unverified*. If it is, use `string` and
    validate in the renderer.
  - The country-code enumeration gives completion. It is generated from
    VyOS's regex.
- **`yang/exec.yang`:** `update geoip`, in the `update` verb container
  from [exec-verbs](exec-verbs.md) (§3.6); `manager.rs`: the
  `update` arm in `op_verb` and the `EXEC_ROUTES` row. There is no new show
  grammar: `show firewall group` already exists.
- **Layer-1 checks** ([commit-validation](commit-validation.md)): the ranges
  above. The VyOS cross-field rules (one of address/fqdn/geoip, maxmind
  needs both keys) go to the layer-2 validator, and are skipped with a
  warning until then.
- **[secret-redaction](secret-redaction.md):** mark `maxmind-license-key` as
  secret. A `remote-group url` with userinfo should be masked too.

### insomnia

- **`src/dynsets.rs` (new):**
  - §3.2 API;
  - `dns.rs`, `url.rs` and `geo.rs` submodules, each with a pure parser:
    - `parse_list(&str) -> (Vec<String>, Vec<String>, usize /*invalid*/)`;
    - `parse_dbip_country(Read, &keys)`, `parse_dbip_asn(…)`;
    - `parse_maxmind_country(zip, &keys)`.
  - The scheduler loop is generic over a clock, for tests.
- **`src/firewall.rs`:**
  - model: `Groups.domain_group`, `.remote_group`; `Endpoint.fqdn`,
    `.geoip`; `GroupRef.domain_group`, `.remote_group`; and
    `GlobalOptions.resolver_cache`, `.resolver_interval`, `.geoip`, shared
    with [fw-global-options](fw-global-options.md), which extends the same
    struct;
  - `dyn_sets`, `fill`;
  - `process`: demand, then render, fill and apply, then `applied`;
  - `run`: a `select!` arm for `snapshot.changed()`, and the warm-start
    seed;
  - show rows.
- **`src/main.rs`:**
  - the flags `--state-dir` (default `/var/lib/insomnia`) and
    `--geoip-mirror`;
  - `dynsets::spawn`, with the `Handle` passed to `firewall::run`.
- **`src/provider.rs`:** the `ROUTES` row `(Exec, "/update/geoip",
  Backend::Firewall)` and `"firewall"` in `EXEC_TREES`
  ([exec-verbs](exec-verbs.md)).
- **Packaging:**
  - `insomnia.service` gains `StateDirectory=insomnia`;
  - `recommends += curl`.
- **`Cargo.toml`:** `flate2`, `zip` (`default-features = false, features =
  ["deflate"]`).

**Worked example.**

```text
set firewall global-options resolver-interval 60
set firewall group domain-group UPDATES address updates.example.net
set firewall group remote-group DROPLIST url https://lists.example.org/drop.txt
set firewall ipv4 forward filter rule 5 action drop
set firewall ipv4 forward filter rule 5 source group remote-group DROPLIST
set firewall ipv4 forward filter rule 10 action accept
set firewall ipv4 forward filter rule 10 protocol tcp
set firewall ipv4 forward filter rule 10 destination port 443
set firewall ipv4 forward filter rule 10 destination group domain-group UPDATES
set firewall ipv4 forward filter rule 20 action accept
set firewall ipv4 forward filter rule 20 destination fqdn mirror.example.net
set firewall ipv4 input filter rule 30 action drop
set firewall ipv4 input filter rule 30 protocol tcp
set firewall ipv4 input filter rule 30 destination port 22
set firewall ipv4 input filter rule 30 source geoip country-code jp
set firewall ipv4 input filter rule 30 source geoip inverse-match
```

**The snapshot:**
- `updates.example.net` → 192.0.2.80, 192.0.2.81, 2001:db8::80;
- `mirror.example.net` → 198.51.100.20;
- `drop.txt` → `203.0.113.0/24`, `203.0.113.7`;
- jp → `1.0.0.0-1.0.0.255`, `1.0.4.0-1.0.7.255` (a fixture).

**The static part** (ipv4 table; `render` output, sets empty):

```nft
table ip zebra_firewall {
    set D_UPDATES {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set R_DROPLIST {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set FQDN_forward_filter_20_d {
        type ipv4_addr
        flags interval
        auto-merge
    }
    set GEOIP_CC_input_filter_30_s {
        type ipv4_addr
        flags interval
        auto-merge
    }
    chain ZEBRA_FORWARD_filter {
        type filter hook forward priority filter; policy accept;
        ip saddr @R_DROPLIST counter drop comment "ipv4-FWD-filter-5"
        meta l4proto tcp tcp dport {443} ip daddr @D_UPDATES counter accept comment "ipv4-FWD-filter-10"
        ip daddr @FQDN_forward_filter_20_d counter accept comment "ipv4-FWD-filter-20"
        counter accept comment "FWD-filter default-action accept"
    }
    chain ZEBRA_INPUT_filter {
        type filter hook input priority filter; policy accept;
        meta l4proto tcp tcp dport {22} ip saddr != @GEOIP_CC_input_filter_30_s counter drop comment "ipv4-INP-filter-30"
        counter accept comment "INP-filter default-action accept"
    }
}
```

The ip6 table holds an empty `D_UPDATES` of `type ipv6_addr`, because
domain-group sets exist in both tables. The matcher order follows today's
`render_rule`: protocol, then destination before source, and within a side
address, mac, port, group. `fqdn` and `geoip` slot in right after
`address`, as in VyOS `parse_rule` (`python/vyos/firewall.py:196-264`).

**The fill, appended to the same transaction:**

```nft
add element ip zebra_firewall D_UPDATES { 192.0.2.80, 192.0.2.81 }
add element ip6 zebra_firewall D_UPDATES { 2001:db8::80 }
add element ip zebra_firewall FQDN_forward_filter_20_d { 198.51.100.20 }
add element ip zebra_firewall R_DROPLIST { 203.0.113.0/24, 203.0.113.7 }
add element ip zebra_firewall GEOIP_CC_input_filter_30_s { 1.0.0.0-1.0.0.255, 1.0.4.0-1.0.7.255 }
```

**A later refill** (DNS answer changed to 192.0.2.82, AAAA gone):

```nft
flush set ip zebra_firewall D_UPDATES
add element ip zebra_firewall D_UPDATES { 192.0.2.82 }
flush set ip6 zebra_firewall D_UPDATES
```

The static table above plus the fill passes `nft -c` verbatim, with the
add/delete prologue and the ip6 `D_UPDATES` set added. An equivalent script
was applied, then refilled, in a scratch netns. The kernel lists
`R_DROPLIST` as `{ 203.0.113.0/24 }` (merged) and the geoip set as
`{ 1.0.0.0/24, 1.0.4.0/22 }`.

**`show firewall group` (excerpt):**

```
 Name                 Type                 References  Members
 ----                 ----                 ----------  -------
 UPDATES              domain-group                  1  192.0.2.80
                                                       192.0.2.81
                                                       2001:db8::80
                                                       (resolved 12s ago)
 DROPLIST             remote-group                  1  203.0.113.0/24
                                                       (fetched 2026-10-21 03:00; 1 invalid line)
```

## 5. Tests

**Unit and golden tests** (no network, nft or curl):

| Test | Asserts |
|:--|:--|
| `firewall::tests::golden_dynamic_sets` | The static script above (both tables); `dyn_sets` lists the five sets with their sources |
| `fill_from_snapshot` | The fill above; empty entries produce no line; elements sorted and deduped |
| `refill_diff` | Only changed sets are flushed; an emptied set gets `flush` with no `add` |
| `negated_dynamic_ref_warns` | `!=` against `D_`/`GEOIP_` → one warning per rule |
| `fqdn_in_prerouting_raw` | `FQDN_prerouting_raw_<n>_s` declared and referenced |
| `one_of_address_fqdn_geoip` | Two on one side → rule skipped; warning |
| `undefined_domain_group_skips_rule` | Through the X2 `GroupIndex` |
| `x12_ignores_fill` | The fw-load-safety truth table holds with a non-empty fill |
| `dynsets::url::parse_list` | IPv4/IPv6 address/prefix/range; `#` comments; invalid count |
| `dynsets::geo::dbip_country_fixture`, `dbip_asn_fixture` | Quoted org with commas; v4/v6 split; key filter |
| `maxmind_country_fixture` | Blocks + Locations join; unknown geoname skipped |
| `dynsets::schedule` | `tokio::time::pause`: DNS every interval; URL retry at `min(interval, resolver-interval)`; geoip weekly plus jitter bounds; dropped demand removes entries and cache files |
| `resolver_cache_semantics` | Failure with/without cache → `Stale` keeps / `Failed` empties |
| `url_redaction` | `https://u:p@h/x?k=v` → `https://h/x` |

**BDD feature `@fw_dynamic`.** It reuses the generic node
script: `insomnia_node.sh` in [fw-load-safety](fw-load-safety.md) M5, which
[nat](nat.md) and [commit-validation](commit-validation.md) call
`insomnia_node.sh`. It is one script, under whichever name lands first. This
plan extends it to bind-mount a per-node `/etc/hosts` inside its private
mount namespace.
- **Topology:** `h1` — `r1` — `srv`. `srv` runs `python3 -m http.server`,
  serving `drop.txt` and `geoip/` (a fixture `dbip-country-lite.csv.gz` that
  maps h1's subnet to `jp`). `r1` uses `--geoip-mirror http://<srv>/geoip/`.
- **Scenarios:**
  1. Setup.
  2. A domain group: rewrite r1's hosts file. Within the interval
     (`resolver-interval 10`), `nft list set ip zebra_firewall D_UPDATES`
     shows the new address; curl from h1 to the old one fails.
  3. A remote group blocks h1. Then stop the HTTP server and commit an
     unrelated change: h1 stays blocked (cache).
  4. GeoIP: `ping` from h1 to r1 fails with `country-code jp`. After
     `update geoip` with a changed fixture, it succeeds.
  5. Restart insomnia: right after the restart, `D_UPDATES` is non-empty
     (warm start).
  6. Teardown topology.

## 6. Docs

- **Book:**
  - `ch-01-04-groups.md`: replace the "not implemented" note
    (`ch-01-04-groups.md:70`) with domain, remote and geoip sections,
    including the negation hazard and the DB-IP attribution;
  - `ch-01-02-match-criteria.md`: `fqdn` and `geoip`;
  - `ch-00-03-command-line-options.md`: `--state-dir` and
    `--geoip-mirror`;
  - `ch-03-00-show-firewall.md`: the group freshness rows.
- **Module docs:** the §3.8 deviations; `dynsets.rs` describes the consumer
  contract (demand, single writer per table, refill).
- **AGENTS.md "Backend shape":** "dynamic sets: declared empty, filled by
  `fill` in the same transaction, refilled by the owning task".

## 7. Milestones

| # | Scope | Repo | Effort | Done when |
|:--|:--|:--|:--|:--|
| M1 | `dynsets` core (demand, snapshot, scheduler; DNS source), `dyn_sets`/`fill`/refill and the warm-start seed in the firewall, plus the fw-load-safety fill hook | insomnia | M | `fill_*`, `refill_diff`, `x12_ignores_fill`, `schedule` pass against a fake DNS |
| M2 | Schema: `domain-group`, `fqdn`, `group domain-group`, `resolver-cache`, `resolver-interval` | zebra-rs | S | Schema tests; JSON shapes captured as fixtures |
| M3 | FW10 end to end: `GroupKind::Domain`, the fqdn matcher, show rows | insomnia | S | `golden_dynamic_sets` (domain/fqdn part); BDD scenarios 1, 2 and 5 |
| M4 | Schema: `remote-group`, `group remote-group` | zebra-rs | S | Schema tests |
| M5 | FW14: URL source, curl, the disk cache, `StateDirectory`, `GroupKind::Remote` | insomnia | M | `parse_list`, `url_redaction`; BDD scenario 3 |
| M6 | Schema: rule `geoip`, `global-options geoip`; the `maxmind-license-key` secret flag; the `update geoip` verb | zebra-rs | S | Schema tests |
| M7 | FW11: download (db-ip, maxmind, mirror), parsers, key filter, weekly refresh, geoip sets | insomnia | L | Parser fixtures; `golden_dynamic_sets` complete |
| M8 | `update geoip` via [exec-verbs](exec-verbs.md) | both | S | BDD scenario 4 |
| M9 | Book, module docs, AGENTS.md, CHANGELOG | insomnia | S | `mdbook build` clean |

M1 has to land before any consumer. [nat](nat.md) and [pbr](pbr.md) become
consumers after M3 and M7 by sending their own `Demand` and filling their own
tables.

## 8. Risks and open questions

- **Agreed with other plans** (recorded on their side):
  - [nft-common](nft-common.md) §3.1: the uncompared `fill` section in
    `Rendered`, `apply_loop` and `apply_if_changed` (§3.3), and the
    `Domain`/`Remote` group kinds and fqdn/geoip matcher branches as
    extensions implemented here.
  - [fw-load-safety](fw-load-safety.md) §3.2: `RefIndex::register` with
    `ObjKind::Set` for the per-rule `FQDN_`/`GEOIP_` sets.
  - [exec-verbs](exec-verbs.md): the `update` verb (`op_verb`, the
    `container update`, and the `EXEC_ROUTES` row `update geoip` →
    `firewall`).
- **Requirements on other plans:**
  - [fw-packet-modification](fw-packet-modification.md): `parse_live` must
    expose interval elements, both `a-b` ranges and prefixes, not only the
    timeout members.
  - [secret-redaction](secret-redaction.md): the two secret leaves.
- **CDN names** rotate faster than `resolver-interval`, so the set lags. That
  is the same as VyOS. Document it, and recommend domain groups for allow
  lists, not deny lists.
- **Negation.** A negated dynamic reference on an empty set matches
  everything. Open: should insomnia refuse `!=` on a dynamic set while it is
  `Pending`, instead of warning? Recommendation: warn, for VyOS parity.
- **The resolver** runs in insomnia's netns and default VRF. There is no
  per-VRF DNS, the same as VyOS.
- **GeoIP size.** Very large sets ("all ASNs of a big carrier") are bounded
  only by memory and nft load time. The measured 60k ranges in 0.13 s leave
  plenty of headroom. Warn above 500k elements per set.
- **Licences.** The DB-IP lite licence (CC BY 4.0) needs attribution; that
  goes in the book and in the `show firewall group` footer for geoip.
  MaxMind requires an account, and GeoLite2's EULA is the user's to accept.
- **`curl` absent.** Remote groups and geoip log `curl not installed` and
  stay on cache. Recommends, not Depends, because the firewall works
  without them.

## 9. Acceptance criteria

- [ ] Domain groups, fqdn, remote groups and geoip render, fill and match
      in BDD.
- [ ] No commit, resubscribe or insomnia restart exposes an empty dynamic
      set when data existed.
- [ ] Refills touch only changed sets and never reset rule counters.
- [ ] Only the owning backend writes its table (code review).
      `dynsets.rs` has no nft call.
- [ ] Remote groups survive fetch failures and reboots through the cache.
      Credentials never appear in logs or show.
- [ ] `update geoip` answers with a result. Weekly refresh runs.
- [ ] `show firewall group` shows live members and freshness.
- [ ] Goldens, parsers and schedule tests pass. clippy and fmt are clean.

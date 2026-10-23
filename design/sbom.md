# Software Bill of Materials (SBOM)

- **Status:** draft.
- **Snapshot:** 2026-10-22, arm64, `SUITE=noble`.
- **Scope:** the zebra-live ISO (built by folksy-rs `contrib/mkiso`), the `zebra-rs`, `cradle-rs`
  and `insomnia` packages, and every library compiled into them.

This document does four things:
- sets the rules for what we ship (§1);
- records what the ISO contains today, down to the libraries inside our binaries (§2–§3,
  Appendices A–C);
- lists the problems found while taking that inventory (§4);
- proposes how to shrink the image (§5), keep the inventory current (§6) and get fixes onto
  routers (§7).

Contents:

1. [Principles](#1-principles)
2. [What we ship](#2-what-we-ship)
3. [Inventory snapshot](#3-inventory-snapshot-2026-10-22)
4. [Findings](#4-findings)
5. [Minimizing](#5-minimizing)
6. [Tracking](#6-tracking)
7. [Patching](#7-patching)
8. [Roadmap](#8-roadmap)
- [Appendix A: ISO packages](#appendix-a-iso-packages)
- [Appendix B: Rust crates](#appendix-b-rust-crates)
- [Appendix C: Adding insomnia to the ISO](#appendix-c-adding-insomnia-to-the-iso)
- [Appendix D: Reproducing this snapshot](#appendix-d-reproducing-this-snapshot)

---

## 1. Principles

Security is the top priority. Every component we ship is attack surface and a patch obligation,
so the rules are:

- **P1. Ship as little as possible.** A component goes into the image only when we can name what
  needs it. The image is defined by an allowlist with a reason for each entry. Anything not on
  the list fails the build.
- **P2. Know exactly what we ship.** For any release we must be able to answer "do we ship X,
  which version, from where" from a file in minutes, without logging into a router.
- **P3. One trusted source per layer:**
  - the OS comes from the Ubuntu archive (`main`);
  - Rust code comes from crates.io;
  - first-party code comes from our own repositories.

  Every exception is listed by name, with an owner: a git dependency, vendored C, a CDN script,
  a `universe` package.
- **P4. Pinned inputs.** Rebuilding a release gives the same component list. That means:
  - `Cargo.lock` is committed and used with `--locked`;
  - the toolchain is pinned;
  - the archive state is pinned.
- **P5. Generated, not hand-written.** The SBOM comes out of the build, from the dpkg database
  and Cargo metadata. The only hand-kept part is the short list of third-party code we build
  from source outside those two systems.
- **P6. Patched means shipped.** A fix counts only once it is in a released image. "The archive
  has the fix" does not count; finding S1 is exactly that gap.
- **P7. If we build it, we patch it.** Some third-party code has no distribution behind it
  because we compile it ourselves: bash in `vty`, mimalloc, ring, the forked crates. We watch
  its upstream ourselves.

## 2. What we ship

The product is `zebra-live-arm64.iso`. folksy-rs `contrib/mkiso/mkiso.sh` builds it rootless, in
the stages rootfs, install, configure, finalize, extract, squashfs and iso. The disk installer
(`zebra-install`) copies the same squashfs onto an ext4 root, so an installed router starts with
exactly the ISO's contents.

| Layer | Contents | Built by | Fixes come from | Visible in |
|---|---|---|---|---|
| L0 base OS | Ubuntu 24.04 debstrap: Essential/required plus the Priority: important set (`ubuntu-minimal`) | Canonical | Ubuntu Security Notices (USN) | dpkg database |
| L1 OS add-ons | packages named in `mkiso.sh`: kernel, live-boot, Kea DHCP, GRUB EFI, installer tools | Canonical | USN | dpkg database |
| L2 our packages | `zebra-rs`, `cradle-rs`; `insomnia` not yet | us | our releases | dpkg database (name and version only) |
| L3 inside our packages | Rust crates and the Rust standard library (statically linked), vendored C, browser JavaScript | upstream authors, compiled by us | upstream, then a rebuild by us | Cargo metadata plus a hand-kept list |
| Build tools (not shipped) | folksy-rs, rustc/cargo, cargo-deb, protoc, bpf-linker, grub-mkrescue, xorriso, mksquashfs, GitHub Actions | various | various | not tracked yet |

dpkg cannot see L3. `dpkg -l` shows `zebra-rs 26.10.2` but not the 216 third-party crates compiled into it.
A generic image scanner misses them as well, unless the binaries carry their dependency list
(§6.2).

## 3. Inventory snapshot (2026-10-22)

### 3.1 How it was taken

- **Fresh build:** `mkiso.sh rootfs install` ran on 2026-10-22 with default settings
  (`SUITE=noble ARCH=arm64 UPDATES=1 FIRMWARE=0 SSH=0`) against `ports.ubuntu.com`.
- **Our debs:** the script picks up `zebra-rs_26.10.2_arm64.deb` and `cradle-rs_1.1.9_arm64.deb` by
  default.
- **Why this equals the ISO:** the later stages install nothing, so the dpkg database after
  `install` is what the ISO contains.
- **The last real ISO was not used:** it is folksy-rs `tmp-mkiso/zebra-live-arm64.iso`, built
  2026-08-18 with zebra-rs 26.8.1, cradle-rs 0.9.9 and 261 packages. It predates the installer
  packages. It has the same stale base versions (S1): libc6, libssl3t64, sudo, libxml2, libpam0g
  and zlib1g are all release-pocket versions.
- **Rust crate lists:** from `cargo tree` on today's source trees, for `aarch64-unknown-linux-gnu`.
  The trees are zebra-rs `main` at 26.10.3, cradle-rs 1.1.9 and insomnia 0.2.0. For zebra-rs
  this only approximates what is inside the 26.10.2 deb; S5 explains why.

Appendix D has the commands.

### 3.2 Summary

| Item | Value |
|---|---|
| Base | Ubuntu 24.04 LTS (noble), arm64 |
| Kernel | `linux-image-6.8.0-147-generic` 6.8.0-147.147 |
| Installed packages | 279: 273 main, 4 universe, 2 local; 685 MiB installed |
| … by how they got there | 90 required, 127 important, 13 named in `mkiso.sh`, 27 dependencies, 22 only through Recommends |
| Packages behind the archive | 108, of which **52 have the newer version in `noble-security`** (S1) |
| Our packages | zebra-rs 26.10.2, cradle-rs 1.1.9 (insomnia 0.2.0 is not in the ISO) |
| Third-party Rust crates linked in | 282 name+version pairs (260 names): zebra-rs 216, cradle-rs 158, insomnia 83 |
| First-party crates | zebra-rs 14, cradle-rs 4, insomnia 1 |
| Build-time-only crates | zebra-rs 78 (plus 3 first-party proc-macro crates), cradle-rs 52, insomnia 35 |
| Git (non-crates.io) crates | 3, all in zebra-rs (S6) |
| Third-party code built outside Cargo | GNU bash 5.3 with readline 8.3, as `vty` (S2) |
| C bundled inside crates | mimalloc 3.3.2 (`libmimalloc-sys` 0.1.49, zebra-rs); ring 0.17.14 (BoringSSL-derived C and assembly, `cradle-k8s` only) |
| Code loaded at run time from the network | three.js 0.160.0 and globe.gl 2.32.0 from unpkg.com, SRI-pinned (`zebra-topology` web page) |

### 3.3 Ubuntu packages

Appendix A.1 has the full list, with the pocket each version comes from and the pending update.

**Named in `mkiso.sh` and not already in the base (13):**

| Package | Version |
|---|---|
| linux-image-6.8.0-147-generic | 6.8.0-147.147 |
| linux-modules-extra-6.8.0-147-generic | 6.8.0-147.147 |
| initramfs-tools | 0.142ubuntu25.8 |
| live-boot | 1:20230131 |
| kea-dhcp4-server | 2.4.1-3ubuntu0.2 |
| kea-dhcp6-server | 2.4.1-3ubuntu0.2 |
| grub2-common | 2.12-1ubuntu7.3 |
| grub-efi-arm64-bin | 2.12-1ubuntu7.3 |
| efibootmgr | 18-1build2 |
| dosfstools | 4.2-1.1build1 |
| fdisk | 2.39.3-9ubuntu6.6 |
| zebra-rs | 26.10.2 |
| cradle-rs | 1.1.9 |

`mkiso.sh` also names systemd-sysv, udev, dbus, kmod, iproute2, iputils-ping, libcap2-bin and
less, but the base already has them.

**Universe (4):** live-boot, live-boot-initramfs-tools, live-boot-doc (all 1:20230131) and
live-tools 1:20190831.1.
- These are community-maintained, outside Canonical's security commitment for `main` (S9).
- live-boot runs in the initramfs and mounts the root filesystem, so it is in the boot path.

**Largest installed:**

| Package | Size | Why it is there |
|---|---|---|
| linux-modules-extra | 116 MiB | needed only for `vrf.ko` and `mpls_iptunnel.ko` on noble |
| linux-modules | 83 MiB | kernel modules |
| zebra-rs | 45 MiB | our package |
| libicu74 | 35 MiB | only for libxml2, which only shared-mime-info needs |
| cradle-rs | 34 MiB | our package |
| iso-codes | 20 MiB | a Recommends of python3-apt |

**Two shells:** the image has two bash builds.
- Ubuntu's `bash` 5.2.21 provides `/bin/bash`, and Canonical patches it.
- Our `vty` is bash 5.3, and we patch it (S2).

### 3.4 Our packages

| Package | In the ISO | Latest | Binaries | Shared libraries linked |
|---|---|---|---|---|
| zebra-rs | 26.10.2 (local build, 2026-10-18) | 26.10.3 (tag `v26.10.3`, 2026-10-19) | `zebra-rs`, `vtyctl`, `vtyhelper`, `zebra-topology`, `vtypam`, `vty` | libc, libm, libgcc_s; `vtypam` adds libpam; `vty` links libtinfo and libc only |
| cradle-rs | 1.1.9 | 1.1.9 | `cradle`, `cradle-cni`, `cradle-k8s` | libc, libm, libgcc_s |
| insomnia | not in the ISO | 0.2.0 | `insomnia` | libc, libm, libgcc_s |

Package relationships:
- **zebra-rs:** Depends on `libc6, libpam0g, libtinfo6`; Recommends `cradle-rs (>= 1.1.9)`.
- **cradle-rs:** Depends on `libc6`.
- **insomnia:** Depends on `libc6, nftables`; Recommends `strongswan-swanctl, charon-systemd,
  keepalived`; Suggests `zebra-rs`.

Our Rust binaries link nothing but glibc and libgcc_s dynamically. Everything else is compiled
in:
- TLS: rustls and ring, in `cradle-k8s`;
- gRPC and HTTP/2: tonic, hyper, h2;
- JSON and YAML parsing;
- hashing and MACs: RustCrypto md-5, sha1, sha2, hmac and chacha20, in zebra-rs.

So an Ubuntu security update to OpenSSL or zlib does not touch our binaries. A RustSec
advisory against one of these crates needs a rebuild and a release by us.

### 3.5 Third-party code outside dpkg and crates.io

| Component | Version | Where | How it gets in | Upstream to watch |
|---|---|---|---|---|
| GNU bash and readline | bash 5.3, patch level 0; readline 8.3 | `/usr/bin/vty` | zebra-rs `vty/Makefile` downloads `bash-5.3.tar.gz` (SHA-256 pinned) and applies `0001-vty-hooks.patch` | `ftp.gnu.org/gnu/bash/bash-5.3-patches/`: 20 patches as of 2026-10-22 |
| mimalloc | 3.3.2 | `zebra-rs` (global allocator) | C sources bundled in `libmimalloc-sys` 0.1.49 | microsoft/mimalloc, `libmimalloc-sys` |
| ring | 0.17.14 | `cradle-k8s` (rustls) | C and assembly derived from BoringSSL, bundled in the crate | briansmith/ring, RustSec |
| three.js, globe.gl | 0.160.0, 2.32.0 | `zebra-topology` web page | loaded by the viewer's browser from unpkg.com, `integrity="sha384-…"` | npm advisories |
| Rust standard library | the compiler's | every Rust binary | statically linked | Rust security advisories |
| eBPF programs | first-party | `cradle` | built with bpf-linker 0.10.3 and `nightly-2026-07-23` | — |
| YANG modules | IETF, IANA, OpenConfig revisions | `/usr/share/zebra-rs/yang` | copied files, data only | — |

### 3.6 insomnia (not in the ISO yet)

Appendix C has the full list. Adding `insomnia` with its recommended backends adds 30 packages,
or 25 without Recommends:
- **strongSwan 5.9.13-2ubuntu4.24.04.5:** `charon-systemd` and `strongswan-swanctl` are `universe`
  binaries built from the `main` strongswan source.
- **keepalived 1:2.2.8-1build2:** it is linked against net-snmp (`libsnmp40t64`), which brings
  libperl 5.38, libsensors and libpci.
- **nftables 1.0.9-1ubuntu0.1** with its libraries.

### 3.7 Build supply chain (not shipped, but trusted)

- **Image builder:** folksy-rs (a private repository) builds the rootfs. It trusts the build host's
  `/usr/share/keyrings/ubuntu-archive-keyring.gpg`.
- **Archive access:** the image is fetched over plain HTTP from `ports.ubuntu.com`. Integrity comes
  from the signed `InRelease` files.
- **Our debs:** the newest `../zebra-rs/packaging/zebra-rs_*_arm64.deb` by `sort -V` (and the same
  for cradle-rs). No checksum is taken and no version is recorded (S7).
- **Toolchains** (S11):
  - zebra-rs and insomnia CI use the floating stable channel; this build host has rustc 1.99.1.
  - cradle-rs pins `nightly-2026-07-23` in `rust-toolchain.toml`.
  - cargo-deb is pinned in zebra-rs and insomnia, but not in cradle-rs.
  - bpf-linker 0.10.3; protoc comes from Ubuntu.
- **GitHub Actions** are referenced by major tag (`@v1`, `@v5`, `@v7`), not by commit.

## 4. Findings

| ID | Severity | Finding | Owner |
|---|---|---|---|
| S1 | **High** | The ISO ships 52 packages whose fixes are already in `noble-security`, including OpenSSL, glibc, sudo, PAM and libxml2 | folksy-rs |
| S2 | **High** | `vty` is bash 5.3 without its 20 upstream patches, several of them memory-safety fixes | zebra-rs |
| S3 | Medium | Recommends are installed although `mkiso.sh` assumes they are not; 22 packages come in only that way | folksy-rs |
| S4 | Medium | The base layer is `ubuntu-minimal`: Python, netplan, sudo, rsyslog, the Pro client and more; 89 packages can go | folksy-rs |
| S5 | Medium | zebra-rs does not commit `Cargo.lock`, so a release's crate list is unrecorded and unreproducible | zebra-rs |
| S6 | Medium | Three crates come from git, two of them tracking a branch | zebra-rs |
| S7 | Medium | The ISO takes our debs from a local build directory, with no version pin or checksum; it has zebra-rs 26.10.2 while 26.10.3 is released | folksy-rs |
| S8 | Medium | No repository scans for vulnerabilities or produces an SBOM | all |
| S9 | Low | The boot path (live-boot) and two strongSwan binaries are `universe` | folksy-rs |
| S10 | Low | Kea is installed and enabled but nothing configures it, and it pulls in MySQL, PostgreSQL, LDAP and Kerberos client libraries | folksy-rs |
| S11 | Low | Floating stable toolchain, nightly compiler for cradle-rs, Actions pinned by tag, unpinned cargo-deb in cradle-rs, no `--locked` | all |
| S12 | Low | Demo and Kubernetes binaries ship inside the router packages | zebra-rs, cradle-rs |
| S13 | Low | Rust dependency hygiene: duplicate versions, archived `serde_yaml`, gRPC server code in a client-only binary | all |

### S1. Known-fixed vulnerabilities in the image (High)

**Evidence.** In the freshly built rootfs, `apt-get -s dist-upgrade` reports `108 upgraded, 1
newly installed`. For 52 of the 108, the newer version is in `noble-security`. Examples:

| Package | In the ISO | Fixed in noble-security |
|---|---|---|
| libssl3t64, openssl | 3.0.13-0ubuntu3 | 3.0.13-0ubuntu3.16 |
| libc6, libc-bin, locales | 2.39-0ubuntu8 | 2.39-0ubuntu8.9 |
| sudo | 1.9.15p5-3ubuntu5 | 1.9.15p5-3ubuntu5.24.04.4 |
| libpam0g, libpam-modules, libpam-runtime | 1.5.3-5ubuntu5 | 1.5.3-5ubuntu5.7 |
| libxml2 | 2.9.14+dfsg-1.3ubuntu3 | 2.9.14+dfsg-1.3ubuntu3.10 |
| libgnutls30t64 | 3.8.3-1.1ubuntu3 | 3.8.3-1.1ubuntu3.6 |
| python3.12 | 3.12.3-1 | 3.12.3-1ubuntu0.17 |
| libsqlite3-0 | 3.45.1-1ubuntu2 | 3.45.1-1ubuntu2.8 |
| libexpat1 | 2.6.1-2build1 | 2.6.1-2ubuntu0.6 |
| zlib1g | 1:1.3.dfsg-3.1ubuntu2 | 1:1.3.dfsg-3.1ubuntu2.3 |
| liblzma5 | 5.6.1+really5.4.5-1 | 5.6.1+really5.4.5-1ubuntu0.4 |
| tar | 1.35+dfsg-3build1 | 1.35+dfsg-3ubuntu0.4 |
| vim-tiny | 2:9.1.0016-1ubuntu7 | 2:9.1.0016-1ubuntu7.20 |
| ca-certificates | 20240203 | 20260816ubuntu0.24.04.1 |
| tzdata | 2024a-2ubuntu1 | 2026e-0ubuntu0.24.04.1 |

Appendix A.1 has the full list in its Pending column. The 2026-08-18 ISO has the same old
versions.

**Cause.**
1. folksy-rs `debstrap` installs from the `noble` release pocket only.
2. `do_install` then adds `noble-updates` and `noble-security` and runs `apt-get update`.
3. But only `apt-get install` follows. That upgrades a package only when a newly requested
   package needs a newer version, which happened to 36 packages.
4. The other 108 stay at their April 2024 release versions.

**Fix.**
- Run `apt-get -y dist-upgrade` right after `apt-get update` in `do_install`. It has to be
  `dist-upgrade`: plain `upgrade` holds back updates that need new packages, and this one adds
  `ethtool`.
- Add a gate after the install stage: `apt-get -s dist-upgrade` must print `0 upgraded, 0
  newly installed`, otherwise the build fails.
- `UPDATES=0` then produces a known-stale image. Mark such an image as non-release, for example
  in the volume ID.

### S2. `vty` is unpatched bash 5.3 (High)

**Evidence.**
- zebra-rs `vty/Makefile` fetches `bash-5.3.tar.gz`, checks its SHA-256, and applies only our
  `patches/0001-vty-hooks.patch`.
- Upstream has published `bash53-001` to `bash53-020`.
- Several of those are memory-safety fixes:

| Patch | Fix |
|---|---|
| 005 | crash when restoring the default disposition of a specially handled signal in a subshell |
| 009 | segmentation fault from data freed by a signal handler, after SIGINT during a reverse i-search (interactive line editing, exactly what CLI users do) |
| 011, 014 | a `mapfile` callback can make bash use freed memory |
| 015 | index −1 used into the `read` builtin's input buffer |

`vty` is the interactive shell every operator uses. Ubuntu cannot help here: its own bash
package is 5.2, a different release line.

**Fix.**
1. Download the official patches as pinned files, each with a SHA-256 like the tarball.
2. Apply them in order, before `0001-vty-hooks.patch`; the hooks patch may need a rebase.
3. Record the patch level in the SBOM, for example `bash 5.3.20`.
4. Watch the patches directory (§7.1).

### S3. Recommends are installed (Medium)

**Evidence.**
- Inside the image, `apt-config dump` shows `APT::Install-Recommends "1"`.
- folksy-rs `debstrap` writes `etc/apt/apt.conf.d/00debstrap` with `Apt::Install-Recommends
  false`.
- But `apt::cleanup` deletes that file before debstrap returns (`src/apt.rs:323`).
- `mkiso.sh` and its README both assume the opposite: "the debstrap rootfs has
  Install-Recommends false".

Packages present only because of a Recommends (22): flash-kernel, u-boot-tools, mtd-utils,
device-tree-compiler, devio, libfdt1, libubootenv-tool, libubootenv0.1, os-prober, rsync,
live-boot-doc, live-tools, sbsigntool, secureboot-db, grub-efi-arm64, grub-efi-arm64-signed,
uuid-runtime, libiniparser1, liblzo2-2, libldap-common, libsasl2-modules, zstd.

**Fix.**
- Pass `--no-install-recommends` to every `apt-get install` in `mkiso.sh`. An explicit flag beats
  relying on a configuration file.
- Write `/etc/apt/apt.conf.d/99zebra-no-recommends` into the image, so apt on an installed
  system behaves the same way.
- Keep two of them by naming them explicitly:
  - `zstd`: `initramfs-tools` compresses with zstd and falls back to gzip without it.
  - `grub-efi-arm64-signed`: if Secure Boot is wanted.

### S4. The base is `ubuntu-minimal`, not a router base (Medium)

**Evidence.** debstrap installs the Priority: important set, which is `ubuntu-minimal` and its
dependencies: 127 packages. Among them:
- the Python 3.12 runtime and its `python3-*` modules (`python3-apt`, `-yaml`, `-gi`, `-dbus`,
  `-rich`, `-pygments`, …);
- `netplan.io`, `netplan-generator`, `libnetplan1` and `networkd-dispatcher` (zebra-rs configures
  interfaces, not netplan);
- `ubuntu-pro-client`, which also adds an apt hook, `20apt-esm-hook.conf`;
- `rsyslog` and `logrotate` (journald already logs);
- `sudo`, `vim-tiny`, `xxd`, `whiptail`;
- `locales`, `console-setup`, `keyboard-configuration`, `kbd`, `xkb-data`;
- `systemd-resolved`, `netcat-openbsd`, `lsb-release`, `distro-info`, `ca-certificates`, the
  `openssl` CLI;
- `libxml2` with `libicu74`, and `iso-codes`.

**Simulation.** In the built rootfs:
1. Mark everything auto-installed.
2. Mark manual only Essential/required, the packages `mkiso.sh` names, `apt` and `zstd`.
3. Run `autoremove` with Recommends and Suggests not treated as important.

Result: 89 packages and 140 MiB go, and 190 packages remain. Python stays only because
Ubuntu's `grub-common` depends on `python3` and `python3-apt`. GRUB is there for the disk
installer.

**Decisions needed before dropping:**
- **Time sync:** a router needs it. Keep `systemd-timesyncd`, or let zebra-rs manage an NTP
  client.
- **`ca-certificates`:** only needed if something verifies public TLS certificates.
  `cradle-k8s` uses the cluster CA from its kubeconfig.
- **`sudo`:** whether operators need it, given `vtypam`.

**Fix.** Give folksy-rs `debstrap` a `--variant minbase` option that installs Essential and
required only. Then name in `mkiso.sh` what we actually need.

### S5. zebra-rs does not commit `Cargo.lock` (Medium)

**Evidence.** zebra-rs `.gitignore` excludes `Cargo.lock`; cradle-rs, insomnia and folksy-rs commit
theirs. As a result:
1. **No record:** the crate list inside a released zebra-rs deb is recorded nowhere. The 26.10.2
   deb in the ISO was built from whatever lock file that machine had at the time.
2. **No reproducibility:** each CI build resolves the newest semver-compatible versions on the
   day, so two builds of the same tag can differ. A broken or malicious new crate release
   enters the next build without any diff to review.
3. **Floating git dependencies:** branch-tracking git dependencies (S6) move silently.

On top of that, no packaging Makefile passes `--locked`, so even a committed lock file can be
rewritten during a build.

**Fix.**
- Commit `Cargo.lock`.
- Build with `cargo build --release --locked` in every packaging Makefile and CI job.
- Dependency updates then become reviewed PRs: the `cargo update` diff.

### S6. Git dependencies (Medium)

| Crate | Source | Pin |
|---|---|---|
| netlink-packet-route 0.20.1 | `github.com/zebra-rs/netlink-packet-route`, branch `seg6` | floating (b03a7385 today) |
| rtnetlink 0.14.1 | `github.com/zebra-rs/rtnetlink` | `rev = 2d7b1830` |
| nom-derive 0.11.0, nom-derive-impl 0.11.0 | `github.com/rust-bakery/nom-derive`, branch `master` | floating (f68f464f today) |

Without a committed lock file, a branch reference means "whatever is on the branch at build
time". The two forks fall under P7: an advisory against upstream `netlink-packet-route` or
`rtnetlink` will not match our fork automatically.

**Fix.**
- Pin all three by `rev`, and record the commit in the SBOM.
- Upstream the seg6 changes, or publish the forks under their own crate names.
- Replace nom-derive `master` with a crates.io release once the change we need is released.

### S7. The ISO's own debs are not pinned (Medium)

**Evidence.** `mkiso.sh` takes `ls ../zebra-rs/packaging/zebra-rs_*_arm64.deb | sort -V | tail -1`.
That is a local build, not a CI release artifact. No checksum is taken and nothing records which
commit it came from. Today that is zebra-rs 26.10.2, built 2026-10-18, although v26.10.3 was
tagged 2026-10-19.

**Fix.**
- Fetch our debs by exact version from the signed zebra.rs apt repository, or from the GitHub
  release.
- Record each deb's version and SHA-256 in a checked-in manifest, such as
  `contrib/mkiso/components.lock`.
- Allow a local deb only through an explicit override that stamps the image as a development
  build.

### S8. Nothing watches for vulnerabilities (Medium)

- None of zebra-rs, cradle-rs, insomnia or folksy-rs runs `cargo audit` or `cargo deny`.
- None generates an SBOM, and the image is never scanned.
- The build host has `cargo-deb` and no other cargo security tooling.
- Today a vulnerability is noticed only if a developer happens to see it.

§6 and §7 are the fix.

### S9. Universe components (Low)

- **live-boot** (live-boot, live-boot-initramfs-tools, live-boot-doc, live-tools) is in
  `universe`: community-maintained, with no Canonical security commitment. Ubuntu Pro ESM-Apps
  covers it. It runs in the initramfs, and its inputs are the boot medium and the kernel command
  line.
- **strongSwan, for insomnia:** `charon-systemd` and `strongswan-swanctl` are `universe` binaries
  built from the `main` `strongswan` source. A strongswan USN rebuilds them too; their noble
  versions match `libstrongswan` today. Formally, though, they sit outside the `main` commitment.

**Fix.**
- Flag `universe` components in the SBOM.
- Decide between Ubuntu Pro (ESM-Apps for universe, Livepatch for the kernel) and accepting the
  risk.
- Prefer a `main` alternative when one exists.

### S10. Kea is shipped but not integrated (Low)

**Evidence.**
- `kea-dhcp4-server` and `kea-dhcp6-server` 2.4.1-3ubuntu0.2 are enabled at boot with the stock
  configuration.
- zebra-rs has no DHCP backend: `dhcp.yang` is a draft and no code uses it.
- Kea brings 15 packages, mostly lease-database client libraries we do not use: `kea-common`,
  `liblog4cplus`, `libmysqlclient21`, `mysql-common`, `libpq5`, `libldap2`, `libsasl2-*` and the
  Kerberos libraries.

**Fix.**
- Make Kea opt-in (`KEA=1`) until a DHCP backend exists (`design/vyos-gap.md` §9).
- When that backend is designed, compare footprints: Ubuntu's Kea with its database clients,
  against an alternative.

### S11. Toolchain and CI pins (Low)

- **Rust toolchain:**
  - zebra-rs and insomnia build with the floating stable channel, so the statically linked
    standard library and the code generator change with each Rust release, without a commit.
  - cradle-rs pins `nightly-2026-07-23`. A pin is good, but a nightly compiler and its standard
    library get no backported fixes.
- **cargo-deb:** cradle-rs installs it unpinned.
- **GitHub Actions:** every workflow references actions by tag (`actions/checkout@v5`,
  `actions-rust-lang/setup-rust-toolchain@v1`, `actions/upload-artifact@v7`). The action's owner
  can move a tag.
- **`--locked`:** missing from the packaging Makefiles (see S5).

**Fix.**
- Pin an exact stable version in a `rust-toolchain.toml` in zebra-rs and insomnia.
- Pin actions by commit SHA; Dependabot can bump them.
- Pin cargo-deb in cradle-rs.
- Record the toolchain versions in the SBOM.

### S12. Non-router binaries in router packages (Low)

- **`zebra-topology`** (in the `zebra-rs` deb) is a demo 3D web visualizer. When started, it
  listens on `0.0.0.0:<port>` and serves a page that loads JavaScript from unpkg.com. The deb
  also carries the playset tree.
- **`cradle-k8s` (12.7 MB) and `cradle-cni` (2.8 MB)**, in the `cradle-rs` deb. `cradle-k8s` is
  the only user of rustls, ring and kube in the image.

None of these runs by default, but each is code on the router that has to be tracked and
patched.

**Fix.** Split them into `zebra-rs-playset` and `cradle-rs-k8s` packages, and keep those out of the
router image.

### S13. Rust dependency hygiene (Low)

- **Duplicate versions:**
  - zebra-rs: getrandom, hashbrown, nix (0.27.1 and 0.31.3), thiserror;
  - cradle-rs: getrandom, hashbrown, socket2.
- **Archived crate:** zebra-rs uses `serde_yaml 0.9.34+deprecated`. Upstream is archived, so it
  gets no further fixes. zebra-rs also has `yaml-rust2`.
- **Unneeded server code:** insomnia links `axum`, an HTTP server framework, only because tonic's
  default features include the server. insomnia only ever connects outward to zebra-rs; it never
  listens.

**Fix.**
- Enable `cargo deny` bans: multiple versions are denied, with explicit, commented skips.
- Move zebra-rs off `serde_yaml`.
- Use `tonic = { default-features = false, features = [...] }` where only a client is needed.

## 5. Minimizing

### 5.1 The allowlist

The image is defined by `contrib/mkiso/packages.allow`, one line per installed package, with a
reason and an owner:

```text
# package                      reason                                       owner
linux-image-*-generic          kernel                                       folksy-rs
linux-modules-extra-*-generic  vrf.ko, mpls_iptunnel.ko (noble only)        folksy-rs
iproute2                       ip(8) for operators and scripts              folksy-rs
libpam0g                       vtypam (zebra-rs Depends)                    zebra-rs
...
```

After the install stage, the build compares `dpkg-query -W -f '${Package}\n'` with the list:
- an installed package that is not listed fails the build;
- a listed package that is not installed is a warning.

So a new dependency, typically pulled in by an Ubuntu update, always shows up as a reviewed
diff, never as a silent addition. The list covers dependencies too; that is the point.

### 5.2 Steps and their effect

Measured on the 2026-10-22 build, using the simulation from S4:

| Step | Change | Packages | Installed |
|---|---|---|---|
| today | — | 279 | 685 MiB |
| M1 | `--no-install-recommends`, keeping `zstd` (S3) | 258 | ≈668 MiB |
| M2 | debstrap minbase plus an explicit list (S4) | 190 | 544 MiB |
| M3 | Kea opt-in (S10) | 175 | 517 MiB |
| M4 | split `zebra-rs-playset` and `cradle-rs-k8s` out (S12) | 175 | about 17 MB less in binaries |
| — | adding insomnia with backends, no Recommends (§3.6) | +25 | — |

Minimizing does not replace S1: only 10 of the 52 security-stale packages leave with M2 and M3.

The biggest remaining item is `linux-modules-extra` (116 MiB), there for two modules.
- Do not copy individual `.ko` files out of the package by hand: that breaks dpkg ownership and
  kernel updates.
- The clean way out is `SUITE=resolute` (26.04), where `vrf.ko` and `mpls_iptunnel.ko` are in
  `linux-modules`. `mkiso.sh` already handles that.

### 5.3 Rust crates

- **Dependency review:** a new crate in a PR is a review item, visible because `Cargo.lock` is
  committed (S5). The PR says why std or an existing crate is not enough.
- **cargo-deny:**
  - bans on duplicate versions and on unwanted crates (archived crates, a second TLS stack);
  - `sources`: only crates.io, plus the listed git repositories pinned by `rev`;
  - a license allowlist.
- **Features:** default features off where they pull in stacks we do not use, for example tonic in
  insomnia.

## 6. Tracking

### 6.1 Format

- **Format:** CycloneDX 1.6 JSON. It identifies components by package URL (purl) and carries VEX
  statements (§7.2). It converts to SPDX if a customer asks for that.
- **Identifiers:**
  - `pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=arm64&distro=ubuntu-24.04` for Ubuntu packages;
  - `pkg:cargo/tokio@1.53.3` for crates;
  - `pkg:github/zebra-rs/netlink-packet-route@b03a7385` for git crates;
  - `pkg:generic/gnu/bash@5.3.20` for code built from source.
- **One SBOM per released image,** plus one per released deb.

### 6.2 Generating it, per layer

| Layer | Source of truth | Tool |
|---|---|---|
| L0–L1 | the image's `/var/lib/dpkg/status`, plus the apt indexes for the pocket of each version | a new `sbom` stage in `mkiso.sh`, run before `finalize` deletes the apt lists; Appendix D's script is a working prototype |
| L2–L3 Rust | `Cargo.lock` and Cargo metadata | build with `cargo auditable build --release --locked`; `cargo cyclonedx` (or Cargo metadata) for the per-deb SBOM |
| L3 non-Cargo | `sbom/extra-components.yaml` in each repo | hand-kept; CI checks it against `vty/Makefile` and the SRI tags |
| Build tools | toolchain files, workflow pins | written into the SBOM's `metadata.tools` |

Each layer merges into one image SBOM:
- installed in the image as `/usr/share/zebra-live/sbom.cdx.json`, so a router can always say
  exactly what it runs;
- published next to the ISO as a release asset, with its SHA-256 and a signature.

`cargo auditable` embeds each binary's crate list in a `.dep-v0` section. That makes a deployed
binary self-describing: `cargo audit bin`, Trivy, Grype and Syft can all read it
without the source tree.

### 6.3 Keeping it in git

Each release commits a plain-text manifest, sorted `package version` lines for every layer, next
to the build recipe. The release PR shows its diff, so a reviewer sees "libssl3t64
3.0.13-0ubuntu3.16 → .17" or "new: libfoo". The text diff is for people and the JSON is for
tools.

### 6.4 Build gates

| Gate | Check | Where |
|---|---|---|
| G1 | `apt-get -s dist-upgrade` in the rootfs reports nothing to do (S1) | mkiso |
| G2 | installed packages equal `packages.allow` (§5.1) | mkiso |
| G3 | `cargo deny check` for advisories, bans, sources and licenses | each Rust repo, every PR |
| G4 | `cargo audit` on a daily schedule, because advisories appear without code changes | each Rust repo |
| G5 | the SBOM is generated, and its manifest diff is attached to the release PR | release workflows |
| G6 | an Ubuntu OVAL check of the image manifest; any open USN for a shipped package fails a release build | mkiso release |

## 7. Patching

### 7.1 Who fixes what, and how we hear about it

| Component class | Who fixes | How we notice | What we do |
|---|---|---|---|
| Ubuntu `main`, including the kernel | Canonical (USN) | Ubuntu OVAL, OSV or VEX feeds at `security-metadata.canonical.com`; G1 and G6 at every build | rebuild the ISO |
| Ubuntu `universe` | community; strongSwan binaries follow their `main` source | the same feeds, plus a manual watch | rebuild; carry a hotfix if needed (§7.4) |
| Rust crates | upstream authors | RustSec, through G3 and G4 | `cargo update -p <crate> --precise <ver>`, then a patch release |
| Forked git crates | us | upstream's GitHub releases and security advisories | cherry-pick into the fork, bump the `rev` |
| Rust compiler and standard library | Rust project | Rust security advisories | bump the pinned toolchain, rebuild every binary |
| bash and readline in `vty` | GNU (official patches) | watch `bash-5.3-patches/` (S2) | add the patch, release zebra-rs |
| mimalloc, ring | upstream, shipped through crate releases | RustSec and GitHub advisories | bump the crate |
| three.js, globe.gl | upstream (npm) | GitHub and npm advisories | bump the version and the SRI hash |
| our code | us | `SECURITY.md` reports, fuzzing, review | patch release |

Every path ends the same way: a fix reaches routers only in a released image (P6). Besides
triggered rebuilds, there is a monthly rebuild-and-release of the ISO even when nothing
specific triggered one. It picks up every `-security` and `-updates` change and follows the
Ubuntu kernel cadence.

### 7.2 Triage and deadlines

How reachable a component is matters as much as the CVSS score:

| Class | Reachable by | Components |
|---|---|---|
| E1 | remote, unauthenticated, on the data or control plane | kernel network stack; zebra-rs protocol parsers (BGP, OSPF, IS-IS, BFD, PIM, ND); cradle eBPF/XDP; and once in the image, charon (IKE, UDP 500/4500), keepalived (VRRP, protocol 112), Kea (DHCP, when bound) |
| E2 | remote management | sshd (`SSH=1`), `zebra-topology` if started, gRPC when `--host tcp:` is used |
| E3 | local users | `vty`, `vtypam`, sudo, PAM, systemd, most of the base |
| E4 | present but not reachable in our use | for example the MySQL client library in Kea with no database backend configured |

Proposed deadlines from a fix being available to a released image. These are a starting point,
to be adjusted:

| Severity | E1 | E2 | E3 | E4 |
|---|---|---|---|---|
| Critical | 2 days | 7 days | 14 days | monthly rebuild |
| High | 7 days | 14 days | 30 days | monthly rebuild |
| Medium, Low | 30 days | 30 days | monthly rebuild | monthly rebuild |

E4 decisions are recorded as CycloneDX VEX statements, `not_affected` with a justification, so
scanners stay quiet for a stated reason. The component is still updated in the next routine
build.

### 7.3 How a fix reaches a router

**Today:**
- A live-booted router is patched by booting a new ISO.
- An installed router has no update path for our packages. Its apt sources list only Ubuntu, and
  the zebra.rs repository is not configured.
- Ubuntu packages update only if the router can reach the archive; the image ships with empty
  apt lists.
- After any `apt upgrade`, the router no longer matches any released SBOM.

**Options:**
- **(a) Package-based.** Add the zebra.rs repository and key to the image, then run `apt-get
  update && apt-get dist-upgrade`, or unattended-upgrades limited to `-security`.
  - For: small downloads, standard tools.
  - Against: every router drifts to its own state, the router needs archive access, and an
    interrupted upgrade leaves a half-upgraded system.
- **(b) Image-based, with rollback.** The installer keeps each release's squashfs under
  `/boot/<version>/` and boots it with live-boot, plus a persistent overlay that holds only the
  configuration. This is the model VyOS uses with `add system image`.
  - An update installs the new image beside the old one, switches the GRUB default and
    reboots. If the health check fails, the old image boots again.
  - The squashfs never changes, so a router runs exactly the released image, and the SBOM is
    a statement about every router running that release.
  - The pieces already exist: live-boot can boot a squashfs from disk with `persistence`.

**Recommendation:**
- Use (b) for every release.
- Keep (a) only for emergencies, restricted to `-security`. A router patched that way marks
  itself as drifted and reports its dpkg list, so its SBOM is still known.
- `zebra-install` writes a single root filesystem today, so (b) is installer work (Phase 3).

**Reboots.** Kernel and glibc fixes need a reboot or at least a restart of every daemon. With a
VRRP pair (insomnia's VRRP backend):
1. upgrade the backup;
2. fail over to it;
3. upgrade the former master.

This goes into the operations runbook. Livepatch would avoid some kernel reboots, but it
requires Ubuntu Pro (S9).

### 7.4 Hotfixes when upstream is slow

- **Ubuntu package:**
  1. Rebuild the source package with our patch.
  2. Version it `<ubuntu-version>+zebra1`. For example, `2.39-0ubuntu8.9+zebra1` sorts above
     `2.39-0ubuntu8.9` and below Ubuntu's next `2.39-0ubuntu8.10`, so Ubuntu's own fix replaces
     ours automatically.
  3. Publish it in the zebra.rs repository and name it in the image manifest.
  4. Drop it once Ubuntu ships the fix.
- **Rust crate:** add a `[patch.crates-io]` entry pointing at a fixed fork `rev` until upstream
  releases. It is recorded in the SBOM as a git source, and removed when the release lands.
- **Either way,** the hotfix is listed in the SBOM with a link to the upstream issue, so it is not
  forgotten.

## 8. Roadmap

| Phase | Work | Findings | Owner |
|---|---|---|---|
| 0: stop shipping known-fixed bugs | `dist-upgrade` plus gate G1; bash 5.3 official patches; `--no-install-recommends`; commit zebra-rs `Cargo.lock`; `--locked` everywhere; fetch released debs by version and SHA-256 | S1, S2, S3, S5, S7 | folksy-rs, zebra-rs |
| 1: know what we ship | `sbom` stage in mkiso (CycloneDX); `cargo auditable` in all packaging; `cargo deny` per PR and scheduled `cargo audit`; `extra-components.yaml`; manifest in git; gates G3–G6 | S8 | all |
| 2: ship less | debstrap minbase and `packages.allow` (G2); Kea opt-in; split `zebra-rs-playset` and `cradle-rs-k8s`; Rust trims; pin toolchains and Actions; pin or replace git dependencies | S4, S6, S10–S13 | all |
| 3: deliver patches | image-based update with rollback; our own snapshot mirror of `ubuntu-ports`, since `snapshot.ubuntu.com` answers 401 for `ubuntu-ports` (checked 2026-10-22); decide on Ubuntu Pro (ESM-Apps, Livepatch) | S9, §7.3 | folksy-rs |

**Outside the SBOM, but noticed while building the image:** the `configure` stage gives root a
passwordless autologin on the serial and virtual consoles. `zebra-install` copies the image
unchanged, so every installed router keeps that autologin.

---

## Appendix A: ISO packages

### A.1 Ubuntu and local packages in the ISO (279)

Columns:

- **Layer:** `required` = debstrap Essential/required set; `important` = debstrap
  Priority: important set (`ubuntu-minimal` and its dependencies); `named` = listed in
  `mkiso.sh`; `depends` = pulled in as a dependency of a named package; `recommends` = pulled
  in only as a Recommends (S3).
- **Pocket:** the archive pockets that carry exactly this version; `local` = a .deb from
  our own build tree.
- **Pending:** the newer version the image's own sources offer, and the pocket it comes
  from (S1).
- **Minimal:** `drop` = removed in the minbase + no-Recommends simulation (S4); `drop (Kea)` =
  removed only when Kea is also left out (S10).

| Package | Version | Source | Comp. | Pocket | Layer | Pending | Minimal |
|---|---|---|---|---|---|---|---|
| adduser | 3.137ubuntu1 | adduser | main | noble | important |  |  |
| apt | 2.7.14build2 | apt | main | noble | required | 2.8.3 (updates) |  |
| apt-utils | 2.7.14build2 | apt | main | noble | important | 2.8.3 (updates) |  |
| base-files | 13ubuntu10 | base-files | main | noble | required | 13ubuntu10.5 (updates) |  |
| base-passwd | 3.6.3build1 | base-passwd | main | noble | required |  |  |
| bash | 5.2.21-2ubuntu4 | bash | main | noble | required |  |  |
| bsdutils | 1:2.39.3-9ubuntu6.6 | util-linux | main | updates, security | required |  |  |
| busybox-initramfs | 1:1.36.1-6ubuntu3.1 | busybox | main | updates, security | depends |  |  |
| ca-certificates | 20240203 | ca-certificates | main | noble | important | 20260816ubuntu0.24.04.1 (security) | drop |
| console-setup | 1.226ubuntu1 | console-setup | main | noble | important | 1.226ubuntu1.1 (updates) | drop |
| console-setup-linux | 1.226ubuntu1 | console-setup | main | noble | important | 1.226ubuntu1.1 (updates) | drop |
| coreutils | 9.4-3ubuntu6 | coreutils | main | noble | required | 9.4-3ubuntu6.3 (security) |  |
| cpio | 2.15+dfsg-1ubuntu2.1 | cpio | main | updates, security | depends |  |  |
| cradle-rs | 1.1.9 | cradle-rs | local | local | named |  |  |
| dash | 0.5.12-6ubuntu5 | dash | main | noble | required |  |  |
| dbus | 1.14.10-4ubuntu4.1 | dbus | main | updates | important |  |  |
| dbus-bin | 1.14.10-4ubuntu4.1 | dbus | main | updates | important |  |  |
| dbus-daemon | 1.14.10-4ubuntu4.1 | dbus | main | updates | important |  |  |
| dbus-session-bus-common | 1.14.10-4ubuntu4.1 | dbus | main | updates | important |  |  |
| dbus-system-bus-common | 1.14.10-4ubuntu4.1 | dbus | main | updates | important |  |  |
| dbus-user-session | 1.14.10-4ubuntu4.1 | dbus | main | updates | important |  | drop |
| debconf | 1.5.86ubuntu1 | debconf | main | noble | required |  |  |
| debconf-i18n | 1.5.86ubuntu1 | debconf | main | noble | important |  | drop |
| debianutils | 5.17build1 | debianutils | main | noble | required |  |  |
| device-tree-compiler | 1.7.0-2build1 | device-tree-compiler | main | noble | recommends |  | drop |
| devio | 1.2-2build1 | devio | main | noble | recommends |  | drop |
| dhcpcd-base | 1:10.0.6-1ubuntu3 | dhcpcd | main | noble | important | 1:10.0.6-1ubuntu3.2 (updates) |  |
| diffutils | 1:3.10-1build1 | diffutils | main | noble | required | 1:3.10-1ubuntu0.1 (security) |  |
| distro-info | 1.7build1 | distro-info | main | noble | important |  | drop |
| distro-info-data | 0.60 | distro-info-data | main | noble | important | 2026.10.12-0ubuntu0.24.04.1 (security) |  |
| dmsetup | 2:1.02.185-3ubuntu3 | lvm2 | main | noble | important | 2:1.02.185-3ubuntu3.2 (updates) | drop |
| dosfstools | 4.2-1.1build1 | dosfstools | main | noble | named |  |  |
| dpkg | 1.22.6ubuntu6 | dpkg | main | noble | required | 1.22.6ubuntu6.6 (security) |  |
| dracut-install | 060+5-1ubuntu3.4 | dracut | main | updates, security | depends |  |  |
| e2fsprogs | 1.47.0-2.4~exp1ubuntu4 | e2fsprogs | main | noble | required | 1.47.0-2.4~exp1ubuntu4.1 (updates) |  |
| efibootmgr | 18-1build2 | efibootmgr | main | noble | named |  |  |
| eject | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | important |  | drop |
| fdisk | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | named |  |  |
| findutils | 4.9.0-5build1 | findutils | main | noble | required |  |  |
| flash-kernel | 3.107ubuntu13~24.04.6 | flash-kernel | main | updates | recommends |  | drop |
| gcc-14-base | 14-20240412-0ubuntu1 | gcc-14 | main | noble | required | 14.2.0-4ubuntu2~24.04.1 (security) |  |
| gettext-base | 0.21-14ubuntu2 | gettext | main | noble | depends |  |  |
| gir1.2-girepository-2.0 | 1.80.1-1 | gobject-introspection | main | noble | important |  | drop |
| gir1.2-glib-2.0 | 2.80.0-6ubuntu1 | glib2.0 | main | noble | important | 2.80.0-6ubuntu3.10 (updates) | drop |
| gpgv | 2.4.4-2ubuntu17 | gnupg2 | main | noble | required | 2.4.4-2ubuntu17.6 (security) |  |
| grep | 3.11-4build1 | grep | main | noble | required |  |  |
| grub-common | 2.12-1ubuntu7.3 | grub2 | main | updates | depends |  |  |
| grub-efi-arm64 | 2.12-1ubuntu7.3 | grub2-unsigned | main | updates | recommends |  | drop |
| grub-efi-arm64-bin | 2.12-1ubuntu7.3 | grub2-unsigned | main | updates | named |  |  |
| grub-efi-arm64-signed | 1.202.5+2.12-1ubuntu7.3 | grub2-signed | main | updates | recommends |  | drop |
| grub2-common | 2.12-1ubuntu7.3 | grub2 | main | updates | named |  |  |
| gzip | 1.12-1ubuntu3 | gzip | main | noble | required | 1.12-1ubuntu3.2 (security) |  |
| hostname | 3.23+nmu2ubuntu2 | hostname | main | noble | required |  |  |
| init | 1.66ubuntu1 | init-system-helpers | main | noble | important |  |  |
| init-system-helpers | 1.66ubuntu1 | init-system-helpers | main | noble | required |  |  |
| initramfs-tools | 0.142ubuntu25.8 | initramfs-tools | main | updates | named |  |  |
| initramfs-tools-bin | 0.142ubuntu25.8 | initramfs-tools | main | updates | depends |  |  |
| initramfs-tools-core | 0.142ubuntu25.8 | initramfs-tools | main | updates | depends |  |  |
| iproute2 | 6.1.0-1ubuntu6.4 | iproute2 | main | updates | important |  |  |
| iputils-ping | 3:20240117-1ubuntu0.1 | iputils | main | updates, security | important |  |  |
| iso-codes | 4.16.0-1 | iso-codes | main | noble | important |  | drop |
| kbd | 2.6.4-2ubuntu2 | kbd | main | noble | important |  | drop |
| kea-common | 2.4.1-3ubuntu0.2 | isc-kea | main | updates, security | depends |  | drop (Kea) |
| kea-dhcp4-server | 2.4.1-3ubuntu0.2 | isc-kea | main | updates, security | named |  | drop (Kea) |
| kea-dhcp6-server | 2.4.1-3ubuntu0.2 | isc-kea | main | updates, security | named |  | drop (Kea) |
| keyboard-configuration | 1.226ubuntu1 | console-setup | main | noble | important | 1.226ubuntu1.1 (updates) | drop |
| klibc-utils | 2.0.13-4ubuntu0.2 | klibc | main | updates, security | depends |  |  |
| kmod | 31+20240202-2ubuntu7.2 | kmod | main | security | important |  |  |
| krb5-locales | 1.20.1-6ubuntu2 | krb5 | main | noble | important | 1.20.1-6ubuntu2.10 (updates) | drop |
| less | 590-2ubuntu2.1 | less | main | updates, security | important |  |  |
| libacl1 | 2.3.2-1build1 | acl | main | noble | required | 2.3.2-1build1.1 (updates) |  |
| libapparmor1 | 4.0.0-beta3-0ubuntu3 | apparmor | main | noble | important | 4.0.1really4.0.1-0ubuntu0.24.04.9 (updates) |  |
| libapt-pkg6.0t64 | 2.7.14build2 | apt | main | noble | required | 2.8.3 (updates) |  |
| libargon2-1 | 0~20190702+dfsg-4build1 | argon2 | main | noble | important |  |  |
| libassuan0 | 2.5.6-1build1 | libassuan | main | noble | required |  |  |
| libatm1t64 | 1:2.5.1-5.1build1 | linux-atm | main | noble | important |  | drop |
| libattr1 | 1:2.5.2-1build1 | attr | main | noble | required | 1:2.5.2-1ubuntu0.1 (security) |  |
| libaudit-common | 1:3.1.2-2.1build1 | audit | main | noble | required | 1:3.1.2-2.1ubuntu0.1 (updates) |  |
| libaudit1 | 1:3.1.2-2.1build1 | audit | main | noble | required | 1:3.1.2-2.1ubuntu0.1 (updates) |  |
| libblkid1 | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | required |  |  |
| libbpf1 | 1:1.3.0-2build2 | libbpf | main | noble | important |  |  |
| libbrotli1 | 1.1.0-2build2 | brotli | main | noble | depends |  |  |
| libbsd0 | 0.12.1-1build1 | libbsd | main | noble | important | 0.12.1-1build1.1 (updates) | drop |
| libbz2-1.0 | 1.0.8-5.1 | bzip2 | main | noble | required | 1.0.8-5.1ubuntu0.1 (security) |  |
| libc-bin | 2.39-0ubuntu8 | glibc | main | noble | required | 2.39-0ubuntu8.9 (security) |  |
| libc6 | 2.39-0ubuntu8 | glibc | main | noble | required | 2.39-0ubuntu8.9 (security) |  |
| libcap-ng0 | 0.8.4-2build2 | libcap-ng | main | noble | required |  |  |
| libcap2 | 1:2.66-5ubuntu2.4 | libcap2 | main | updates, security | required |  |  |
| libcap2-bin | 1:2.66-5ubuntu2.4 | libcap2 | main | updates, security | important |  |  |
| libcom-err2 | 1.47.0-2.4~exp1ubuntu4 | e2fsprogs | main | noble | required | 1.47.0-2.4~exp1ubuntu4.1 (updates) |  |
| libcrypt1 | 1:4.4.36-4build1 | libxcrypt | main | noble | required |  |  |
| libcryptsetup12 | 2:2.7.0-1ubuntu4 | cryptsetup | main | noble | important | 2:2.7.0-1ubuntu4.2 (updates) |  |
| libdb5.3t64 | 5.3.28+dfsg2-7 | db5.3 | main | noble | important |  |  |
| libdbus-1-3 | 1.14.10-4ubuntu4.1 | dbus | main | updates | important |  |  |
| libdebconfclient0 | 0.271ubuntu3 | cdebconf | main | noble | required |  |  |
| libdevmapper1.02.1 | 2:1.02.185-3ubuntu3 | lvm2 | main | noble | important | 2:1.02.185-3ubuntu3.2 (updates) |  |
| libefiboot1t64 | 38-3.1build1 | efivar | main | noble | depends |  |  |
| libefivar1t64 | 38-3.1build1 | efivar | main | noble | depends |  |  |
| libelf1t64 | 0.190-1.1build4 | elfutils | main | noble | important | 0.190-1.1ubuntu0.1 (security) |  |
| libestr0 | 0.1.11-1build1 | libestr | main | noble | important |  | drop |
| libexpat1 | 2.6.1-2build1 | expat | main | noble | important | 2.6.1-2ubuntu0.6 (security) |  |
| libext2fs2t64 | 1.47.0-2.4~exp1ubuntu4 | e2fsprogs | main | noble | required | 1.47.0-2.4~exp1ubuntu4.1 (updates) |  |
| libfastjson4 | 1.2304.0-1build1 | libfastjson | main | noble | important |  | drop |
| libfdisk1 | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | important |  |  |
| libfdt1 | 1.7.0-2build1 | device-tree-compiler | main | noble | recommends |  | drop |
| libffi8 | 3.4.6-1build1 | libffi | main | noble | required |  |  |
| libfreetype6 | 2.13.2+dfsg-1ubuntu0.2 | freetype | main | updates, security | depends |  |  |
| libfribidi0 | 1.0.13-3build1 | fribidi | main | noble | important |  | drop |
| libfuse3-3 | 3.14.0-5build1 | fuse3 | main | noble | depends |  |  |
| libgcc-s1 | 14-20240412-0ubuntu1 | gcc-14 | main | noble | required | 14.2.0-4ubuntu2~24.04.1 (security) |  |
| libgcrypt20 | 1.10.3-2build1 | libgcrypt20 | main | noble | required | 1.10.3-2ubuntu0.2 (security) |  |
| libgirepository-1.0-1 | 1.80.1-1 | gobject-introspection | main | noble | important |  | drop |
| libglib2.0-0t64 | 2.80.0-6ubuntu1 | glib2.0 | main | noble | important | 2.80.0-6ubuntu3.10 (updates) | drop |
| libglib2.0-data | 2.80.0-6ubuntu1 | glib2.0 | main | noble | important | 2.80.0-6ubuntu3.10 (updates) | drop |
| libgmp10 | 2:6.3.0+dfsg-2ubuntu6 | gmp | main | noble | required | 2:6.3.0+dfsg-2ubuntu6.1 (updates) |  |
| libgnutls30t64 | 3.8.3-1.1ubuntu3 | gnutls28 | main | noble | required | 3.8.3-1.1ubuntu3.6 (security) |  |
| libgpg-error0 | 1.47-3build2 | libgpg-error | main | noble | required | 1.47-3build2.1 (updates) |  |
| libgssapi-krb5-2 | 1.20.1-6ubuntu2 | krb5 | main | noble | important | 1.20.1-6ubuntu2.10 (updates) | drop (Kea) |
| libhogweed6t64 | 3.9.1-2.2build1 | nettle | main | noble | required | 3.9.1-2.2build1.1 (updates) |  |
| libicu74 | 74.2-1ubuntu3 | icu | main | noble | important | 74.2-1ubuntu3.1 (updates) | drop |
| libidn2-0 | 2.3.7-2build1 | libidn2 | main | noble | required | 2.3.7-2build1.1 (updates) |  |
| libiniparser1 | 4.1-7ubuntu0.1 | iniparser | main | updates, security | recommends |  | drop |
| libjson-c5 | 0.17-1build1 | json-c | main | noble | important |  |  |
| libk5crypto3 | 1.20.1-6ubuntu2 | krb5 | main | noble | important | 1.20.1-6ubuntu2.10 (updates) | drop (Kea) |
| libkeyutils1 | 1.6.3-3build1 | keyutils | main | noble | important |  | drop (Kea) |
| libklibc | 2.0.13-4ubuntu0.2 | klibc | main | updates, security | depends |  |  |
| libkmod2 | 31+20240202-2ubuntu7.2 | kmod | main | security | important |  |  |
| libkrb5-3 | 1.20.1-6ubuntu2 | krb5 | main | noble | important | 1.20.1-6ubuntu2.10 (updates) | drop (Kea) |
| libkrb5support0 | 1.20.1-6ubuntu2 | krb5 | main | noble | important | 1.20.1-6ubuntu2.10 (updates) | drop (Kea) |
| libldap-common | 2.6.10+dfsg-0ubuntu0.24.04.1 | openldap | main | updates | recommends |  | drop |
| libldap2 | 2.6.10+dfsg-0ubuntu0.24.04.1 | openldap | main | updates | depends |  | drop (Kea) |
| liblocale-gettext-perl | 1.07-6ubuntu5 | liblocale-gettext-perl | main | noble | important |  |  |
| liblog4cplus-2.0.5t64 | 2.0.8-1.1ubuntu3 | log4cplus | main | noble | depends |  | drop (Kea) |
| liblz4-1 | 1.9.4-1build1 | lz4 | main | noble | required | 1.9.4-1build1.1 (updates) |  |
| liblzma5 | 5.6.1+really5.4.5-1 | xz-utils | main | noble | required | 5.6.1+really5.4.5-1ubuntu0.4 (security) |  |
| liblzo2-2 | 2.10-2build4 | lzo2 | main | noble | recommends |  | drop |
| libmd0 | 1.1.0-2build1 | libmd | main | noble | required | 1.1.0-2build1.1 (updates) |  |
| libmnl0 | 1.0.5-2build1 | libmnl | main | noble | important |  |  |
| libmount1 | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | required |  |  |
| libmysqlclient21 | 8.0.46-0ubuntu0.24.04.4 | mysql-8.0 | main | updates, security | depends |  | drop (Kea) |
| libncursesw6 | 6.4+20240113-1ubuntu2 | ncurses | main | noble | required | 6.4+20240113-1ubuntu2.2 (security) |  |
| libnetplan1 | 1.0-2ubuntu1 | netplan.io | main | noble | important | 1.1.2-8ubuntu1~24.04.3 (updates) | drop |
| libnettle8t64 | 3.9.1-2.2build1 | nettle | main | noble | required | 3.9.1-2.2build1.1 (updates) |  |
| libnewt0.52 | 0.52.24-2ubuntu2 | newt | main | noble | important |  | drop |
| libnpth0t64 | 1.6-3.1build1 | npth | main | noble | required |  |  |
| libnss-systemd | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  | drop |
| libp11-kit0 | 0.25.3-4ubuntu2 | p11-kit | main | noble | required | 0.25.3-4ubuntu2.2 (security) |  |
| libpam-cap | 1:2.66-5ubuntu2.4 | libcap2 | main | updates, security | important |  | drop |
| libpam-modules | 1.5.3-5ubuntu5 | pam | main | noble | required | 1.5.3-5ubuntu5.7 (security) |  |
| libpam-modules-bin | 1.5.3-5ubuntu5 | pam | main | noble | required | 1.5.3-5ubuntu5.7 (security) |  |
| libpam-runtime | 1.5.3-5ubuntu5 | pam | main | noble | required | 1.5.3-5ubuntu5.7 (security) |  |
| libpam-systemd | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  | drop |
| libpam0g | 1.5.3-5ubuntu5 | pam | main | noble | required | 1.5.3-5ubuntu5.7 (security) |  |
| libpcre2-8-0 | 10.42-4ubuntu2 | pcre2 | main | noble | required | 10.42-4ubuntu2.1 (updates) |  |
| libpng16-16t64 | 1.6.43-5ubuntu0.7 | libpng1.6 | main | updates, security | depends |  |  |
| libpopt0 | 1.19+dfsg-1build1 | popt | main | noble | important |  |  |
| libpq5 | 16.15-0ubuntu0.24.04.1 | postgresql-16 | main | updates, security | depends |  | drop (Kea) |
| libproc2-0 | 2:4.0.4-4ubuntu3 | procps | main | noble | required | 2:4.0.4-4ubuntu3.3 (updates) |  |
| libpython3-stdlib | 3.12.3-0ubuntu1 | python3-defaults | main | noble | important | 3.12.3-0ubuntu2.1 (security) |  |
| libpython3.12-minimal | 3.12.3-1 | python3.12 | main | noble | important | 3.12.3-1ubuntu0.17 (security) |  |
| libpython3.12-stdlib | 3.12.3-1 | python3.12 | main | noble | important | 3.12.3-1ubuntu0.17 (security) |  |
| libreadline8t64 | 8.2-4build1 | readline | main | noble | important |  |  |
| libsasl2-2 | 2.1.28+dfsg1-5ubuntu3.1 | cyrus-sasl2 | main | updates | depends |  | drop (Kea) |
| libsasl2-modules | 2.1.28+dfsg1-5ubuntu3.1 | cyrus-sasl2 | main | updates | recommends |  | drop |
| libsasl2-modules-db | 2.1.28+dfsg1-5ubuntu3.1 | cyrus-sasl2 | main | updates | depends |  | drop (Kea) |
| libseccomp2 | 2.5.5-1ubuntu3 | libseccomp | main | noble | required | 2.5.5-1ubuntu3.1 (updates) |  |
| libselinux1 | 3.5-2ubuntu2 | libselinux | main | noble | required | 3.5-2ubuntu2.1 (updates) |  |
| libsemanage-common | 3.5-1build5 | libsemanage | main | noble | required |  |  |
| libsemanage2 | 3.5-1build5 | libsemanage | main | noble | required |  |  |
| libsepol2 | 3.5-2build1 | libsepol | main | noble | required |  |  |
| libslang2 | 2.3.3-3build2 | slang2 | main | noble | important |  | drop |
| libsmartcols1 | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | required |  |  |
| libsqlite3-0 | 3.45.1-1ubuntu2 | sqlite3 | main | noble | important | 3.45.1-1ubuntu2.8 (security) |  |
| libss2 | 1.47.0-2.4~exp1ubuntu4 | e2fsprogs | main | noble | required | 1.47.0-2.4~exp1ubuntu4.1 (updates) |  |
| libssl3t64 | 3.0.13-0ubuntu3 | openssl | main | noble | required | 3.0.13-0ubuntu3.16 (security) |  |
| libstdc++6 | 14-20240412-0ubuntu1 | gcc-14 | main | noble | required | 14.2.0-4ubuntu2~24.04.1 (security) |  |
| libsystemd-shared | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  |  |
| libsystemd0 | 255.4-1ubuntu8.18 | systemd | main | updates, security | required |  |  |
| libtasn1-6 | 4.19.0-3build1 | libtasn1-6 | main | noble | required | 4.19.0-3ubuntu0.24.04.2 (security) |  |
| libtext-charwidth-perl | 0.04-11build3 | libtext-charwidth-perl | main | noble | important |  |  |
| libtext-iconv-perl | 1.7-8build3 | libtext-iconv-perl | main | noble | important |  |  |
| libtext-wrapi18n-perl | 0.06-10 | libtext-wrapi18n-perl | main | noble | important |  |  |
| libtinfo6 | 6.4+20240113-1ubuntu2 | ncurses | main | noble | required | 6.4+20240113-1ubuntu2.2 (security) |  |
| libtirpc-common | 1.3.4+ds-1.1build1 | libtirpc | main | noble | important |  | drop |
| libtirpc3t64 | 1.3.4+ds-1.1build1 | libtirpc | main | noble | important |  | drop |
| libubootenv-tool | 0.3.5-0.1build1 | libubootenv | main | noble | recommends |  | drop |
| libubootenv0.1 | 0.3.5-0.1build1 | libubootenv | main | noble | recommends |  | drop |
| libudev1 | 255.4-1ubuntu8.18 | systemd | main | updates, security | required |  |  |
| libunistring5 | 1.1-2build1 | libunistring | main | noble | required | 1.1-2build1.1 (updates) |  |
| libuuid1 | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | required |  |  |
| libxml2 | 2.9.14+dfsg-1.3ubuntu3 | libxml2 | main | noble | important | 2.9.14+dfsg-1.3ubuntu3.10 (security) | drop |
| libxtables12 | 1.8.10-3ubuntu2 | iptables | main | noble | important |  |  |
| libxxhash0 | 0.8.2-2build1 | xxhash | main | noble | required |  |  |
| libyaml-0-2 | 0.2.5-1build1 | libyaml | main | noble | important |  | drop |
| libzstd1 | 1.5.5+dfsg2-2build1.1 | libzstd | main | updates | required |  |  |
| linux-base | 4.5ubuntu9+24.04.2 | linux-base | main | updates | depends |  |  |
| linux-image-6.8.0-147-generic | 6.8.0-147.147 | linux-signed | main | updates, security | named |  |  |
| linux-modules-6.8.0-147-generic | 6.8.0-147.147 | linux | main | updates, security | depends |  |  |
| linux-modules-extra-6.8.0-147-generic | 6.8.0-147.147 | linux | main | updates, security | named |  |  |
| live-boot | 1:20230131 | live-boot | universe | noble | named |  |  |
| live-boot-doc | 1:20230131 | live-boot | universe | noble | recommends |  | drop |
| live-boot-initramfs-tools | 1:20230131 | live-boot | universe | noble | depends |  |  |
| live-tools | 1:20190831.1 | live-tools | universe | noble | recommends |  | drop |
| locales | 2.39-0ubuntu8 | glibc | main | noble | important | 2.39-0ubuntu8.9 (security) | drop |
| login | 1:4.13+dfsg1-4ubuntu3 | shadow | main | noble | required | 1:4.13+dfsg1-4ubuntu3.2 (updates) |  |
| logrotate | 3.21.0-2build1 | logrotate | main | noble | important |  | drop |
| logsave | 1.47.0-2.4~exp1ubuntu4 | e2fsprogs | main | noble | required | 1.47.0-2.4~exp1ubuntu4.1 (updates) |  |
| lsb-release | 12.0-2 | lsb-release-minimal | main | noble | important |  | drop |
| mawk | 1.3.4.20240123-1build1 | mawk | main | noble | required |  |  |
| media-types | 10.1.0 | media-types | main | noble | important |  |  |
| mount | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | required |  |  |
| mtd-utils | 1:2.2.0-1ubuntu2 | mtd-utils | main | noble | recommends |  | drop |
| mysql-common | 5.8+1.1.0build1 | mysql-defaults | main | noble | depends |  | drop (Kea) |
| ncurses-base | 6.4+20240113-1ubuntu2 | ncurses | main | noble | required | 6.4+20240113-1ubuntu2.2 (security) |  |
| ncurses-bin | 6.4+20240113-1ubuntu2 | ncurses | main | noble | required | 6.4+20240113-1ubuntu2.2 (security) |  |
| netbase | 6.4 | netbase | main | noble | important |  |  |
| netcat-openbsd | 1.226-1ubuntu2 | netcat-openbsd | main | noble | important |  | drop |
| netplan-generator | 1.0-2ubuntu1 | netplan.io | main | noble | important | 1.1.2-8ubuntu1~24.04.3 (updates) | drop |
| netplan.io | 1.0-2ubuntu1 | netplan.io | main | noble | important | 1.1.2-8ubuntu1~24.04.3 (updates) | drop |
| networkd-dispatcher | 2.2.4-1 | networkd-dispatcher | main | noble | important |  | drop |
| openssl | 3.0.13-0ubuntu3 | openssl | main | noble | important | 3.0.13-0ubuntu3.16 (security) | drop |
| os-prober | 1.81ubuntu4 | os-prober | main | noble | recommends |  | drop |
| passwd | 1:4.13+dfsg1-4ubuntu3 | shadow | main | noble | required | 1:4.13+dfsg1-4ubuntu3.2 (updates) |  |
| perl-base | 5.38.2-3.2build2 | perl | main | noble | required | 5.38.2-3.2ubuntu0.6 (security) |  |
| procps | 2:4.0.4-4ubuntu3 | procps | main | noble | required | 2:4.0.4-4ubuntu3.3 (updates) |  |
| python-apt-common | 2.7.7ubuntu1 | python-apt | main | noble | important | 2.7.7ubuntu5.3 (updates) |  |
| python3 | 3.12.3-0ubuntu1 | python3-defaults | main | noble | important | 3.12.3-0ubuntu2.1 (security) |  |
| python3-apt | 2.7.7ubuntu1 | python-apt | main | noble | important | 2.7.7ubuntu5.3 (updates) |  |
| python3-cffi-backend | 1.16.0-2build1 | python-cffi | main | noble | important |  | drop |
| python3-dbus | 1.3.2-5build3 | dbus-python | main | noble | important |  | drop |
| python3-gi | 3.48.2-1 | pygobject | main | noble | important |  | drop |
| python3-markdown-it | 3.0.0-2 | markdown-it-py | main | noble | important |  | drop |
| python3-mdurl | 0.1.2-1 | mdurl | main | noble | important |  | drop |
| python3-minimal | 3.12.3-0ubuntu1 | python3-defaults | main | noble | important | 3.12.3-0ubuntu2.1 (security) |  |
| python3-netifaces | 0.11.0-2build3 | netifaces | main | noble | important |  | drop |
| python3-netplan | 1.0-2ubuntu1 | netplan.io | main | noble | important | 1.1.2-8ubuntu1~24.04.3 (updates) | drop |
| python3-pkg-resources | 68.1.2-2ubuntu1 | setuptools | main | noble | important | 68.1.2-2ubuntu1.2 (security) | drop |
| python3-pygments | 2.17.2+dfsg-1 | pygments | main | noble | important |  | drop |
| python3-rich | 13.7.1-1 | rich | main | noble | important |  | drop |
| python3-yaml | 6.0.1-2build2 | pyyaml | main | noble | important |  | drop |
| python3.12 | 3.12.3-1 | python3.12 | main | noble | important | 3.12.3-1ubuntu0.17 (security) |  |
| python3.12-minimal | 3.12.3-1 | python3.12 | main | noble | important | 3.12.3-1ubuntu0.17 (security) |  |
| readline-common | 8.2-4build1 | readline | main | noble | important |  |  |
| rsync | 3.2.7-1ubuntu1.5 | rsync | main | updates, security | recommends |  | drop |
| rsyslog | 8.2312.0-3ubuntu9 | rsyslog | main | noble | important | 8.2312.0-3ubuntu9.4 (security) | drop |
| sbsigntool | 0.9.4-3.1ubuntu7 | sbsigntool | main | noble | recommends |  | drop |
| secureboot-db | 1.9build1 | secureboot-db | main | noble | recommends |  | drop |
| sed | 4.9-2build1 | sed | main | noble | required | 4.9-2ubuntu0.24.04.1 (security) |  |
| sensible-utils | 0.0.22 | sensible-utils | main | noble | required |  |  |
| shared-mime-info | 2.4-4 | shared-mime-info | main | noble | important |  | drop |
| sudo | 1.9.15p5-3ubuntu5 | sudo | main | noble | important | 1.9.15p5-3ubuntu5.24.04.4 (security) | drop |
| systemd | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  |  |
| systemd-dev | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  |  |
| systemd-hwe-hwdb | 255.1.3 | systemd-hwe | main | noble | important | 255.1.7 (updates) | drop |
| systemd-resolved | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  | drop |
| systemd-sysv | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  |  |
| systemd-timesyncd | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  | drop |
| sysvinit-utils | 3.08-6ubuntu3 | sysvinit | main | noble | required |  |  |
| tar | 1.35+dfsg-3build1 | tar | main | noble | required | 1.35+dfsg-3ubuntu0.4 (security) |  |
| tzdata | 2024a-2ubuntu1 | tzdata | main | noble | important | 2026e-0ubuntu0.24.04.1 (security) |  |
| u-boot-tools | 2025.10-0ubuntu0.24.04.4 | u-boot | main | updates, security | recommends |  | drop |
| ubuntu-keyring | 2023.11.28.1 | ubuntu-keyring | main | noble | required |  |  |
| ubuntu-minimal | 1.539 | ubuntu-meta | main | noble | important | 1.539.2 (updates) | drop |
| ubuntu-pro-client | 31.2.3 | ubuntu-advantage-tools | main | noble | important | 38ubuntu0~24.04 (updates) | drop |
| ubuntu-pro-client-l10n | 31.2.3 | ubuntu-advantage-tools | main | noble | important | 38ubuntu0~24.04 (updates) | drop |
| ucf | 3.0043+nmu1 | ucf | main | noble | important |  | drop |
| udev | 255.4-1ubuntu8.18 | systemd | main | updates, security | important |  |  |
| util-linux | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | required |  |  |
| uuid-runtime | 2.39.3-9ubuntu6.6 | util-linux | main | updates, security | recommends |  | drop |
| vim-common | 2:9.1.0016-1ubuntu7 | vim | main | noble | important | 2:9.1.0016-1ubuntu7.20 (security) | drop |
| vim-tiny | 2:9.1.0016-1ubuntu7 | vim | main | noble | important | 2:9.1.0016-1ubuntu7.20 (security) | drop |
| whiptail | 0.52.24-2ubuntu2 | newt | main | noble | important |  | drop |
| wireless-regdb | 2026.05.30-0ubuntu1~24.04.1 | wireless-regdb | main | updates, security | depends |  |  |
| xdg-user-dirs | 0.18-1build1 | xdg-user-dirs | main | noble | important |  | drop |
| xkb-data | 2.41-2ubuntu1 | xkeyboard-config | main | noble | important | 2.41-2ubuntu1.1 (updates) | drop |
| xxd | 2:9.1.0016-1ubuntu7 | vim | main | noble | important | 2:9.1.0016-1ubuntu7.20 (security) | drop |
| zebra-rs | 26.10.2 | zebra-rs | local | local | named |  |  |
| zlib1g | 1:1.3.dfsg-3.1ubuntu2 | zlib | main | noble | required | 1:1.3.dfsg-3.1ubuntu2.3 (security) |  |
| zstd | 1.5.5+dfsg2-2build1.1 | libzstd | main | updates | recommends |  |  |

## Appendix B: Rust crates

### B.1 Rust crates linked into the shipped binaries (282 name+version pairs)

Z = zebra-rs (`zebra-rs`, `vtyctl`, `vtyhelper`, `vtypam`, `zebra-topology`),
C = cradle-rs (`cradle`, `cradle-cni`, `cradle-k8s`), I = insomnia (`insomnia`).
Resolved for `aarch64-unknown-linux-gnu`, normal edges only (no build scripts, proc-macros or
dev-dependencies).

| Crate | Version | Z | C | I | Source |
|---|---|:-:|:-:|:-:|---|
| adler2 | 2.0.1 | ✓ |  |  | crates.io |
| ahash | 0.8.12 | ✓ | ✓ |  | crates.io |
| aho-corasick | 1.1.4 |  | ✓ |  | crates.io |
| aho-corasick | 1.1.5 | ✓ |  |  | crates.io |
| allocator-api2 | 0.2.21 |  | ✓ |  | crates.io |
| alphanumeric-sort | 1.5.8 | ✓ |  |  | crates.io |
| annotate-snippets | 0.12.16 |  | ✓ |  | crates.io |
| anstream | 1.0.0 | ✓ | ✓ | ✓ | crates.io |
| anstyle | 1.0.14 | ✓ | ✓ | ✓ | crates.io |
| anstyle-parse | 1.0.0 | ✓ | ✓ | ✓ | crates.io |
| anstyle-query | 1.1.5 | ✓ | ✓ | ✓ | crates.io |
| anyhow | 1.0.104 | ✓ | ✓ | ✓ | crates.io |
| arraydeque | 0.5.1 | ✓ | ✓ |  | crates.io |
| assert_matches | 1.5.0 |  | ✓ |  | crates.io |
| async-broadcast | 0.7.2 |  | ✓ |  | crates.io |
| async-stream | 0.3.6 |  | ✓ |  | crates.io |
| atomic-waker | 1.1.2 | ✓ | ✓ | ✓ | crates.io |
| audit | 0.7.3 | ✓ |  |  | crates.io |
| axum | 0.8.9 | ✓ | ✓ | ✓ | crates.io |
| axum-core | 0.5.6 | ✓ | ✓ | ✓ | crates.io |
| aya | 0.14.0 |  | ✓ |  | crates.io |
| aya-obj | 0.3.0 |  | ✓ |  | crates.io |
| backon | 1.6.0 |  | ✓ |  | crates.io |
| base64 | 0.22.1 | ✓ | ✓ | ✓ | crates.io |
| bitflags | 2.13.1 | ✓ | ✓ |  | crates.io |
| block-buffer | 0.12.1 | ✓ |  |  | crates.io |
| byteorder | 1.5.0 | ✓ |  |  | crates.io |
| byteorder_slice | 3.0.0 | ✓ |  |  | crates.io |
| bytes | 1.12.1 | ✓ | ✓ | ✓ | crates.io |
| cfg-if | 1.0.4 | ✓ | ✓ | ✓ | crates.io |
| chacha20 | 0.10.1 | ✓ |  |  | crates.io |
| chrono | 0.4.45 | ✓ |  |  | crates.io |
| ciborium | 0.2.2 | ✓ |  |  | crates.io |
| ciborium-io | 0.2.2 | ✓ |  |  | crates.io |
| ciborium-ll | 0.2.2 | ✓ |  |  | crates.io |
| clap | 4.6.4 |  | ✓ |  | crates.io |
| clap | 4.6.6 | ✓ |  | ✓ | crates.io |
| clap_builder | 4.6.2 |  | ✓ |  | crates.io |
| clap_builder | 4.6.6 | ✓ |  | ✓ | crates.io |
| clap_lex | 1.1.0 | ✓ | ✓ | ✓ | crates.io |
| cmov | 0.5.4 | ✓ |  |  | crates.io |
| codespan-reporting | 0.13.1 | ✓ |  |  | crates.io |
| colorchoice | 1.0.5 | ✓ | ✓ | ✓ | crates.io |
| concurrent-queue | 2.5.0 |  | ✓ |  | crates.io |
| console-api | 0.9.0 | ✓ |  |  | crates.io |
| console-subscriber | 0.5.0 | ✓ |  |  | crates.io |
| const-oid | 0.10.2 | ✓ |  |  | crates.io |
| cpufeatures | 0.3.0 | ✓ |  |  | crates.io |
| crc32fast | 1.5.0 | ✓ | ✓ |  | crates.io |
| crossbeam-channel | 0.5.16 | ✓ |  |  | crates.io |
| crossbeam-deque | 0.8.7 | ✓ |  |  | crates.io |
| crossbeam-epoch | 0.9.20 | ✓ |  |  | crates.io |
| crossbeam-utils | 0.8.22 | ✓ | ✓ |  | crates.io |
| crypto-common | 0.2.2 | ✓ |  |  | crates.io |
| ctutils | 0.4.2 | ✓ |  |  | crates.io |
| daemonize | 0.5.0 | ✓ |  |  | crates.io |
| dashmap | 6.2.1 | ✓ |  |  | crates.io |
| deranged | 0.5.8 | ✓ |  |  | crates.io |
| derive_builder | 0.20.2 | ✓ |  |  | crates.io |
| derive_more | 2.1.1 |  | ✓ |  | crates.io |
| digest | 0.11.3 | ✓ |  |  | crates.io |
| dirs | 6.0.0 | ✓ |  |  | crates.io |
| dirs-sys | 0.5.0 | ✓ |  |  | crates.io |
| doc-comment | 0.3.4 | ✓ |  |  | crates.io |
| either | 1.17.0 | ✓ | ✓ |  | crates.io |
| encoding_rs | 0.8.35 | ✓ | ✓ |  | crates.io |
| encoding_rs_io | 0.1.7 |  | ✓ |  | crates.io |
| equivalent | 1.0.2 | ✓ | ✓ | ✓ | crates.io |
| errno | 0.3.14 | ✓ | ✓ | ✓ | crates.io |
| event-listener | 5.4.1 |  | ✓ |  | crates.io |
| event-listener-strategy | 0.5.4 |  | ✓ |  | crates.io |
| fastrand | 2.5.0 |  | ✓ |  | crates.io |
| fixedbitset | 0.5.7 | ✓ |  |  | crates.io |
| flate2 | 1.1.9 | ✓ |  |  | crates.io |
| fletcher | 1.0.0 | ✓ |  |  | crates.io |
| fnv | 1.0.7 | ✓ | ✓ | ✓ | crates.io |
| foldhash | 0.1.5 | ✓ |  |  | crates.io |
| foldhash | 0.2.0 |  | ✓ |  | crates.io |
| form_urlencoded | 1.2.2 |  | ✓ |  | crates.io |
| function_name | 0.3.0 | ✓ |  |  | crates.io |
| futures | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-channel | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-channel | 0.3.34 |  |  | ✓ | crates.io |
| futures-core | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-core | 0.3.34 |  |  | ✓ | crates.io |
| futures-executor | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-io | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-sink | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-sink | 0.3.34 |  |  | ✓ | crates.io |
| futures-task | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-task | 0.3.34 |  |  | ✓ | crates.io |
| futures-util | 0.3.33 | ✓ | ✓ |  | crates.io |
| futures-util | 0.3.34 |  |  | ✓ | crates.io |
| getrandom | 0.2.17 |  | ✓ |  | crates.io |
| getrandom | 0.3.4 | ✓ | ✓ |  | crates.io |
| getrandom | 0.4.3 | ✓ |  |  | crates.io |
| granit-parser | 0.0.7 |  | ✓ |  | crates.io |
| h2 | 0.4.15 | ✓ | ✓ | ✓ | crates.io |
| half | 2.7.1 | ✓ |  |  | crates.io |
| hashbrown | 0.14.5 | ✓ |  |  | crates.io |
| hashbrown | 0.15.5 | ✓ |  |  | crates.io |
| hashbrown | 0.16.1 |  | ✓ |  | crates.io |
| hashbrown | 0.17.1 | ✓ | ✓ | ✓ | crates.io |
| hashlink | 0.9.1 | ✓ |  |  | crates.io |
| hdrhistogram | 7.6.0 | ✓ |  |  | crates.io |
| hex | 0.4.3 | ✓ |  |  | crates.io |
| hmac | 0.13.0 | ✓ |  |  | crates.io |
| hostname | 0.4.2 | ✓ | ✓ |  | crates.io |
| http | 1.4.2 |  | ✓ |  | crates.io |
| http | 1.5.0 | ✓ |  | ✓ | crates.io |
| http-body | 1.1.0 | ✓ | ✓ | ✓ | crates.io |
| http-body-util | 0.1.4 | ✓ | ✓ |  | crates.io |
| http-body-util | 0.1.5 |  |  | ✓ | crates.io |
| httparse | 1.10.1 | ✓ | ✓ | ✓ | crates.io |
| httpdate | 1.0.3 | ✓ | ✓ | ✓ | crates.io |
| humantime | 2.4.0 | ✓ |  |  | crates.io |
| hybrid-array | 0.4.14 | ✓ |  |  | crates.io |
| hyper | 1.11.0 | ✓ | ✓ | ✓ | crates.io |
| hyper-rustls | 0.27.9 |  | ✓ |  | crates.io |
| hyper-timeout | 0.5.2 | ✓ | ✓ | ✓ | crates.io |
| hyper-util | 0.1.20 | ✓ | ✓ | ✓ | crates.io |
| iana-time-zone | 0.1.65 | ✓ |  |  | crates.io |
| indexmap | 2.14.0 | ✓ | ✓ | ✓ | crates.io |
| internet-checksum | 0.2.1 | ✓ |  |  | crates.io |
| ipnet | 2.12.1 | ✓ |  |  | crates.io |
| is_terminal_polyfill | 1.70.2 | ✓ | ✓ | ✓ | crates.io |
| itertools | 0.14.0 | ✓ |  |  | crates.io |
| itoa | 1.0.18 | ✓ | ✓ | ✓ | crates.io |
| jiff | 0.2.35 |  | ✓ |  | crates.io |
| jiff-core | 0.1.0 |  | ✓ |  | crates.io |
| json-patch | 4.2.0 |  | ✓ |  | crates.io |
| jsonpath-rust | 1.0.6 |  | ✓ |  | crates.io |
| jsonptr | 0.7.1 |  | ✓ |  | crates.io |
| k8s-openapi | 0.28.0 |  | ✓ |  | crates.io |
| kube | 4.2.0 |  | ✓ |  | crates.io |
| kube-client | 4.2.0 |  | ✓ |  | crates.io |
| kube-core | 4.2.0 |  | ✓ |  | crates.io |
| kube-runtime | 4.2.0 |  | ✓ |  | crates.io |
| lazy_static | 1.5.0 | ✓ | ✓ | ✓ | crates.io |
| libc | 0.2.189 | ✓ | ✓ | ✓ | crates.io |
| libmimalloc-sys | 0.1.49 | ✓ |  |  | crates.io |
| libyang | 2.2.0 | ✓ |  |  | crates.io |
| linux-raw-sys | 0.12.1 | ✓ |  |  | crates.io |
| lock_api | 0.4.14 | ✓ | ✓ | ✓ | crates.io |
| log | 0.4.33 | ✓ | ✓ | ✓ | crates.io |
| marked-yaml | 0.7.2 | ✓ |  |  | crates.io |
| matchers | 0.2.0 | ✓ | ✓ | ✓ | crates.io |
| matchit | 0.8.4 | ✓ | ✓ | ✓ | crates.io |
| md-5 | 0.11.0 | ✓ |  |  | crates.io |
| memchr | 2.8.3 | ✓ | ✓ | ✓ | crates.io |
| memoffset | 0.9.1 | ✓ | ✓ |  | crates.io |
| mimalloc | 0.1.52 | ✓ |  |  | crates.io |
| mime | 0.3.17 | ✓ | ✓ | ✓ | crates.io |
| miniz_oxide | 0.8.9 | ✓ |  |  | crates.io |
| mio | 1.2.2 | ✓ | ✓ | ✓ | crates.io |
| netlink-packet-audit | 0.5.1 | ✓ |  |  | crates.io |
| netlink-packet-core | 0.7.0 | ✓ |  |  | crates.io |
| netlink-packet-route | 0.20.1 | ✓ |  |  | git `github:zebra-rs/netlink-packet-route?branch=seg6` @ `b03a7385` |
| netlink-packet-utils | 0.5.2 | ✓ |  |  | crates.io |
| netlink-proto | 0.11.5 | ✓ |  |  | crates.io |
| netlink-sys | 0.8.8 | ✓ |  |  | crates.io |
| network-interface | 2.0.5 | ✓ |  |  | crates.io |
| nix | 0.27.1 | ✓ | ✓ |  | crates.io |
| nix | 0.31.3 | ✓ |  |  | crates.io |
| nohash-hasher | 0.2.0 |  | ✓ |  | crates.io |
| nom | 8.0.0 | ✓ |  |  | crates.io |
| nom-derive | 0.11.0 | ✓ |  |  | git `github:rust-bakery/nom-derive?branch=master` @ `f68f464f` |
| nu-ansi-term | 0.50.3 | ✓ | ✓ | ✓ | crates.io |
| num-conv | 0.2.2 | ✓ |  |  | crates.io |
| num-traits | 0.2.19 | ✓ | ✓ |  | crates.io |
| num_enum | 0.7.6 | ✓ |  |  | crates.io |
| num_threads | 0.1.7 | ✓ |  |  | crates.io |
| object | 0.39.1 |  | ✓ |  | crates.io |
| once_cell | 1.21.4 | ✓ | ✓ | ✓ | crates.io |
| openssl-probe | 0.2.1 |  | ✓ |  | crates.io |
| option-ext | 0.2.0 | ✓ |  |  | crates.io |
| ordered-float | 2.10.1 |  | ✓ |  | crates.io |
| parking | 2.2.1 |  | ✓ |  | crates.io |
| parking_lot | 0.12.5 | ✓ | ✓ | ✓ | crates.io |
| parking_lot_core | 0.9.12 | ✓ | ✓ | ✓ | crates.io |
| parol-macros | 1.0.0 | ✓ |  |  | crates.io |
| parol_runtime | 4.5.0 | ✓ |  |  | crates.io |
| pcap-file | 2.0.0 | ✓ |  |  | crates.io |
| pem | 3.0.6 |  | ✓ |  | crates.io |
| percent-encoding | 2.3.2 | ✓ | ✓ | ✓ | crates.io |
| pest | 2.8.8 |  | ✓ |  | crates.io |
| petgraph | 0.8.3 | ✓ |  |  | crates.io |
| pin-project | 1.1.13 | ✓ | ✓ | ✓ | crates.io |
| pin-project-lite | 0.2.17 | ✓ | ✓ | ✓ | crates.io |
| powerfmt | 0.2.0 | ✓ |  |  | crates.io |
| prefix-trie | 0.9.4 | ✓ |  |  | crates.io |
| procfs | 0.18.0 | ✓ |  |  | crates.io |
| procfs-core | 0.18.0 | ✓ |  |  | crates.io |
| prost | 0.14.4 | ✓ | ✓ | ✓ | crates.io |
| prost-types | 0.14.4 | ✓ | ✓ |  | crates.io |
| rand | 0.10.2 | ✓ |  |  | crates.io |
| rand_core | 0.10.1 | ✓ |  |  | crates.io |
| rayon | 1.12.0 | ✓ |  |  | crates.io |
| rayon-core | 1.13.0 | ✓ |  |  | crates.io |
| regex | 1.13.1 | ✓ | ✓ |  | crates.io |
| regex-automata | 0.4.16 |  | ✓ |  | crates.io |
| regex-automata | 0.4.18 | ✓ |  | ✓ | crates.io |
| regex-syntax | 0.8.11 | ✓ | ✓ | ✓ | crates.io |
| ring | 0.17.14 |  | ✓ |  | crates.io |
| rs-pfcp | 0.3.1 | ✓ |  |  | crates.io |
| rtnetlink | 0.14.1 | ✓ |  |  | git `github:zebra-rs/rtnetlink?rev=2d7b1830e9bd9a049a757f0a79ccd16216450bf2` @ `2d7b1830` |
| rustix | 1.1.4 | ✓ |  |  | crates.io |
| rustls | 0.23.42 |  | ✓ |  | crates.io |
| rustls-native-certs | 0.8.4 |  | ✓ |  | crates.io |
| rustls-pki-types | 1.15.1 |  | ✓ |  | crates.io |
| rustls-platform-verifier | 0.7.0 |  | ✓ |  | crates.io |
| rustls-webpki | 0.103.13 |  | ✓ |  | crates.io |
| ryu | 1.0.23 | ✓ |  |  | crates.io |
| same-file | 1.0.6 | ✓ |  |  | crates.io |
| scan_fmt | 0.2.6 | ✓ |  |  | crates.io |
| scnr2 | 0.5.2 | ✓ |  |  | crates.io |
| scopeguard | 1.2.0 | ✓ | ✓ | ✓ | crates.io |
| secrecy | 0.10.3 |  | ✓ |  | crates.io |
| serde | 1.0.229 | ✓ | ✓ | ✓ | crates.io |
| serde-saphyr | 0.0.29 |  | ✓ |  | crates.io |
| serde-value | 0.7.0 |  | ✓ |  | crates.io |
| serde_core | 1.0.229 | ✓ | ✓ | ✓ | crates.io |
| serde_json | 1.0.151 | ✓ | ✓ | ✓ | crates.io |
| serde_yaml | 0.9.34+deprecated | ✓ |  |  | crates.io |
| serde_yaml_ng | 0.10.0 | ✓ |  |  | crates.io |
| sha1 | 0.11.0 | ✓ |  |  | crates.io |
| sha2 | 0.11.0 | ✓ |  |  | crates.io |
| sharded-slab | 0.1.7 | ✓ | ✓ | ✓ | crates.io |
| signal-hook-registry | 1.4.8 | ✓ | ✓ | ✓ | crates.io |
| simd-adler32 | 0.3.10 | ✓ |  |  | crates.io |
| similar | 3.1.2 | ✓ |  |  | crates.io |
| slab | 0.4.12 | ✓ | ✓ | ✓ | crates.io |
| smallvec | 1.15.2 | ✓ | ✓ | ✓ | crates.io |
| socket2 | 0.5.10 |  | ✓ |  | crates.io |
| socket2 | 0.6.5 | ✓ | ✓ | ✓ | crates.io |
| strsim | 0.11.1 | ✓ | ✓ | ✓ | crates.io |
| strum | 0.28.0 | ✓ |  |  | crates.io |
| subtle | 2.6.1 |  | ✓ |  | crates.io |
| symlink | 0.1.0 | ✓ |  |  | crates.io |
| sync_wrapper | 1.0.2 | ✓ | ✓ | ✓ | crates.io |
| syntree | 0.18.0 | ✓ |  |  | crates.io |
| syntree_layout | 0.4.0 | ✓ |  |  | crates.io |
| sysctl | 0.7.1 | ✓ |  |  | crates.io |
| syslog | 7.0.0 | ✓ |  |  | crates.io |
| termcolor | 1.4.1 | ✓ |  |  | crates.io |
| thiserror | 1.0.69 | ✓ |  |  | crates.io |
| thiserror | 2.0.19 | ✓ | ✓ |  | crates.io |
| thread_local | 1.1.10 | ✓ | ✓ | ✓ | crates.io |
| time | 0.3.55 | ✓ |  |  | crates.io |
| time-core | 0.1.9 | ✓ |  |  | crates.io |
| tokio | 1.53.1 |  | ✓ | ✓ | crates.io |
| tokio | 1.53.3 | ✓ |  |  | crates.io |
| tokio-rustls | 0.26.4 |  | ✓ |  | crates.io |
| tokio-stream | 0.1.19 | ✓ | ✓ | ✓ | crates.io |
| tokio-util | 0.7.19 | ✓ | ✓ | ✓ | crates.io |
| tonic | 0.14.6 | ✓ | ✓ | ✓ | crates.io |
| tonic-prost | 0.14.6 | ✓ | ✓ | ✓ | crates.io |
| tower | 0.5.3 | ✓ | ✓ | ✓ | crates.io |
| tower-http | 0.6.11 |  | ✓ |  | crates.io |
| tower-layer | 0.3.3 | ✓ | ✓ | ✓ | crates.io |
| tower-service | 0.3.3 | ✓ | ✓ | ✓ | crates.io |
| tracing | 0.1.44 | ✓ | ✓ | ✓ | crates.io |
| tracing-appender | 0.2.5 | ✓ |  |  | crates.io |
| tracing-core | 0.1.36 | ✓ | ✓ | ✓ | crates.io |
| tracing-log | 0.2.0 | ✓ | ✓ | ✓ | crates.io |
| tracing-serde | 0.2.0 | ✓ | ✓ |  | crates.io |
| tracing-subscriber | 0.3.23 | ✓ | ✓ | ✓ | crates.io |
| try-lock | 0.2.5 | ✓ | ✓ | ✓ | crates.io |
| typenum | 1.20.1 | ✓ |  |  | crates.io |
| ucd-trie | 0.1.7 |  | ✓ |  | crates.io |
| unicode-width | 0.2.2 | ✓ | ✓ |  | crates.io |
| unsafe-libyaml | 0.2.11 | ✓ |  |  | crates.io |
| untrusted | 0.9.0 |  | ✓ |  | crates.io |
| utf8parse | 0.2.2 | ✓ | ✓ | ✓ | crates.io |
| walkdir | 2.5.0 | ✓ |  |  | crates.io |
| want | 0.3.1 | ✓ | ✓ | ✓ | crates.io |
| xml_writer | 0.4.0 | ✓ |  |  | crates.io |
| yaml-rust2 | 0.9.0 | ✓ |  |  | crates.io |
| zerocopy | 0.8.55 |  | ✓ |  | crates.io |
| zerocopy | 0.8.56 | ✓ |  |  | crates.io |
| zeroize | 1.9.0 |  | ✓ |  | crates.io |
| zmij | 1.0.23 | ✓ | ✓ | ✓ | crates.io |

### B.2 First-party crates (workspace path dependencies)

- **zebra-rs:** `bfd-packet`, `bgp-packet`, `fixedbuf`, `isis-packet`, `nd-packet`, `ospf-packet`, `packet-utils`, `pim-packet`, `stamp-packet`, `vtyctl`, `vtyhelper`, `vtypam`, `zebra-rs`, `zebra-topology`
- **cradle-rs:** `cradle`, `cradle-cni`, `cradle-common`, `cradle-k8s`
- **insomnia:** `insomnia`

### B.3 Build-time-only crates (build scripts and proc-macros)

These crates run code on the build machine but are not linked into the binary.

- **zebra-rs (78):** array-const-fn-init 0.1.1, assert_cmd 2.2.2, async-trait 0.1.92, autocfg 1.5.1, bitfield-struct 0.13.0, bstr 1.13.0, cc 1.4.0, cfg_aliases 0.2.2, clap_derive 4.6.4, darling 0.20.11, darling_core 0.20.11, darling_macro 0.20.11, derive-into-owned 0.2.0, derive_builder_core 0.20.2, derive_builder_macro 0.20.2, difflib 0.4.0, enum-as-inner 0.6.1, env_filter 2.0.0, env_logger 0.11.11, fastrand 2.5.0, find-msvc-tools 0.1.9, function_name-proc-macro 0.3.0, futures-macro 0.3.33, heck 0.5.0, ident_case 1.0.1, jiff 0.2.35, jiff-core 0.1.0, lalry 0.1.0, multimap 0.10.1, nom-derive-impl 0.11.0, num_cpus 1.17.0, num_enum_derive 0.7.6, owo-colors 4.3.0, parol 4.7.0, paste 1.0.15, pin-project-internal 1.1.13, predicates 3.1.4, predicates-core 1.0.10, predicates-tree 1.0.13, prettyplease 0.2.37, proc-macro-crate 3.5.0, proc-macro2 1.0.107, prost-build 0.14.4, prost-derive 0.14.4, pulldown-cmark 0.13.4, pulldown-cmark-to-cmark 22.0.0, quote 1.0.47, rand_regex 0.19.0, rustc-hash 2.1.3, rustversion 1.0.23, scnr2_generate 0.5.2, scnr2_macro 0.5.2, serde_derive 1.0.229, shlex 2.0.1, strum_macros 0.28.0, syn 1.0.109, syn 2.0.119, syn 3.0.3, tempfile 3.27.0, termtree 0.5.1, thiserror-impl 1.0.69, thiserror-impl 2.0.19, tokio-macros 2.7.2, toml_datetime 1.1.1+spec-1.1.0, toml_edit 0.25.13+spec-1.1.0, toml_parser 1.1.3+spec-1.1.0, tonic-build 0.14.6, tonic-prost-build 0.14.6, tracing-attributes 0.1.31, ts-rs 12.0.1, ts-rs-macros 12.0.1, ume 0.1.0, unicase 2.9.0, unicode-ident 1.0.24, version_check 0.9.5, wait-timeout 0.2.1, winnow 1.0.4, zerocopy-derive 0.8.56
- **cradle-rs (52):** async-stream-impl 0.3.6, async-trait 0.1.91, autocfg 1.5.1, aya-build 0.2.0, camino 1.2.4, cargo-platform 0.3.3, cargo_metadata 0.23.1, cc 1.4.0, clap_derive 4.6.4, derive_more-impl 2.1.1, educe 0.6.0, enum-ordinalize 4.4.1, enum-ordinalize-derive 4.4.1, find-msvc-tools 0.1.9, fixedbitset 0.5.7, foldhash 0.1.5, futures-macro 0.3.33, getrandom 0.4.3, hashbrown 0.15.5, heck 0.5.0, itertools 0.14.0, linux-raw-sys 0.12.1, multimap 0.10.1, pest_derive 2.8.8, pest_generator 2.8.8, pest_meta 2.8.8, petgraph 0.8.3, pin-project-internal 1.1.13, prettyplease 0.2.37, proc-macro2 1.0.107, prost-build 0.14.4, prost-derive 0.14.4, pulldown-cmark 0.13.4, pulldown-cmark-to-cmark 22.0.0, quote 1.0.47, rustc_version 0.4.1, rustix 1.1.4, semver 1.0.28, serde_derive 1.0.229, shlex 2.0.1, syn 2.0.119, syn 3.0.3, tempfile 3.27.0, thiserror-impl 2.0.19, tokio-macros 2.7.1, tonic-build 0.14.6, tonic-prost-build 0.14.6, tracing-attributes 0.1.31, unicase 2.9.0, unicode-ident 1.0.24, version_check 0.9.5, which 8.0.5
- **insomnia (35):** async-trait 0.1.92, bitflags 2.13.1, clap_derive 4.6.4, either 1.17.0, fastrand 2.5.0, fixedbitset 0.5.7, foldhash 0.1.5, getrandom 0.4.3, hashbrown 0.15.5, heck 0.5.0, itertools 0.14.0, linux-raw-sys 0.12.1, multimap 0.10.1, petgraph 0.8.3, pin-project-internal 1.1.13, prettyplease 0.2.37, proc-macro2 1.0.107, prost-build 0.14.4, prost-derive 0.14.4, prost-types 0.14.4, pulldown-cmark 0.13.4, pulldown-cmark-to-cmark 22.0.1, quote 1.0.47, regex 1.13.1, rustix 1.1.4, serde_derive 1.0.229, syn 2.0.119, syn 3.0.3, tempfile 3.27.0, tokio-macros 2.7.2, tonic-build 0.14.6, tonic-prost-build 0.14.6, tracing-attributes 0.1.31, unicase 2.9.0, unicode-ident 1.0.24

## Appendix C: Adding insomnia to the ISO

Simulated with `apt-get -s install` in the 2026-10-22 rootfs (Appendix D, step 8):
- **From:** the first pocket apt names for that version.
- **Needed without Recommends:** ✓ means the package is still installed with
  `--no-install-recommends`.

Do not drop `libstrongswan-standard-plugins` with the other Recommends. It carries charon's
`openssl` and `gcm` plugins: RSA/ECDSA, (EC)DH and the AES-GCM proposals need them. Name it
explicitly. It also means strongSwan's cryptography comes from Ubuntu's `libssl3t64`, so OpenSSL
USNs apply to IPsec.

| Package | Version | Pocket | Comp. | Needed without Recommends |
|---|---|---|---|:-:|
| charon-systemd | 5.9.13-2ubuntu4.24.04.5 | noble-updates | universe | ✓ |
| insomnia | 0.2.0 | local | local | ✓ |
| ipvsadm | 1:1.31-1ubuntu0.1 | noble-updates | main |  |
| keepalived | 1:2.2.8-1build2 | noble | main | ✓ |
| libcharon-extauth-plugins | 5.9.13-2ubuntu4.24.04.5 | noble-updates | main |  |
| libedit2 | 3.1-20230828-1build1 | noble | main | ✓ |
| libgdbm6t64 | 1.23-5.1build1 | noble | main | ✓ |
| libgdbm-compat4t64 | 1.23-5.1build1 | noble | main | ✓ |
| libip4tc2 | 1.8.10-3ubuntu2 | noble | main |  |
| libjansson4 | 2.14-2build2 | noble | main | ✓ |
| libnftables1 | 1.0.9-1ubuntu0.1 | noble-updates | main | ✓ |
| libnftnl11 | 1.2.6-2build1 | noble | main | ✓ |
| libnl-3-200 | 3.7.0-0.3build1.1 | noble-updates | main | ✓ |
| libnl-genl-3-200 | 3.7.0-0.3build1.1 | noble-updates | main | ✓ |
| libpci3 | 1:3.10.0-2build1 | noble | main | ✓ |
| libperl5.38t64 | 5.38.2-3.2ubuntu0.6 | noble-updates | main | ✓ |
| libsensors5 | 1:3.6.0-9build1 | noble | main | ✓ |
| libsensors-config | 1:3.6.0-9build1 | noble | main | ✓ |
| libsnmp40t64 | 5.9.4+dfsg-1.1ubuntu3.2 | noble-updates | main | ✓ |
| libsnmp-base | 5.9.4+dfsg-1.1ubuntu3.2 | noble-updates | main | ✓ |
| libstrongswan | 5.9.13-2ubuntu4.24.04.5 | noble-updates | main | ✓ |
| libstrongswan-standard-plugins | 5.9.13-2ubuntu4.24.04.5 | noble-updates | main |  |
| libwrap0 | 7.6.q-33 | noble | main | ✓ |
| nftables | 1.0.9-1ubuntu0.1 | noble-updates | main | ✓ |
| pci.ids | 0.0~2024.03.31-1ubuntu0.1 | noble-updates | main | ✓ |
| perl | 5.38.2-3.2ubuntu0.6 | noble-updates | main |  |
| perl-base | 5.38.2-3.2ubuntu0.6 | noble-updates | main | ✓ |
| perl-modules-5.38 | 5.38.2-3.2ubuntu0.6 | noble-updates | main | ✓ |
| strongswan-libcharon | 5.9.13-2ubuntu4.24.04.5 | noble-updates | main | ✓ |
| strongswan-swanctl | 5.9.13-2ubuntu4.24.04.5 | noble-updates | universe | ✓ |

## Appendix D: Reproducing this snapshot

All of this runs rootless on an arm64 Ubuntu 24.04 host with folksy-rs set up as its
`contrib/mkiso/README.md` describes. `$W` is a scratch directory and `$ROOTFS` is `$W/mkiso/rootfs`.

**1. Build the rootfs with today's recipe.** Only the stages that install packages are needed:

```sh
cd folksy-rs/contrib/mkiso
WORKDIR=$W/mkiso ./mkiso.sh rootfs install > $W/build.log 2>&1
```

`build.log` has one "The following NEW packages will be installed" block per apt run:
1. debstrap's required set;
2. debstrap's important set;
3. `mkiso.sh`'s package list;
4. the local debs.

Those blocks give the Layer column in Appendix A.

**2. Pending updates (S1):**

```sh
folksy-rs spawn $ROOTFS apt-get -s dist-upgrade | grep '^Inst'
```

An `Inst` line whose origin includes `noble-security` is a known-fixed vulnerability.

**3. Recommends-only packages (S3):**

```sh
folksy-rs spawn $ROOTFS apt-get -s \
  -o APT::AutoRemove::RecommendsImportant=false \
  -o APT::AutoRemove::SuggestsImportant=false autoremove | grep '^Remv'
```

**4. Minimal set (S4, S10).** Run this on a scratch rootfs only: it rewrites apt's auto/manual
marks. `$KEEP` is the named list from `mkiso.sh` plus `apt` and `zstd`. Leave the Kea packages
out of it for the M3 row.

```sh
folksy-rs spawn $ROOTFS sh -c "
  dpkg-query -W -f='\${Package}\n' | xargs apt-mark auto >/dev/null
  dpkg-query -W -f='\${Package} \${Essential} \${Priority}\n' |
    awk '\$2==\"yes\" || \$3==\"required\" {print \$1}' | xargs apt-mark manual >/dev/null
  apt-mark manual $KEEP >/dev/null
  apt-get -s -o APT::AutoRemove::RecommendsImportant=false \
    -o APT::AutoRemove::SuggestsImportant=false autoremove" | grep '^Remv'
```

**5. Package inventory.** This reads the dpkg database and finds the pocket that carries each
installed version. It is the prototype for the `sbom` stage (§6.2):

```python
#!/usr/bin/env python3
"""inventory.py ROOTFS OUT.tsv: one row per installed package."""
import glob, os, sys

def stanzas(path):
    block, key = {}, None
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if not line:
            if block:
                yield block
            block, key = {}, None
        elif line[0] in " \t":
            if key:
                block[key] += "\n" + line
        else:
            key, _, v = line.partition(":")
            block[key] = v.strip()
    if block:
        yield block

root, out = sys.argv[1], sys.argv[2]
avail = {}  # (package, version) -> {(pocket, component)}
for p in glob.glob(os.path.join(root, "var/lib/apt/lists/*_binary-*_Packages")):
    dist, comp = os.path.basename(p).split("_dists_")[1].split("_")[:2]
    pocket = dist.split("-")[1] if "-" in dist else "release"
    for s in stanzas(p):
        avail.setdefault((s["Package"], s["Version"]), set()).add((pocket, comp))

with open(out, "w") as f:
    f.write("package\tversion\tsource\tcomponent\tpocket\tkib\n")
    for s in sorted(stanzas(os.path.join(root, "var/lib/dpkg/status")),
                    key=lambda s: s["Package"]):
        if not s.get("Status", "").endswith(" installed"):
            continue
        hits = avail.get((s["Package"], s["Version"]), set())
        f.write("\t".join([
            s["Package"], s["Version"], s.get("Source", s["Package"]).split(" ")[0],
            ",".join(sorted({c for _, c in hits})) or "local",
            ",".join(sorted({p for p, _ in hits})) or "-",
            s.get("Installed-Size", "0"),
        ]) + "\n")
```

```sh
python3 -I inventory.py $ROOTFS $W/inventory.tsv
```

**6. Rust crates.** Run this per shipped binary package:
- zebra-rs: `zebra-rs vtyctl vtyhelper vtypam zebra-topology`;
- cradle-rs: `cradle cradle-cni cradle-k8s`;
- insomnia: `insomnia`.

```sh
# Linked into the binary
cargo tree --locked --color never -p <pkg> --target aarch64-unknown-linux-gnu \
  -e normal,no-proc-macro --prefix none -f '{p}' | sed 's/ (\*)$//' | sort -u
# The whole build closure (adds build scripts and proc-macros)
cargo tree --locked --color never -p <pkg> --target aarch64-unknown-linux-gnu \
  -e normal,build --prefix none -f '{p}' | sed 's/ (\*)$//;s/ (proc-macro)$//' | sort -u
```

zebra-rs has no committed lock file (S5), so `--locked` fails there. Without it, cargo resolves
a lock file first, and the result reflects the day it runs.

Crates that bundle native code show up in `cargo metadata --filter-platform
aarch64-unknown-linux-gnu`:
- the package declares a `links` key, or
- it has a `cc` build-dependency.

Check each hit by hand. `network-interface` declares `cc` but compiles C only for BSD and macOS.

**7. Shared libraries each binary loads:**

```sh
readelf -d $ROOTFS/usr/bin/<binary> | grep NEEDED
```

**8. The insomnia addition (Appendix C):**

```sh
folksy-rs spawn --bind insomnia_0.2.0_arm64.deb:/tmp/insomnia.deb $ROOTFS \
  apt-get -s [--no-install-recommends] install /tmp/insomnia.deb \
  strongswan-swanctl charon-systemd keepalived | grep '^Inst'
```

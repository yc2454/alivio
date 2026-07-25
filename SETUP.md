# Setup

alivio has three usage tiers. Each one adds requirements to the one before
it — **pick the lowest tier that covers what you need**, since only tier 3
requires Linux, KVM, and a patched kernel.

| Tier | What you can do | What it needs | Platform |
|---|---|---|---|
| **1 — Verifier** | Verify `.o` / `.c` / `.json` programs in zone or kernel mode, run PCC, run selftests and corpus sweeps | Rust toolchain | Linux, macOS |
| **2 — Proofs** | …plus generate `.bcf-bundle` proof bundles | + BCF-patched cvc5 | Linux, macOS |
| **3 — Kernel discharge** | …plus watch a patched kernel *accept* those programs at load time | + patched kernel, VM image, in-VM loaders | Linux + KVM |

Tier 1 is a two-minute `cargo build`. Tier 3 is roughly an hour on a fresh
Linux box. The [README](README.md) explains what the tool does and what the
flags mean; this document is only about getting it running.

---

# Tier 1 — the verifier

Everything except proof emission: both numeric domains, kernel-mode
mirroring, PCC certificates, the selftest and corpus harnesses.

## 1.1 Build

Requires a Rust toolchain (via [rustup](https://rustup.rs)); no minimum
version beyond what `Cargo.toml` resolves.

```bash
git clone https://github.com/yc2454/alivio.git
cd alivio
cargo build --release
```

The binary lands at `./target/release/alivio`. Add it to `$PATH` if you
like; this document spells out the relative path throughout.

## 1.2 Smoke test

Three inputs, three formats, all shipped in the repo — no external data
needed:

```bash
# ELF object
./target/release/alivio verify bcf-tests/system_monitor.bpf.o     # → PASS

# Legacy JSON test catalogue (single case)
./target/release/alivio verify selftests/legacy/verifier/calls.json \
    --test "calls: basic sanity"                                  # → PASS

# Proof-Carrying Code round trip (generate + check)
./target/release/alivio pcc cycle selftests/legacy/verifier/calls.json \
    --test "calls: basic sanity"                                  # → PASS
```

Run the unit tests too, if you want the full picture:

```bash
cargo test
```

## 1.3 Optional: clang, for C selftests

Verifying `.c` sources (`alivio verify prog.c`, `alivio dev selftest-file`,
`alivio dev selftest-suite`) compiles them with `clang -target bpf` first.
You need clang with a BPF backend — any reasonably recent LLVM.

```bash
# Debian/Ubuntu
sudo apt install -y clang llvm
# macOS (Apple's clang has no BPF target; use Homebrew LLVM)
brew install llvm
```

alivio resolves clang in this order: `$BPF_CLANG`, then
`/opt/homebrew/opt/llvm/bin/clang` (macOS), then `clang` on `$PATH`. Set
`BPF_CLANG` explicitly if you have several toolchains:

```bash
export BPF_CLANG=/usr/lib/llvm-18/bin/clang
```

Kernel and libbpf headers are **vendored** under
`selftests/headers/v6.15/`, so you do *not* need a kernel checkout or a
system libbpf for this. Try it:

```bash
./target/release/alivio dev selftest-file selftests/progs/bpf_dctcp.c
# → per-program PASS/FAIL lines, e.g. "(5 / 6 pass)"
```

> **Caveat.** A minority of the upstream selftests `#include` headers that
> are not vendored (for example `cb_refs.c` reaches for
> `../test_kmods/bpf_testmod_kfunc.h`). Those fail at the clang step with a
> `file not found` error rather than a verification result, and exit **2**
> — distinct from a verification FAIL, so a scripted sweep can tell "didn't
> build" from "built and was rejected". Use a full upstream tree (§1.4) if
> you need them.

## 1.4 Optional: an upstream kernel tree, for full selftest sweeps

`selftests/progs/` holds a curated subset. The `*-upstream` harness
commands instead sweep a real kernel checkout, which is what the
"3267+ PASS" baseline figure comes from. `vendor/` is gitignored, so a
fresh clone does not have one — check out the tag in
[`selftests/SOURCE_TAG`](selftests/SOURCE_TAG) (currently `v6.15`):

```bash
git clone --depth 1 --branch v6.15 \
    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git \
    vendor/linux
```

Then:

```bash
# Sweep the upstream tree
./target/release/alivio --kernel-mode dev selftest-suite \
    vendor/linux/tools/testing/selftests/bpf/progs

# Write a baseline, then gate future changes against it
./target/release/alivio dev selftest-baseline-write-upstream vendor/linux base.json
./target/release/alivio dev selftest-baseline-check-upstream vendor/linux base.json
```

A full sweep takes a while; `scripts/parallel_selftest.py` does the same
job across cores in minutes.

## 1.5 Optional: Python, for the corpus harnesses

The harnesses in `scripts/` need **python3 only — no pip install, no
virtualenv**; they import nothing outside the standard library. They shell
out to `alivio dev verify-corpus` and post-process its JSONL.

```bash
python3 scripts/triage_frs.py --help
```

---

# Tier 2 — proof bundles

Adds `--bcf`: alivio proves the side-conditions behind its own rejections
and writes a `.bcf-bundle` sidecar. This needs a **BCF-patched cvc5** —
stock cvc5 will not work, because the bundle carries cvc5's binary proof
objects in the BCF proof format.

## 2.1 Build the patched cvc5

It comes from the [BCF project](https://github.com/SunHao-0/BCF):

```bash
git clone https://github.com/SunHao-0/BCF ~/BCF
cd ~/BCF
./scripts/install-deps.sh    # build dependencies
./scripts/build.sh solver    # ~15 min → ~/BCF/output/cvc5-libs/bin/cvc5
```

> **If `build.sh solver` fails partway through:** it decides "already
> built, skipping" from the presence of a build directory, not from whether
> the previous run succeeded. Fixing the underlying error and re-running
> will skip rather than retry. Wipe the partial state first:
>
> ```bash
> rm -rf ~/BCF/build/cvc5-*
> ```

You only need `build.sh solver` here. Do **not** run `build.sh kernel` —
see §3.4 for why.

## 2.2 Point alivio at it

```bash
export ALIVIO_CVC5=~/BCF/output/cvc5-libs/bin/cvc5
```

Add that to your shell profile to persist it. This is the one environment
variable alivio genuinely requires; everything else is print-only
diagnostics.

> **Cross-platform trap.** A cvc5 binary built on Linux will not run on
> macOS, and alivio's failure mode is unhelpful if you point at the wrong
> one. If you work on both, keep separate builds and set `ALIVIO_CVC5` per
> machine rather than syncing a dotfile.

## 2.3 Smoke test

```bash
./target/release/alivio --bcf --kernel-mode verify bcf-tests/shift_constraint.bpf.o
```

Expect a proof line, a bundle line, and a `Success!`:

```
[INFO] [bcf] refined stack-OOB at base=R2 off=0 size=1: cvc5 proof 11688 bytes (hash 53bad2296570f686)
[INFO] [bcf] wrote bundle: bcf-tests/shift_constraint.bpf.o.bcf-bundle (1 entries, 11920 bytes)
[Verifier] Success! Verified 13 instructions (pruned 1 states).
```

Without `--bcf` the same object is rejected (`Stack out of bounds at pc
9`) — that contrast is the whole point of the tool. Proof and bundle byte
counts vary with your cvc5 build; the canonical hash does not.

More sample objects are in `bcf-tests/`. `--bcf` is only meaningful
together with `--kernel-mode`, since the goals must match the ones the real
kernel needs discharged.

---

# Tier 3 — end-to-end kernel discharge

This tier proves the loop closes: a BCF-patched kernel, handed alivio's
bundle, accepts a program it would otherwise reject. It needs **one Linux
host with sudo and KVM** (Ubuntu 22.04+ / Debian 12+; Cloudlab Ubuntu
profiles work as-is), because it boots a VM running our patched kernel.

alivio sits on top of [BCF](https://github.com/SunHao-0/BCF) here too: we
reuse its dependency set, VM image, in-VM bpftool/cvc5, and qemu launcher.
We ship our own kernel `bzImage`, patched libbpf, and loaders.

## 3.0 Prerequisites

BCF's `install-deps.sh` sources `vars.sh`, which fatals immediately if
`virtiofsd` isn't already on `PATH` — so virtiofsd must be installed
*before* BCF's installer runs, not by it. Same for the Rust toolchain
(needed to build virtiofsd) and virtiofsd's link dependencies.

```bash
sudo apt update
sudo apt install -y libseccomp-dev libcap-ng-dev \
                    python3-venv \
                    clang llvm libbpf-dev dwarves

# Rust toolchain
command -v cargo >/dev/null || \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# virtiofsd
command -v virtiofsd >/dev/null || cargo install virtiofsd

# KVM access — qemu opens /dev/kvm (root:kvm). Add yourself to the kvm
# group, then log out and back in (or `newgrp kvm`) so it takes effect.
sudo usermod -aG kvm $USER
newgrp kvm
```

## 3.1 Clone BCF and install its dependencies

```bash
git clone https://github.com/SunHao-0/BCF ~/BCF
cd ~/BCF
./scripts/install-deps.sh   # kernel + cvc5 + qemu deps
```

## 3.2 Download the BCF VM image

The image is ~4.7 GB, so put it somewhere with room:

```bash
cd ~/BCF/imgs
wget -O imgs.zip 'https://zenodo.org/records/17542583/files/imgs.zip?download=1'
unzip imgs.zip
chmod 600 bookworm.id_rsa
```

> **If `$HOME` is quota-limited** (Cloudlab home directories are), stage the
> image on a larger filesystem and symlink it into `~/BCF/imgs/`, where
> BCF's scripts look for it:
>
> ```bash
> BIGDISK=/proj/your-project    # Cloudlab: /proj/<project>-PG0
> mkdir -p "$BIGDISK/bcf-vm" && cd "$BIGDISK/bcf-vm"
> wget -O imgs.zip 'https://zenodo.org/records/17542583/files/imgs.zip?download=1'
> unzip imgs.zip && chmod 600 bookworm.id_rsa
> for f in bookworm.img bookworm.id_rsa bookworm.id_rsa.pub; do
>     ln -sf "$BIGDISK/bcf-vm/$f" ~/BCF/imgs/$f
> done
> ```

## 3.3 Build cvc5

Same as [§2.1](#21-build-the-patched-cvc5) — if you already did tier 2,
skip ahead.

```bash
cd ~/BCF && ./scripts/build.sh solver
export ALIVIO_CVC5=~/BCF/output/cvc5-libs/bin/cvc5
```

## 3.4 Fetch the prebuilt kernel and libbpf

We deliberately skip BCF's `./scripts/build.sh kernel`: it clones bpf-next
and re-applies BCF's patches, which takes ~30 min, currently fails on patch
drift, and wouldn't produce the right libbpf anyway — our loaders call
`bpf_program__set_bcf_bundle()`, an alivio addition not in upstream BCF.
Use our prebuilt artifacts instead:

```bash
# Kernel bzImage → BCF's output dir
wget -O ~/BCF/output/bzImage \
    https://github.com/yc2454/alivio/releases/download/kernel-47b3934f7ad8/bzImage
echo "0755cb22fd116733714dad663c80bfd122bfbe247cd565691f3385bfc5249d6a  $HOME/BCF/output/bzImage" \
    | sha256sum -c -

# Patched libbpf → the path §3.6's `gcc -I` expects
mkdir -p ~/BCF/build/bpf-next/tools/lib
wget -O /tmp/libbpf-alivio.tar.gz \
    https://github.com/yc2454/alivio/releases/download/kernel-47b3934f7ad8/libbpf-alivio.tar.gz
echo "3c4221b1d6275d2506d408c0f3d704a2d9b0a86b5a07f0b223810ffa93d844a9  /tmp/libbpf-alivio.tar.gz" \
    | sha256sum -c -
tar -xzf /tmp/libbpf-alivio.tar.gz -C ~/BCF/build/bpf-next/tools/lib
```

Current pin: kernel `6.18.0-rc4-g47b3934f7ad8` (branch `userspace-bcf`);
libbpf = bpf-next + BCF set5 + 3 alivio patches (adding
`bpf_program__set_bcf_bundle`).

The kernel-side source of truth is [`linux-deltas/`](linux-deltas) in this
repo: four patches (canonical hash, bundle UAPI, bundle parser/lookup,
per-site discharge hook) plus the headers and `kernel/bpf/` sources they
touch. Read those if you want to rebuild the kernel yourself rather than
take our binary.

## 3.5 Boot the VM

In a tmux/screen pane — the VM is a child of the shell and dies with it:

```bash
cd ~/BCF
./scripts/boot_vm.sh    # qemu + virtiofs share ~/BCF → /root/bcf; ssh on localhost:10023
```

Verify from another shell:

```bash
ssh -i ~/BCF/imgs/bookworm.id_rsa -p 10023 root@localhost "uname -r"
# Expected: 6.18.0-rc4-g47b3934f7ad8
```

If `uname -r` shows anything else, the bzImage in §3.4 didn't land.

## 3.6 Build the in-VM loaders

The loader sources live in this repo and are compiled *inside* the VM
against the patched libbpf:

Run these from your alivio checkout (whatever you named it — the shell
snippets below use `$ALIVIO` for it):

```bash
export ALIVIO=$PWD          # from inside the checkout
mkdir -p ~/BCF/sweep
cp $ALIVIO/linux-deltas/test_loader.c ~/BCF/sweep/
cp $ALIVIO/linux-deltas/ll2_loader.c  ~/BCF/sweep/

ssh -i ~/BCF/imgs/bookworm.id_rsa -p 10023 root@localhost <<'EOF'
cd /root/bcf/sweep
LIBBPF=/root/bcf/build/bpf-next/tools/lib
gcc -O2 -I$LIBBPF -o test_loader test_loader.c $LIBBPF/bpf/libbpf.a -lelf -lz
gcc -O2 -I$LIBBPF -o ll2_loader  ll2_loader.c  $LIBBPF/bpf/libbpf.a -lelf -lz
EOF
```

* `test_loader` — load an object, optionally with a bundle; `--per-prog`
  for the false-accept oracle.
* `ll2_loader` — the same, but with kernel verifier `log_level=2` for
  debugging a rejection.

## 3.7 Smoke test

Build a bundle on the host, load it in the VM:

```bash
cd $ALIVIO
cp bcf-tests/shift_constraint.bpf.o ~/BCF/sweep/
./target/release/alivio --bcf --kernel-mode verify ~/BCF/sweep/shift_constraint.bpf.o

ssh -i ~/BCF/imgs/bookworm.id_rsa -p 10023 root@localhost \
  "/root/bcf/sweep/test_loader /root/bcf/sweep/shift_constraint.bpf.o \
                               /root/bcf/sweep/shift_constraint.bpf.o.bcf-bundle"
# Expected: SUCCESS: loaded 1/1 program(s)
```

Loading the same object *without* the bundle argument should fail — that
difference is the result this tier exists to demonstrate.

## 3.8 Interactive demo

[`scripts/demo_e2e.sh`](scripts/demo_e2e.sh) walks any BPF object through
the full kernel-rejects → alivio-discharges → kernel-accepts story, pausing
between steps and dumping bundle contents:

```bash
scripts/demo_e2e.sh <prog.bpf.o> [--type TYPE] [--no-pause]
```

Good starter objects, each a small program the kernel rejects alone but
alivio can discharge:

```bash
scripts/demo_e2e.sh bcf-tests/shift_constraint.bpf.o --type tracepoint
scripts/demo_e2e.sh bcf-tests/stack_ptr_varoff.bpf.o
scripts/demo_e2e.sh bcf-tests/unreachable_arsh.bpf.o
```

Objects outside `~/BCF/` are copied into `~/BCF/sweep/` so the VM sees them
over virtiofs. Default program type is `classifier`; pass `--type xdp` /
`kprobe` / `tracepoint` for other hooks.

---

# Reproducing the published results

With tier 3 working:

* **The 36-object load gate** — `scripts/box_gate2.sh <listfile>` builds
  bundles in parallel and kernel-loads each, checking full discharge. List
  lines are `<srcdir> <name> <type>`. Set `ALIVIO_CVC5` first; tune `JOBS`
  and `VMJOBS` to your core count.
* **The full 360-object target** (calico 337, cilium 17, bcc 3, Inspektor
  Gadget 3) is built from third-party BPF objects that this repo does not
  vendor; see [`scripts/bench_e2e.py`](scripts/bench_e2e.py) for the
  harness and the README's status section for what the number means.
* **The false-accept scorecard** — `scripts/fa_scorecard.py` runs alivio
  against fixed oracles and exits non-zero on any false accept.

Cilium objects need `--type classifier` and a generous per-load timeout
(≥1500 s).

---

# Environment variables

Only `ALIVIO_CVC5` changes what alivio can do; the rest are print-only
diagnostics or operational conveniences. The README has the full
diagnostic table.

| Variable | Purpose | Tier |
|---|---|---|
| `ALIVIO_CVC5` | Absolute path to the BCF-patched cvc5 | 2, 3 |
| `BPF_CLANG` | clang binary used to compile `.c` selftests | 1 |
| `ALIVIO_BUNDLE_KEEP=1` | Append rather than clear the bundle (multi-pass builds) | 2, 3 |
| `ALIVIO_BCF_EAGER_FLUSH=<path>` | Flush the bundle after every push, for runs that may be killed | 2, 3 |
| `ALIVIO_BCF_DUMP_SMT=<dir>` | Dump per-site SMT-LIB queries to `<dir>` | 2, 3 |

Kernel-shape exploration is the `--kernel-mode` **flag**, not an
environment variable.

---

# Troubleshooting

**Tier 1**

* *`clang failed compiling …: '…' file not found`* — that selftest includes
  a header we don't vendor. Use an upstream kernel tree (§1.4), or pick a
  different program.
* *`clang: error: unknown target 'bpf'`* — Apple's clang has no BPF
  backend. Install Homebrew LLVM and set `BPF_CLANG` (§1.3).
* *`FAIL: Complexity limit of 1000000 exceeded`* — raise `--max-insn`. See
  the README's troubleshooting section for the other verifier messages.

**Tier 2**

* *`cvc5 binary not found at …`* — set `ALIVIO_CVC5` (§2.2); re-run
  `build.sh solver` if the binary really is missing.
* *cvc5 runs but no bundle appears* — the goals didn't discharge. Check
  you passed `--kernel-mode` alongside `--bcf`.
* *`build.sh solver` skips instead of rebuilding* — `rm -rf ~/BCF/build/cvc5-*`.

**Tier 3**

* *`gcc: bpf/libbpf.h: No such file or directory`* — §3.4's libbpf tarball
  didn't extract where expected. Confirm
  `ls ~/BCF/build/bpf-next/tools/lib/bpf/libbpf.h`.
* *`ld: cannot find -lbpf`* — don't use `-lbpf`; link
  `$LIBBPF/bpf/libbpf.a` directly (§3.6).
* *`test_loader: -EACCES` / "invalid bpf_bundle"* — alivio and the kernel
  are out of sync. Confirm the kernel is the §3.4 pin and alivio is current.
* *VM hangs on `boot_vm.sh`* — stale virtiofsd socket:
  `rm -f ~/BCF/output/bpf-test.sock` and retry.
* *`boot_vm.sh` exits when ssh disconnects* — the VM is a child of the
  shell. Use tmux or screen.
* *`uname -r` doesn't show the pinned SHA* — the bzImage wasn't replaced
  (§3.4). Check `stat ~/BCF/output/bzImage`.

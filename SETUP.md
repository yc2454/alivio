# Setup

One Linux host (Ubuntu 22.04+ / Debian 12+, sudo, KVM). Cloudlab Ubuntu
profiles work as-is.

alivio sits on top of [BCF](https://github.com/SunHao-0/BCF): we reuse its
deps, VM image, in-VM bpftool/cvc5, qemu launcher, and patched libbpf. We
ship our own kernel `bzImage` and the verifier binary.

---

## 0. Prerequisites (install before BCF's installer)

BCF's `install-deps.sh` sources `vars.sh`, which fatals immediately if
`virtiofsd` isn't already on `PATH` — so virtiofsd has to be installed
*before* BCF's installer runs, not by it. Same for the Rust toolchain
(needed to build virtiofsd) and virtiofsd's link deps.

```bash
sudo apt update
sudo apt install -y libseccomp-dev libcap-ng-dev \
                    python3-venv \
                    clang llvm libbpf-dev dwarves

# Rust toolchain
command -v cargo >/dev/null || \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# install virtiofsd
command -v virtiofsd >/dev/null || cargo install virtiofsd

# KVM access — qemu opens /dev/kvm (root:kvm). Add yourself to the kvm
# group, then log out + back in (or `newgrp kvm`) so the new group
# membership takes effect.
sudo usermod -aG kvm $USER
newgrp kvm
```

## 1. Clone BCF and install dependencies

```bash
git clone https://github.com/SunHao-0/BCF ~/BCF
cd ~/BCF
./scripts/install-deps.sh   # kernel + cvc5 + qemu deps
```

## 2. Download the BCF VM image

The image is ~4.7 GB. **On cloudlab, your `$HOME` quota is too small** —
put it under `/proj/ebpf-PG0/`:

```bash
# Cloudlab:
mkdir -p /proj/ebpf-PG0/bcf-vm
cd /proj/ebpf-PG0/bcf-vm
wget -O imgs.zip 'https://zenodo.org/records/17542583/files/imgs.zip?download=1'
unzip imgs.zip
chmod 600 bookworm.id_rsa

# Then symlink into ~/BCF/imgs/ (where BCF's scripts look):
ln -sf /proj/ebpf-PG0/bcf-vm/bookworm.img     ~/BCF/imgs/bookworm.img
ln -sf /proj/ebpf-PG0/bcf-vm/bookworm.id_rsa  ~/BCF/imgs/bookworm.id_rsa
ln -sf /proj/ebpf-PG0/bcf-vm/bookworm.id_rsa.pub ~/BCF/imgs/bookworm.id_rsa.pub
```

Non-cloudlab boxes: skip the symlinks, just `cd ~/BCF/imgs && wget … && unzip …`.

## 3. Build BCF's cvc5

```bash
cd ~/BCF
./scripts/build.sh solver   # ~15 min — produces ~/BCF/output/cvc5-libs/bin/cvc5
```

We don't run `./scripts/build.sh kernel` — it would clone bpf-next and
re-apply BCF's patches, which (a) takes ~30 min, (b) currently fails on
patch drift, and (c) wouldn't give us the right libbpf anyway (our
loaders use `bpf_program__set_bcf_bundle()`, a alivio addition not in
upstream BCF). We fetch alivio's prebuilt kernel + libbpf in step 4
instead.

> **Heads-up if `build.sh solver` fails partway through:** it decides
> "already built, skipping" based on the presence of a build directory,
> not on whether the previous run actually succeeded. If you fix the
> underlying error and re-run, it will skip instead of retrying. Wipe
> the partial state first:
>
> ```bash
> rm -rf ~/BCF/build/cvc5-*
> ```

## 4. Fetch alivio's prebuilt kernel + libbpf

```bash
# 4a. Kernel bzImage → drops into BCF's output dir
wget -O ~/BCF/output/bzImage \
    https://github.com/yc2454/alivio/releases/download/kernel-47b3934f7ad8/bzImage
echo "0755cb22fd116733714dad663c80bfd122bfbe247cd565691f3385bfc5249d6a  $HOME/BCF/output/bzImage" \
    | sha256sum -c -

# 4b. Patched libbpf → drops into the path step 7's gcc -I expects
mkdir -p ~/BCF/build/bpf-next/tools/lib
wget -O /tmp/libbpf-alivio.tar.gz \
    https://github.com/yc2454/alivio/releases/download/kernel-47b3934f7ad8/libbpf-alivio.tar.gz
echo "3c4221b1d6275d2506d408c0f3d704a2d9b0a86b5a07f0b223810ffa93d844a9  /tmp/libbpf-alivio.tar.gz" \
    | sha256sum -c -
tar -xzf /tmp/libbpf-alivio.tar.gz -C ~/BCF/build/bpf-next/tools/lib
```

Current pin: kernel `6.18.0-rc4-g47b3934f7ad8` (branch `userspace-bcf`),
libbpf = bpf-next + BCF set5 + 3 alivio patches (adds
`bpf_program__set_bcf_bundle`).

## 5. Build alivio

```bash
git clone https://github.com/yc2454/alivio.git ~/eBPF-Zone-Verifier
cd ~/eBPF-Zone-Verifier
git checkout 37d9fdeca8dd75f12bab435546ade867f9539eb5 # Stable commit
cargo build --release
export ALIVIO_CVC5=~/BCF/output/cvc5-libs/bin/cvc5
```

Add the `export` line to `~/.bashrc` to persist.

## 6. Boot the VM

In a tmux/screen pane (VM dies when the parent shell exits):

```bash
cd ~/BCF
./scripts/boot_vm.sh        # qemu + virtiofs share ~/BCF → /root/bcf, ssh on localhost:10023
```

Verify from another shell:

```bash
ssh -i ~/BCF/imgs/bookworm.id_rsa -p 10023 root@localhost "uname -r"
# Expected: 6.18.0-rc4-g47b3934f7ad8
```

## 7. Build the in-VM loaders

```bash
mkdir ~/BCF/sweep

cp ~/eBPF-Zone-Verifier/linux-deltas/test_loader.c ~/BCF/sweep/
cp ~/eBPF-Zone-Verifier/linux-deltas/ll2_loader.c  ~/BCF/sweep/

ssh -i ~/BCF/imgs/bookworm.id_rsa -p 10023 root@localhost <<'EOF'
cd /root/bcf/sweep
LIBBPF=/root/bcf/build/bpf-next/tools/lib
gcc -O2 -I$LIBBPF -o test_loader test_loader.c $LIBBPF/bpf/libbpf.a -lelf -lz
gcc -O2 -I$LIBBPF -o ll2_loader  ll2_loader.c  $LIBBPF/bpf/libbpf.a -lelf -lz
EOF
```

- `test_loader` — load object (+ optional bundle); `--per-prog` for the FA oracle.
- `ll2_loader` — same, but with kernel verifier `log_level=2` for debugging.

## 8. Smoke test

```bash
cd ~/eBPF-Zone-Verifier
OBJ=~/BCF/examples/shift_constraint.bpf.o
./target/release/alivio --bcf --kernel-mode verify "$OBJ"   # writes $OBJ.bcf-bundle

ssh -i ~/BCF/imgs/bookworm.id_rsa -p 10023 root@localhost \
  "/root/bcf/sweep/test_loader /root/bcf/examples/shift_constraint.bpf.o \
                               /root/bcf/examples/shift_constraint.bpf.o.bcf-bundle"
# Expected: SUCCESS: loaded 1/1 program(s)
```

## 9. Interactive end-to-end demo

Once the smoke test passes, [`scripts/demo_e2e.sh`](scripts/demo_e2e.sh)
walks any BPF object through the full kernel-rejects → alivio-discharges →
kernel-accepts story, with pauses between steps and a bundle-contents
dump:

```bash
~/eBPF-Zone-Verifier/scripts/demo_e2e.sh <prog.bpf.o> [--type TYPE] [--no-pause]
```

Three good starter objects ship with BCF — each is a small program the
kernel verifier rejects on its own but alivio can discharge:

```bash
~/eBPF-Zone-Verifier/scripts/demo_e2e.sh ~/BCF/examples/shift_constraint.bpf.o
~/eBPF-Zone-Verifier/scripts/demo_e2e.sh ~/BCF/examples/stack_ptr_varoff.bpf.o
~/eBPF-Zone-Verifier/scripts/demo_e2e.sh ~/BCF/examples/unreachable_arsh.bpf.o
```

If `<prog.bpf.o>` lives outside `~/BCF/`, the script copies it into
`~/BCF/sweep/` so the VM can see it via virtiofs. Default program type
is `classifier`; pass `--type xdp` / `kprobe` / etc. for other hooks.

---

## Environment variables

| Variable                    | Purpose                                                       |
|-----------------------------|---------------------------------------------------------------|
| `ALIVIO_CVC5`                | Absolute path to cvc5 (`~/BCF/output/cvc5-libs/bin/cvc5`)     |
| `ALIVIO_BUNDLE_KEEP=1`       | Append discharge entries (multi-pass bundle build)            |
| `ALIVIO_KERNEL_ENGINE=1`     | Enable kernel-shape exploration engine                        |
| `ALIVIO_KERNEL_ENGINE_AND=1` | AND-mode bundle merge (with `ALIVIO_KERNEL_ENGINE=1`)          |
| `ALIVIO_BCF_DUMP_SMT=1`      | Dump per-site SMT-LIB to disk (debugging)                     |

## Troubleshooting

**`gcc: bpf/libbpf.h: No such file or directory`** — step 4b's libbpf tarball didn't extract to the expected path. Confirm `ls ~/BCF/build/bpf-next/tools/lib/bpf/libbpf.h` shows the file.

**`ld: cannot find -lbpf`** — Don't use `-lbpf`. Link `$LIBBPF/bpf/libbpf.a` directly (step 7).

**`test_loader: -EACCES` / "invalid bpf_bundle"** — alivio and the kernel are out of sync. Confirm both at the same SHA.

**`cvc5 binary not found`** — `export ALIVIO_CVC5=~/BCF/output/cvc5-libs/bin/cvc5`; re-run `build.sh solver` if missing.

**VM hangs on `boot_vm.sh`** — Stale virtiofsd socket: `rm -f ~/BCF/output/bpf-test.sock` and retry.

**`boot_vm.sh` exits when ssh disconnects** — VM is a child of the shell. Use tmux/screen.

**`uname -r` doesn't show our SHA** — bzImage wasn't replaced (step 4). `stat ~/BCF/output/bzImage` to check.

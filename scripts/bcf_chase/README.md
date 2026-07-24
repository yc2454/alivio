# BCF reject-chain chase tools

Diagnostic tooling for **userspace-BCF coverage analysis**: given a zovia-emitted
bundle and a BCF-patched kernel, determine *exactly* which path-unreachable
obligations the kernel requires to load a program, which of those zovia generates,
and which are engine-shape DFS-route gaps it cannot. No kernel rebuild needed.

These were built chasing `from_nat_no_log/calico_tc_skb_accepted_entrypoint`
(2026-06-08). See `memory/project_no_log_reopen_experiment_2026-06-03.md` for the
narrative; this README is the operational reference.

## The core trick

The BCF kernel logs `bcf_canonical_hash:` for **every** discharge query and **stops
at the first MISS** (load fails `EACCES -13`). And the prototype kernel **trusts the
hash match** — `bcf_bundle.c` has an explicit `TODO: structural equiv check ... For
the prototype we trust the hash match`. So we can:

1. Load a small bundle → read the one missed hash from `dmesg`.
2. If that hash is in zovia's emitted **superset**, it's a **real** obligation
   (zovia can generate it) → add the real entry and reload.
3. If it's **not** in the superset, it's an **engine-shape gap** (zovia cannot
   generate it) → **clone-fabricate** an entry with that `cond_hash` + `kind=2
   (UNREACHABLE)` and any donor goal/proof. The kernel discharges it on hash match
   and advances.
4. Loop until the program loads (`err=0`).

The final tally `|real| : |engine-shape|` quantifies the coverage gap precisely.
⚠️ **Fabrication is a DIAGNOSTIC ONLY** — the fake proofs do not actually prove
their goals (unsound). It proves the obligation *set* is complete and that no
non-BCF blocker (precision FA, other reject kind) stands in the way.

## Scripts

| file | what it does |
|------|--------------|
| `bundle_tool.py` | Parse / build BCF bundles (16B hdr magic `0x42464342` + u32 count@4; 28B entries, `cond_hash` u64 first). Subcommands: `hashes <bundle>` (list cond_hashes), `clone <donor> <hashfile> <out>` (bundle where EVERY hash is a clone of donor[0] — the fully-fabricated probe, RAM-trivial), `pick <superset> <wantfile> <out>` (sub-bundle of superset entries whose hash is in wantfile), `pickx <superset> <wantfile> <fakefile> <out>` (real picks **+ cloned fakes** — fabrication on top of real bytes), `merge <base> <superset> <wantfile> <out>`. Importable: `parse()`, `build()`, `parse_goal()`. |
| `build_superset.sh` | `<obj> <func> <out_hashset.txt> [depth]` — build ONE function's zovia obligation superset (variant-c recipe) **under a macOS memory watchdog**, extract its unique cond_hash set, discard the big bundle. Watchdog kills on RSS>`KILL_GB` (15) or `memory_pressure` free% < `MIN_FREE_PCT` (12); exit 99 = OOM-guard. ⚠️ use `memory_pressure` free%, NOT vm_stat "Pages free" (≈0 by design on macOS). |
| `chase_clone.sh` | Lightweight chase: clone-based bundles + classify each miss against a precomputed superset hash set (`SUPHASH`). RAM-trivial, fast (no big-bundle re-parse). Env: `SUPHASH DONOR HOST VMKEY OBJ PROG ITERS DIR`. Outputs `real.txt`/`fake.txt` + a `total / real / engine-shape (%)` tally. Use this for surveys; `chase_chain.sh` is the original real-bytes version. |
| `chase_chain.sh` | The miss-driven prune loop above, end-to-end over the VM. Classifies each miss real vs engine-shape, fabricates the gaps, loops to `err=0`. All paths configurable via env (`SUP HOST VMKEY OBJ PROG WANT FAKE ITERS DIR`); defaults reproduce the accepted_entrypoint run. Seed `WANT` with known reals to skip iterations. |
| `decode_canon.py` | Decode ONE kernel canonical-hash byte buffer (chunked `off=N bytes:` lines copied from `dmesg | grep "hash=0x<HASH>"`) into a flat post-order record list. `decode_canon.py <file>`. |
| `render_canon.py` | Same kernel-chunked input, but renders the expression **tree** as a readable conjunct list (top-level AND over comparison conjuncts). `render_canon.py <file>`. |
| `render_zovia.py` | Decode zovia's own dump format — the single-line `[zovia] bcf_canonical_hash: ... bytes: ..` emitted by `ZOVIA_BCF_DUMP_HASH_BYTES=1`. CLI prints conjuncts for the first (or a given) hash; importable `conjuncts(line)`, `parse(bytes)`, `render(node)`. |
| `closest.py` | Rank zovia's emitted entries by conjunct-multiset symmetric-difference to a target missed hash (var-renamed), revealing the exact prefix/anchor/fold conjuncts the kernel wanted that zovia didn't emit. `closest.py <target_chunked> <hashbytes_log> [signature_hex]`. |

### Canonical byte format (both decoders)
Post-order stream of records: `tag(u8)` `code(u8)` `vlen(u8)` `width(u16)` then
payload. `tag` 1=VAR (+u32 id), 2=CONST (+vlen u32 words), 3=OP (pops `vlen`
children). `code` low bit = `BCF_BV` flag; strip it for the op: `0x10`==, `0x50`!=,
`0x30`u>=, `0xb0`u<=, `0x00`+, top-level AND/CONJ has `vlen>2`. zovia goal `root`
is a **slot index** (flat layout), not a record index.

## Building the superset (zovia side)

```
# whole 4-pass thorough is the real superset; per-func variant-c is the cheap proxy:
ZOVIA_EXP_SKIP_LOOP_HEADER_UNSAFE=1 ZOVIA_EXP_LOOP_SUFFIX_BASE=1 ZOVIA_BCF_ANCESTOR_DEPTH=16 \
ZOVIA_KERNEL_ENGINE=1 ZOVIA_BCF_FAITHFUL_FOLD=1 ZOVIA_BCF_FOLD_PRENARROW=1 ZOVIA_BCF_REPLAY=1 \
./target/release/zovia -q --bcf --kernel-mode \
    verify --func <NAME> <obj>          # writes <obj>.bcf-bundle
```
⚠️ env vars **INLINE**, never via an unquoted `$ENV` shell var (silently dropped).
⚠️ `--kernel-mode` is required (zone mode false-OOMs at the map-load before the fan).
⚠️ `verify --func` is baseline-only unless you set the variant env explicitly (above).
Add `ZOVIA_BCF_DUMP_HASH_BYTES=1` to also emit the per-goal canonical streams for
`closest.py` / `render_zovia.py`.

## Ground-truth result (accepted_entrypoint, 2026-06-08)

`from_nat_no_log` (`clang-15_-O1_felix_bin_bpf_from_nat_no_log.o`),
prog `calico_tc_skb_accepted_entrypoint`, VM-validated `err=0`:

```
72 distinct path-unreachable obligations required to LOAD:
   36 REAL          (zovia generates; in the variant-c superset)  -> accepted_entrypoint.real_36.txt
   36 ENGINE-SHAPE  (zovia CANNOT generate; fabricated)           -> accepted_entrypoint.engine_shape_36.txt
   all 72 present -> total_disc=96 found=96 miss=0 -> LOADS CLEAN, no other blocker
```

The two `.txt` files are **ground truth** — the exact cond_hashes. They are
interleaved ~1:1 across the proto-switch reject fan. The engine-shape gaps are the
`R9==0` straight-line / flag-block-bypass routes to the proto dead-arms (root cause:
disasm pc897 `If R9==0` folds to `0x0==0x0` and skips the `&1024` block, so those
obligations lack the `(reg != 0x400)` conjunct that all of zovia's emitted variants
carry). Same DFS-route-divergence class as calico_tc_main's 78171d.

### Corpus survey (2026-06-08): the coverage wall is BROAD
Per-prog empty-bundle triage across no_log objs (ll2_loader `--prog <fn> <obj> empty.bundle`), matching the
authoritative final `bpf_object__load err=` line (⚠️ NOT `grep err | head -1` — that grabs a benign early
`err=0` from open/map setup and gives the wrong answer; an earlier pass made exactly that mistake):

```
                     tc_main  accepted   new_flow/icmp_inner_nat/send_icmp_replies/drop
from_nat_no_log       -13      -13        all err=0
from_nat_fib_no_log   -13      -13        all err=0
from_tnl_no_log       -13      -13        all err=0
from_tnl_fib_no_log   -13      -13        all err=0
from_wep_no_log       -13      err=0      all err=0
from_l3_no_log        -13      -13        all err=0
```

`calico_tc_main` needs obligations in all 6 objs; `accepted_entrypoint` in 5/6. Same source (proto-switch
dead-path fan) compiled with different flags → the same two big functions reject everywhere. The 4 small
entrypoints genuinely need no obligations. So the engine-shape obligation gap is **widespread** — fixing the
route-reproduction mechanism would help broadly. (Measured real:engine ratio so far only for from_nat/accepted =
36:36; `calico_tc_main` is a separate `err=-28` complexity-limit failure mode.)

## flag-skip-base result (2026-06-09)

`ZOVIA_EXP_FLAG_SKIP_BASE` (commit 9f052ec) reproduces **12 of accepted's 36 engine-shape obligations**
byte-exact (the `==`-flag-clear routes, anchored at the proto-switch flag branch folded to `0==0`), real-36
byte-stable. ⚠️ **Zero-pad hashes to 16 hex before comparing** (`awk '{printf "%016s\n",$0}'`) — `cond_hash`
formatting strips leading zeros (`1c57aac05a1a745` == `01c57aac05a1a745`), which silently undercounts matches.

The remaining 24 are anchored at a `u>=` branch (not `==`): 12 fold to `(0x0 u>= 0x0)`, 12 keep
`(0x0 u>= ZEXT(v))` which zovia over-folds to `(0x1 != 0x0)`. Closing them needs a second anchor mechanism
(`u>=` fold + an anti-fold). To diff fast: capture all kernel buffers in ONE VM load (`bundle_tool.py clone`
the full hash set → load → `dmesg|grep bcf_canonical_hash`), then single-parse compare (NOT closest.py in a
loop — it re-parses the whole emitted log each call).

## VM access

Host `ssh <HOST>` → nested `ssh -i <VMKEY> -p 10023 root@localhost`.
Loader `/root/bcf/sweep/ll2_loader --prog <name> <obj> <bundle>` (NOT `test_loader`
— that loads at log_level 0, no `[ZK]` prints). Read `dmesg | grep "ZK summary. END"`
(`total_disc/found/miss`) and `dmesg | grep bcf_canonical_hash:` (queried hashes; the
last before the reject = the miss). `E2BIG` ⇒ bundle > kernel 64MB `BCF_BUNDLE_MAX_SIZE`.
Do not hardcode the cloudlab hostname long-term — it rotates; read it from your git
remote / memory.

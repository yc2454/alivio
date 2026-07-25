# BCF prog_index splits

Subsets of `~/BCF/bpf-progs/prog_index.json` (BCF's canonical corpus index),
sliced so you can run BCF's `load_prog.py` over one project — or one cilium
source program — at a time without re-running the full sweep.

Each file is in BCF's expected shape:

```json
{ "<project>": { "<group>": ["<obj_file>", ...] } }
```

## Files

Per project (6):
- `prog_index.cilium.json`            — 6 groups, 42 objects
- `prog_index.calico.json`            — 492 groups, 1476 objects
- `prog_index.bcc.json`               — 1 group, 8 objects
- `prog_index.inspektor-gadget.json`  — 1 group, 11 objects
- `prog_index.bpf-examples.json`      — 2 groups, 42 objects
- `prog_index.collected.json`         — 1 group, 9 objects

Per cilium source program (6):
- `prog_index.cilium.bpf_lxc.json`        — 8 objects
- `prog_index.cilium.bpf_wireguard.json`  — 8 objects
- `prog_index.cilium.bpf_xdp.json`        — 2 objects
- `prog_index.cilium.bpf_overlay.json`    — 8 objects
- `prog_index.cilium.bpf_sock.json`       — 8 objects
- `prog_index.cilium.bpf_host.json`       — 8 objects

## Usage with `load_prog.py`

`load_prog.py` always reads `prog_index.json` from the `--directory` it's
given (hard-coded default in `load_index()`). Swap the file in:

```bash
# Pick the subset you want
cp ~/eBPF-Zone-Verifier/scripts/bcf-indexes/prog_index.cilium.bpf_lxc.json \
   ~/BCF/bpf-progs/prog_index.json

# Run BCF's loader against that subset
python3 ~/BCF/scripts/load_prog.py \
    --directory ~/BCF/bpf-progs \
    --output    ~/BCF/output/cilium-bpf_lxc \
    --bpftool   /usr/local/sbin/bpftool
```

To restore the full corpus:

```bash
cp ~/eBPF-Zone-Verifier/scripts/bcf-indexes/prog_index.cilium.json  \
   ~/BCF/bpf-progs/prog_index.json
# …or scp the original back from a known-good box
```

## Regenerating

If `~/BCF/bpf-progs/prog_index.json` upstream changes (new objects added,
groups renamed), regenerate the splits:

```bash
scp 'yc1795@<host>:~/BCF/bpf-progs/prog_index.json' /tmp/
python3 - <<'PY'
import json, pathlib
src = json.load(open('/tmp/prog_index.json'))
out = pathlib.Path('scripts/bcf-indexes')
for proj, groups in src.items():
    json.dump({proj: groups}, open(out / f'prog_index.{proj}.json', 'w'), indent=2)
for group, objs in src['cilium'].items():
    safe = group.replace('.o', '')
    json.dump({'cilium': {group: objs}}, open(out / f'prog_index.cilium.{safe}.json', 'w'), indent=2)
PY
```

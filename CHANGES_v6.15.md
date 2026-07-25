# v6.15 Kernel Corpus Upgrade — Feature Changes

This document summarises the analysis improvements added to reach **3278 PASS / 0 FA / 0 FR / 0 ERROR** against the Linux v6.15 selftest corpus.

---

## New Helper and kfunc Prototypes

- **`bpf_get_branch_snapshot`** — full proto modelled; R0 bound derived from the size-argument.
- **`bpf_sock_ops_enable_tx_tstamp`** kfunc proto added.
- **Workqueue cluster** — `bpf_wq_init`, `bpf_wq_set_callback`, `bpf_wq_start` kfuncs modelled; CFG DFS edges added for `wq_set_callback` so the callback subprogram is analysed.
- **Per-CPU object cluster** — `bpf_percpu_obj_new`, `bpf_percpu_obj_drop_impl`, per-cpu `kptr_xchg`, and five fail-test gates.
- **Testmod kfuncs** — `bpf_kfunc_call_test3`, `get_rdwr_mem`, `get_rdonly_mem`.
- **Entry-arg coverage** for new prog-types / hooks:
  - `sock_from_file`, `task_pt_regs`, `unix_listen`
  - `sched_process_fork` (tp_btf), `exit_creds` (fentry/fexit)
  - `fmod_ret/update_socket_protocol`, `lsm/file_mprotect`, `bprm_creds_for_exec`
- **`percpu-ksym` allowlist** — `bpf_task_storage_busy` added.
- **`GET_STACK` mem-size pair** — `allow_zero` set to `true` (`ARG_CONST_SIZE_OR_ZERO`).

---

## dynptr

- **`bpf_dynptr_slice`** — return type changed to read-only memory; stores through the returned pointer are now rejected.
- **Clone lineage** — `ref_obj_id` and source-kind propagated through `bpf_dynptr_clone` so the child inherits the parent's identity.
- **`bpf_dynptr_from_mem` size=0** — `ConstSize` constraint relaxed to `ConstSizeOrZero`, matching the kernel.
- **`bpf_dynptr_write` SKB invalidation** — slice invalidation scoped to SKB-backed dynptrs only.
- **`bpf_dynptr_from_skb`** — permitted as read-write in `SchedCls`/`SchedAct` prog kinds.
- **`cb-helper` dynptr-slice invalidation** — invalidation of dynptr slices inside callback helpers is gated on whether the callback body can destroy the dynptr.
- **`PtrToDynptr`** — new register type models the kernel's `PTR_TO_DYNPTR` for `user_ringbuf` callback R1.

---

## kptr / Kernel Pointer

- **`PtrToMapKptr` full cluster** — offset representation, ALU arithmetic, `bpf_kptr_xchg` arm, and Unref-store gate all modelled in a single coherent pass.
- **Load bounds** — `PtrToMapKptr` load bounds now computed from `eff_off` (`reg.offset + insn.off`) instead of `reg.offset` alone.
- **`bpf_kptr_xchg`** — now accepts `PtrToOwnedKptr` as R1 (kptr field inside an allocated struct).
- **Pointee-match skip** — `kptr_xchg` pointee-type match is skipped when `r2_name` resolves to `"unknown"` (avoids spurious rejects on unresolved BTF).
- **BTF field cap** — kptr-field extraction capped at `BTF_FIELDS_MAX` (= 11), matching the kernel limit.
- **Unref-kptr stores** — `Ptr{Task, Cgroup, Cpumask}` accepted as the source operand.
- **`bpf_per_cpu_ptr`** — R0 typed from `PtrToMapKptr` source; `MEM_ALLOC` store gate enforced.

---

## RCU Tracking

- **Nested-lock reject** — entering a second RCU read-lock section while already inside one is now rejected.
- **`MEM_RCU` demotion** — RCU annotation stripped from registers on the outermost `rcu_read_unlock`.
- **RCU allowlist additions** — `task_struct.cgroups` and `css_set.dfl_cgrp` added to the trusted RCU pointer table.
- **`bpf_tail_call` RCU gate** — implicit prog-type RCU sections are now ignored (matches kernel behaviour for tail-call chains).
- **Exit-time RCU leak check** — gated to main frame only; sleepable subprog calls inside an active RCU critical section are rejected.
- **`bpf_iter_css_next`** — R0 typed as `PtrToBtfId{cgroup_subsys_state, RCU}`.

---

## BTF and Type System

- **Field-offset tracking** — BTF field offsets on `PtrToBtfId` reads are now tracked and propagated to the helper-arg validator.
- **`__uptr` loads** — typed as `PtrToAllocMemOrNull` with `mem_size` derived from BTF.
- **Global subprog `PTR`-to-`PTR` arg** — `mem_size` fixed to 8 (matches kernel's 64-bit pointer interpretation).
- **`.BTF.ext` parser** — CO-RE relocation records are now surfaced; forms the foundation for future CO-RE-aware verification.
- **`__ksym` extern resolution** — `BPF_PSEUDO_BTF_ID` immediates resolved via the BTF symbol table.
- **map-of-maps BTF** — `__array(values, struct T)` annotation used to resolve `inner_map_idx`.
- **`map_uid` tracking** — cross-instance map-of-maps mismatches (same BTF type, different map instance) now detected and rejected.
- **Non-allowlisted BTF pointer fields** — default typing changed from unconstrained to `PtrToBtfId{Y, UNTRUSTED}`.
- **`btf/context`** module expanded with dedicated submodules: `datasec`, `fields`, `funcs`, `kptr`, `lookup`.

---

## Struct Ops and Callbacks

- **Optional-SEC fallback** — struct\_ops methods without a `SEC(...)` annotation default to 8 Scalar input slots.
- **Refcounted task arg** — struct\_ops methods whose first ctx-array slot holds a refcounted task are typed as `PtrToTask{ref_id}`.
- **`freplace` target inheritance** — `prog_kind` derived from the ctx-arg BTF of the target; each argument is individually typed.
- **`fexit/<subprog>` layout override** — static target-arg layout can be overridden for inlined inner `BPF_PROG` targets.
- **Exception callback** — PC 0 is treated as the main entry; CFG roots include exception-callback subprograms.
- **`bad_struct_ops` detection** — libbpf program reuse across distinct struct\_ops struct types is now detected and rejected.
- **`bpf_timer` callback** — R1 typed as `MapObject`, R3 as `MapValue`, both derived from the caller's R1 map index.
- **`bpf_for_each_map_elem` callback** — R2/R3 typed as `PtrToMapValue` from the caller's R1; R2 additionally marked read-only, rejecting stores through it.
- **CFG DFS edges** — kfunc-callback edges added for `rbtree_add` and `wq_set_callback` so their callback bodies are explored.

---

## Iterator (`bpf_iter`) Support

- **Subtype synthesis** — `bpf_iter__<subtype>` entry-argument and per-subtype payload are now synthesised from the iterator's BTF annotation.
- **Per-subtype payload nullability** — payload pointers carry the correct nullability for each iterator subtype.
- **`OrNull SOCK_COMMON` compat** — sock-common payloads accept `OrNull` variants to match the kernel's iter-ctx model.

---

## Arena and Memory

- **`__arg_arena` classifier** — arena arguments are identified and `bounds[]` synced from the DBM before widening.
- **Scalar-at-boundary** — `__arg_arena` now accepts any scalar at the call boundary, not only zero.
- **`PtrToAllocMem` in pointer arithmetic** — `PtrToAllocMem` registers are now valid as the base in `ptr+=scalar`/`ptr-=scalar` and in writable-mem validation.
- **`.rodata` fold** — `LD_IMM64` loads from `.rodata` sections pin the tnum to the loaded constant (kernel-aligned).

---

## Networking / Socket

- **`sk_lookup ctx->sk`** — typed as `PtrToSocketOrNull` (previously `SockCommon`), matching the kernel's null-able semantics.
- **`udp_sock` compat** — added to the `is_ptr_to_btf_sock_subtype` allowlist for socket compatibility checks.
- **`sk_reuseport_md` ctx model** — ctx fields fully modelled; atomic operations on sock pointers guarded.
- **`sockmap`** — `map_update_elem` rejected from `SockOps` programs; `map_delete_elem` continues to be permitted.

---

## Loop Widening and Precision

A series of targeted widening improvements were made to close loop-related false-accepts (FA) against the v6.15 corpus:

- **Counter-feeds-accumulator widening** (loop1) — when a loop counter's value feeds an accumulator register, the verifier applies closure demotion to bound the accumulation.
- **Spill-aware counter widening** (loop3) — spilled counter copies are recognised; `reg-counter ULt Reg(K_const)` branch constraints are extended to spilled slots.
- **Constrained domain-counter widening** — a domain counter tracks how many times a loop head has been visited under a given abstract state; widening is applied only after the threshold is exceeded.
- **Multi-counter + descending widening** — handles loops with multiple induction variables and/or descending counters; accumulator-feed gate prevents spurious widening.
- **Branch-only demotion** — non-counter precise registers that diverge in the DBM are demoted on the branch side only, preserving the join-side precision.
- **Non-precise DBM-diverging register demotion** — demotion extended to registers that are not marked precise but still diverge under the DBM.
- **Null-branch bounds tightening** — bounds on acquired-reference slots and registers on the null-taken branch are tightened to reflect the null outcome.
- **Targeted forget + `tnum_range`** — on DBM widen, affected registers are forgotten in a targeted way; `tnum_range` is applied instead of full widening to `UNKNOWN`.
- **Eviction-resistant `precise_pcs`** — precise PC sets are made eviction-resistant; precision walking is extended across call frames.
- **Union-widen scalar slots** — scalar stack slots are union-widened instead of fully invalidated on loop iteration.

---

## Context Models

- **`raw_tracepoint` / `pt_regs`** — direct-typed context extended to `raw_tracepoint` programs with `pt_regs` layouts and scalar fields.
- **`fentry`/`fexit` ctx-arg trust** — modelled as plain `PTR_TO_BTF_ID` (without TRUSTED flag), matching the kernel's trust model.
- **`flow_keys` gate** — kernel tnum imprecision on `flow_keys` accesses tracked via a side-channel flag to avoid false rejects.

---

## LSM

- **Int-hook trio closure** — for LSM int-returning hooks, the post-load bounds clamp is skipped when bounds are already explicit.
- **Retval `s32` view** — LSM int-hook return values are viewed as signed 32-bit; W32 mov s32 shadow propagation added.

---

## Miscellaneous

- **W32 `mov`-from-reg** — u32 shadow bounds propagated correctly across the zero-extend implicit in a W32 move.
- **`spill`/`fill` secondary packet anchor** — secondary packet-anchor registers are preserved across spill/fill cycles; same-family pointer subtraction is demoted to scalar cleanly.
- **`transfer_exit` contradiction drop** — paths where callee anchor constraints contradict the caller are dropped at `exit`.
- **`ptr+=scalar`/`ptr-=scalar` tnum** — absolute-address tnum synchronisation removed from pointer arithmetic (was unsound).
- **`OUT_OF_SCOPE` verdict** — new test result added for tests that require loader or runtime preprocessing that the static verifier cannot replicate.
- **Per-file domain overrides** — individual test files can be pinned to the Interval domain (e.g., `cls_redirect`) or given kernel-equivalent per-file step limits.
- **`ZOVIA_DUMP_PRECISE_PCS_PC` diagnostic flag** — set `ZOVIA_DUMP_PRECISE_PCS_PC=<pc>` to dump the precise-PC set at a given instruction during analysis.

// src/analysis/transfer/types.rs
//
// Type update logic for all instruction types

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::{PtrFlags, RegType, TypeState, new_ptr_id};
use crate::analysis::machine::stack_state::StackState;
use crate::analysis::machine::state::State;
use crate::ast::{AluOp, MapLoadKind, MemSize, Operand, Width};
use crate::common::constants;
use crate::common::ctx_model::{CtxFieldKind, validate_ctx_access};
use crate::domains::numeric::NumericDomain;
use crate::parsing::elf::KptrFieldKind;

/// Anchor a map-value pointer's BCF symbolic offset at const(0) when the
/// reg is given `PtrToMapValue` directly (no `OrNull` stage that would go
/// through `maybe_promote_map_val`). Both array-map lookups with constant
/// in-bounds keys and `bpf_get_local_storage` take this fast path.
/// Mirrors the anchor inside `maybe_promote_map_val`; without it, the
/// map-OOB refinement at access sites sees an unanchored fresh symbolic
/// variable for the base and can't prove safety even when the access is
/// provably in-bounds.
fn bcf_anchor_map_value(state: &mut State, reg: Reg) {
    if let Some(bcf) = state.bcf.as_mut()
        && let Some(i) = reg.bcf_idx()
    {
        let zero = bcf.add_val64(0);
        bcf.bind_reg(i, zero);
    }
}

/// True if R2 (the lookup-elem key pointer) points at a stack slot
/// whose value is a known constant strictly less than `map_def.max_entries`.
/// Mirrors kernel's array-map "lookup with const in-bounds key returns
/// non-null" specialization (closes verifier_array_access::*_no_nullness).
fn const_key_in_bounds(state: &State, map_def: &crate::parsing::elf::BpfMapDef) -> bool {
    let level = match state.types.get(Reg::R2) {
        RegType::PtrToStack { frame_level } => frame_level,
        _ => return false,
    };
    let off = match state.domain.get_distance_fixed(Reg::R2, Reg::R10) {
        Some(o) => o,
        None => return false,
    };
    let slot = match state.stack_at(level).get_slot(off as i16) {
        Some(s) => s,
        None => return false,
    };
    if slot.size.bytes() as u32 != map_def.key_size {
        return false;
    }
    if !slot.tnum.is_const() {
        return false;
    }
    slot.tnum.value < map_def.max_entries as u64
}

fn update_packet_ptr_type_after_alu(types: &mut TypeState, domain: &NumericDomain, dst: Reg) {
    // Check offset from anchor: dst - @data
    // Use get_distance_interval to support both zone and interval domains
    let (_, max_offset) = domain.get_distance_interval(dst, Reg::AnchorData);
    if max_offset <= constants::MAX_PACKET_OFF {
        types.set(dst, RegType::PtrToPacket);
    } else {
        types.set(dst, RegType::ScalarValue);
    }
}

/// Extracts a fixed i64 value from an operand (immediate or register with known value)
fn get_operand_fixed_value(domain: &NumericDomain, src: &Operand) -> Option<i64> {
    match src {
        Operand::Imm(k) => Some(*k),
        Operand::Reg(r) => domain.get_fixed_value(*r),
    }
}

/// Updates PtrToMapValue offset by delta, returning new type
fn adjust_map_value_offset(ty: RegType, delta: Option<i64>) -> RegType {
    match ty {
        RegType::PtrToMapValue {
            id,
            offset,
            map_idx,
            map_uid,
            rdonly,
        } => {
            let new_offset = match (offset, delta) {
                (Some(o), Some(d)) => Some(o + d),
                _ => None, // Unknown if either is unknown
            };
            RegType::PtrToMapValue {
                id,
                offset: new_offset,
                map_idx,
                map_uid,
                rdonly,
            }
        }
        other => other,
    }
}

/// Unified handler for pointer arithmetic (Add/Sub) type updates
fn update_ptr_arithmetic_type(
    env: &VerifierEnv,
    types: &mut TypeState,
    domain: &NumericDomain,
    dst: Reg,
    dst_ty: RegType,
    src: &Operand,
    is_add: bool, // true = Add, false = Sub
) {
    let delta = get_operand_fixed_value(domain, src);
    let signed_delta = if is_add { delta } else { delta.map(|d| -d) };

    match dst_ty {
        RegType::PtrToMapValue { .. } => {
            types.set(dst, adjust_map_value_offset(dst_ty, signed_delta));
        }
        RegType::PtrToMapObject { .. } => {
            // Only allow adding/subtracting 0
            if signed_delta != Some(0) {
                types.set(dst, RegType::ScalarValue);
            }
            // else: type unchanged (adding 0 is a no-op)
        }
        RegType::PtrToStack { frame_level } => {
            types.set(dst, RegType::PtrToStack { frame_level });
        }
        RegType::PtrToMapKptr {
            pointee_btf_id,
            ref_id,
            flags,
            offset,
        } => {
            // Mirror PtrToOwnedKptr arithmetic: kernel preserves
            // PTR_TO_BTF_ID|MEM_* through `Add reg, K` / `Sub reg, K`
            // and bumps `reg->off`. Required for the
            // `R6 = bpf_kptr_xchg(...); R1 = R6 + 16; bpf_kptr_xchg(R1, NULL)`
            // idiom (local_kptr_stash::unstash_rb_node), where the
            // second xchg targets a kptr field embedded inside the
            // previously xchg'd object.
            // Variable delta on a kptr is rejected by the kernel
            // ("variable untrusted_ptr_ access var_off=..."); drop to
            // ScalarValue so the downstream kptr-field store gate
            // catches the source-type mismatch.
            let Some(d) = signed_delta else {
                types.set(dst, RegType::ScalarValue);
                return;
            };
            let new_offset =
                offset.saturating_add(d.clamp(i32::MIN as i64, i32::MAX as i64) as i32);
            types.set(
                dst,
                RegType::PtrToMapKptr {
                    pointee_btf_id,
                    ref_id,
                    flags,
                    offset: new_offset,
                },
            );
        }
        RegType::PtrToOwnedKptr {
            ref_id,
            offset,
            non_owning,
            pointee_btf_id,
        } => {
            // Kernel `verifier.c` v6.15 ~L15170: PTR_TO_BTF_ID|MEM_ALLOC
            // preserves type through pointer arithmetic; `reg->off` is
            // bumped by the constant delta. Required for graph-add
            // kfuncs that pass `&n->node` (PtrToOwnedKptr + 16) — the
            // member offset must reach the validator without being
            // demoted to Scalar. Release sinks (`bpf_obj_drop`,
            // `bpf_kptr_xchg`) reject non-zero offsets in the post-call
            // gate, mirroring kernel "must have zero offset when passed
            // to release func" (verifier.c ~L13242).
            let new_offset = match signed_delta {
                Some(d) => offset.saturating_add(d.clamp(i32::MIN as i64, i32::MAX as i64) as i32),
                None => offset, // unknown delta: keep type, offset unchanged
            };
            types.set(
                dst,
                RegType::PtrToOwnedKptr {
                    ref_id,
                    offset: new_offset,
                    non_owning,
                    pointee_btf_id,
                },
            );
        }
        RegType::PtrToAllocMem {
            id,
            mem_size,
            ref_id,
            dynptr_id,
            rdonly,
        } => {
            // Kernel `verifier.c` ~L15170 (v6.15): pointer arithmetic on
            // PTR_TO_MEM (alloc) preserves the type and bumps `reg->off`
            // by the constant delta. We don't carry an offset field on
            // PtrToAllocMem, so model the offset by shrinking mem_size
            // (the remaining-bytes-from-here invariant). Forward-only
            // adds within bounds preserve the type; anything else (sub,
            // unknown delta, out-of-range delta) demotes to scalar so
            // the access check rejects rather than silently allowing.
            // Drop ref_id — an interior pointer is no longer the
            // acquire-tracked owner and can't be released through.
            let _ = ref_id;
            match signed_delta {
                Some(d) if d >= 0 && (d as u64) <= mem_size => {
                    types.set(
                        dst,
                        RegType::PtrToAllocMem {
                            id,
                            mem_size: mem_size - d as u64,
                            ref_id: None,
                            dynptr_id,
                            rdonly,
                        },
                    );
                }
                _ => types.set(dst, RegType::ScalarValue),
            }
        }
        RegType::PtrToArena { ref_id, mem_size } => {
            // Kernel `verifier.c` ~L15191 (v6.15): when dst is
            // PTR_TO_ARENA, "Any arithmetic operations are allowed on
            // arena pointers" and the function returns 0 without
            // changing dst's type. Add/Sub/Shl/Shr/And/Or/etc. all
            // preserve PtrToArena. This is what alloc_pages's
            // `pg - base; result >> 12` shape needs to verify.
            types.set(dst, RegType::PtrToArena { ref_id, mem_size });
        }
        RegType::PtrToCtx => {
            if signed_delta == Some(0) {
                types.set(dst, RegType::PtrToCtx);
            } else {
                types.set(dst, RegType::ScalarValue);
            }
        }
        RegType::PtrToPacket => {
            if is_add {
                // For Add: check if immediate exceeds max offset
                if let Some(d) = delta {
                    if d >= constants::MAX_PACKET_OFF {
                        types.set(dst, RegType::ScalarValue);
                    }
                    // else: type unchanged, still PtrToPacket
                }
                // For Add with register: check if known value exceeds max
                else if let Operand::Reg(_) = src {
                    // delta is None means unknown - keep type unchanged
                }
            } else {
                // For Sub: use anchor-based bounds check
                update_packet_ptr_type_after_alu(types, domain, dst);
            }
        }
        RegType::PtrToPacketMeta => {
            // Use get_distance_interval to support both zone and interval domains
            let (_, max_offset) = domain.get_distance_interval(dst, Reg::AnchorDataMeta);
            if max_offset <= constants::MAX_PACKET_OFF {
                types.set(dst, RegType::PtrToPacketMeta);
            } else {
                types.set(dst, RegType::ScalarValue);
            }
        }
        // pointer arithmetic on a BTF-typed pointer (e.g.
        // `r1 = sk + 1296` to reach an embedded struct field) preserves
        // the type and trusted flags. Without this, struct_ops methods
        // that compute interior pointers via add/sub demoted to scalar
        // and the subsequent field access failed. The access check on
        // `type_name == "unknown"` already skips per-field bounds
        // validation; for layout-known names the access path enforces
        // bounds via mem_region_model.
        //
        // when the offset matches an
        // *embedded* struct member of `type_name`, retype to that
        // member's struct (e.g. `&task->cpus_mask` →
        // `PtrToBtfId{cpumask, TRUSTED}`). This is what kfunc arg
        // matchers like `validate_ptr_to_cpumask` need to accept the
        // interior pointer. For non-named types (`"unknown"`,
        // `"struct"`) or unresolved offsets, fall back to preserving
        // the source type — matches the shape.
        RegType::PtrToBtfId {
            type_name,
            flags,
            ref_id,
        } => {
            // Pointer arithmetic on a refcounted BTF pointer drops the
            // ref_id: an interior pointer is no longer the
            // acquire-tracked owner, and releasing through it would
            // mismatch the original. Kernel matches.
            let _ = ref_id;
            let new_type_name = signed_delta
                .filter(|d| *d > 0 && *d < i64::from(i32::MAX))
                .and_then(|d| {
                    let struct_id = env.ctx.btf.find_struct_by_name(type_name)?;
                    let info = env.ctx.btf.field_at_offset(struct_id, d as u32)?;
                    match info.kind {
                        crate::parsing::btf::BtfFieldKind::Embedded {
                            type_name: Some(name),
                            ..
                        } => Some(
                            crate::analysis::machine::context::intern_btf_type_name_strict(&name),
                        ),
                        _ => None,
                    }
                })
                .unwrap_or(type_name);
            types.set(
                dst,
                RegType::PtrToBtfId {
                    type_name: new_type_name,
                    flags,
                    ref_id: None,
                },
            );
        }
        _ => types.set(dst, RegType::ScalarValue),
    }
}

/// Handles scalar + pointer/scalar arithmetic type updates
fn handle_scalar_arithmetic_type(
    in_types: &TypeState,
    types: &mut TypeState,
    dst: Reg,
    src: &Operand,
    is_add: bool,
) {
    match src {
        Operand::Imm(_) => {
            types.set(dst, RegType::ScalarValue);
        }
        Operand::Reg(src_reg) => {
            let src_ty = in_types.get(*src_reg);
            if is_add {
                // scalar + pointer => pointer type (commutative)
                types.set(dst, src_ty);
            } else {
                // scalar - pointer => scalar (subtraction from scalar)
                types.set(dst, src_ty);
            }
        }
    }
}

/// Updates register types after an ALU operation.
pub(crate) fn update_alu_types(
    env: &VerifierEnv,
    in_types: &TypeState,
    types: &mut TypeState,
    domain: &NumericDomain,
    width: Width,
    op: AluOp,
    dst: Reg,
    src: &Operand,
    pc: usize,
) {
    if width == Width::W32 {
        types.set(dst, RegType::ScalarValue);
        return;
    }
    match op {
        AluOp::Mov => {
            match src {
                Operand::Reg(r) => {
                    let src_ty = in_types.get(*r);
                    // `bpf_addr_space_cast(as(1)→as(0))` is encoded as
                    // BPF_MOV | BPF_X with off=1, imm=1. The parser
                    // records its PCs; the kernel
                    // (`verifier.c` ~L15402, v6.15) does
                    // `mark_reg_unknown` then unconditionally sets
                    // `dst_reg->type = PTR_TO_ARENA` for this form,
                    // ignoring the source register's prior type. Mirror
                    // that here: the cast ignores src and produces a
                    // fresh PtrToArena.
                    if env.addr_space_cast_to_arena_pcs.contains(&pc) {
                        types.set(
                            dst,
                            RegType::PtrToArena {
                                ref_id: None,
                                mem_size: 1u64 << 32,
                            },
                        );
                    } else {
                        types.set(dst, src_ty);
                    }
                }
                Operand::Imm(_) => {
                    // Regular ALU MOV imm: look up a reloc at *this* pc only.
                    // LD_IMM64 (`r = imm64`) is handled via its own MapLoad
                    // opcode, so the legacy `pc+1` fallback would only ever
                    // misattribute a neighbouring insn's reloc to a single-slot
                    // ALU MOV (e.g. `r1 = 0` followed by an LD_IMM64-of-vals
                    // → r1 wrongly typed as PtrToMapValue at the call site).
                    let reloc = env.ctx.pc_to_reloc.get(&pc);

                    if let Some(info) = reloc {
                        if info.map_idx < env.ctx.map_defs.len() {
                            let map_name = &env.ctx.map_defs[info.map_idx].name;
                            // Data sections become PtrToMapValue
                            if map_name.starts_with(".rodata")
                                || map_name.starts_with(".data")
                                || map_name == ".bss"
                            {
                                types.set(
                                    dst,
                                    RegType::PtrToMapValue {
                                        id: new_ptr_id(),
                                        offset: Some(info.offset),
                                        map_idx: info.map_idx,
                                        map_uid: None,
                                        rdonly: false,
                                    },
                                );
                                // NOTE: this site has only `&mut TypeState`,
                                // not full `State`, so we can't anchor the
                                // BCF symbolic offset here directly. None of
                                // the current target programs hit this path
                                // (rodata/data/bss are LD_IMM64 forms, not
                                // map_lookup_elem chains). Track as Phase 2+
                                // deferred — would need to plumb `state.bcf`
                                // access through this code path.
                            } else {
                                types.set(dst, RegType::ScalarValue);
                            }
                        } else {
                            types.set(dst, RegType::ScalarValue);
                        }
                    } else {
                        types.set(dst, RegType::ScalarValue);
                    }
                }
            }
        }
        AluOp::Add | AluOp::Sub => {
            let dst_ty = in_types.get(dst);
            let is_add = op == AluOp::Add;

            // pointer − pointer collapses to an (arbitrary) scalar.
            // Mirrors kernel `adjust_reg_min_max_vals` (verifier.c
            // L15208-15234): when BOTH operands are pointers, the only
            // permitted ALU op is `BPF_SUB` under `allow_ptr_leaks`
            // (privileged) — `mark_reg_unknown(dst)` → dst becomes a
            // SCALAR; any other op / unprivileged is `R%d pointer %s
            // pointer prohibited` -EACCES. It is NOT restricted to the
            // packet pointer family: `value_ptr -= value_ptr`
            // (PtrToMapValue − PtrToMapValue) must also demote so the
            // following deref is correctly rejected "R0 invalid mem
            // access 'scalar'" (verifier_value_ptr_arith.c::
            // access_value_ptr_value_ptr_2). Without this alivio kept dst
            // a map_value pointer and accepted the load. The DBM domain
            // already carries the scalar bounds via `apply_sub_reg` in
            // handle_sub (packet ptr-sub additionally preserves the
            // correlated-branch length relation there).
            let both_ptr_sub = !is_add
                && match src {
                    Operand::Reg(r) => dst_ty.is_pointer() && in_types.get(*r).is_pointer(),
                    _ => false,
                };

            if both_ptr_sub {
                types.set(dst, RegType::ScalarValue);
            } else if dst_ty.is_pointer() {
                update_ptr_arithmetic_type(env, types, domain, dst, dst_ty, src, is_add);
            } else {
                handle_scalar_arithmetic_type(in_types, types, dst, src, is_add);
            }
        }
        _ => {
            // Non-Add/Sub ALU ops normally demote dst to scalar. The
            // exception is PtrToArena: the kernel
            // (`verifier.c` ~L15191, v6.15) allows any arithmetic on
            // an arena pointer and the type stays PTR_TO_ARENA.
            // Preserves alloc_pages's `R1 = (pg - base) >> 12` chain
            // where the Shr after Sub keeps the arena type alive.
            let in_ty = in_types.get(dst);
            if matches!(in_ty, RegType::PtrToArena { .. }) {
                types.set(dst, in_ty);
            } else {
                types.set(dst, RegType::ScalarValue);
            }
        }
    }
}

/// Updates register types after a Load operation. Returns `true` when
/// the function has explicitly set numeric domain bounds on `dst`
/// (e.g. via `CtxFieldKind::BoundedScalar`), in which case the caller
/// must skip its default post-load `forget(dst)` + width-based clamp —
/// otherwise the explicit bounds get wiped before they're observed by
/// downstream transfer steps.
pub(crate) fn update_load_types(
    env: &VerifierEnv,
    state: &mut State,
    size: usize,
    dst: Reg,
    base: Reg,
    off: i16,
) -> bool {
    let base_ty = state.types.get(base);
    match base_ty {
        RegType::PtrToCtx => {
            let kind = validate_ctx_access(env, off, size as i64);
            if let Some(info) = kind {
                match info.kind {
                    CtxFieldKind::PacketMeta => {
                        state.types.set(dst, RegType::PtrToPacketMeta);
                    }
                    CtxFieldKind::PacketStart => {
                        state.types.set(dst, RegType::PtrToPacket);
                    }
                    CtxFieldKind::PacketEnd => {
                        state.types.set(dst, RegType::PtrToPacketEnd);
                    }
                    CtxFieldKind::SockCommon => {
                        state
                            .types
                            .set(dst, RegType::PtrToSockCommonOrNull { ref_id: None });
                    }
                    CtxFieldKind::Socket => {
                        state.types.set(dst, RegType::PtrToSocket { ref_id: None });
                    }
                    CtxFieldKind::SocketOrNull => {
                        state
                            .types
                            .set(dst, RegType::PtrToSocketOrNull { ref_id: None });
                    }
                    CtxFieldKind::AllocMem { mem_size } => {
                        state.types.set(
                            dst,
                            RegType::PtrToAllocMem {
                                id: new_ptr_id(),
                                mem_size,
                                ref_id: None,
                                dynptr_id: None,
                                rdonly: false,
                            },
                        );
                    }
                    CtxFieldKind::TrustedPtr {
                        type_name,
                        nullable,
                        trusted,
                        tag_flags,
                    } => {
                        // Compose TRUSTED with attach-target tag flags
                        // (USER / PERCPU). Direct deref of USER/PERCPU
                        // pointers is rejected at the load-site check
                        // in memory/access.rs — programs must go through
                        // bpf_copy_from_user / bpf_per_cpu_ptr first.
                        // `trusted=false` mirrors kernel
                        // `prog_args_trusted()` returning false for
                        // fentry / fexit / fmod_ret: ctx args are plain
                        // PTR_TO_BTF_ID without PTR_TRUSTED, which makes
                        // ARG_PTR_TO_MEM helpers reject them.
                        let base = if trusted {
                            PtrFlags::TRUSTED
                        } else {
                            PtrFlags::empty()
                        };
                        let flags = base.union(tag_flags);
                        if nullable {
                            state.types.set(
                                dst,
                                RegType::PtrToBtfIdOrNull {
                                    id: new_ptr_id(),
                                    type_name,
                                    flags,
                                    ref_id: None,
                                },
                            );
                        } else {
                            state.types.set(
                                dst,
                                RegType::PtrToBtfId {
                                    type_name,
                                    flags,
                                    ref_id: None,
                                },
                            );
                        }
                    }
                    CtxFieldKind::RefcountedTask { ref_id } => {
                        state.types.set(
                            dst,
                            RegType::PtrToTask {
                                ref_id: Some(ref_id),
                            },
                        );
                        state.domain.forget(dst);
                    }
                    CtxFieldKind::BoundedScalar { lo, hi } => {
                        // LSM int-hook trailing `int ret` arg etc. —
                        // kernel constrains the value at attach to
                        // `[lo, hi]`. Materialize as ScalarValue + apply
                        // the range to both the s64 and s32 shadows.
                        // We need the s32 bound because `return ret;`
                        // patterns get truncated through a W32 mov
                        // (`w0 = r_src`) before exit, and the LSM retval
                        // rule is checked on the s32 view (kernel
                        // `retval_range_s32`). Without the s32 bound
                        // propagating through the W32 mov, R0's s32
                        // view widens to full range.
                        //
                        // Return `true` so `transfer_load_ext` skips its
                        // post-load `forget(dst)` + access-size clamp;
                        // those would wipe the explicit bound we just
                        // set and cap u32 at u32::MAX, defeating the
                        // s32 carry-through.
                        state.types.set(dst, RegType::ScalarValue);
                        state.domain.forget(dst);
                        state.domain.assume_ge_imm(dst, lo);
                        state.domain.assume_le_imm(dst, hi);
                        if lo >= i32::MIN as i64 && hi <= i32::MAX as i64 {
                            state.domain.set_s32_bounds(dst, lo as i32, hi as i32);
                        }
                        return true;
                    }
                    _ => state.types.set(dst, RegType::ScalarValue),
                }
            } else {
                state.types.set(dst, RegType::ScalarValue);
            }
        }
        RegType::PtrToStack { .. } => {
            match state.domain.get_distance_fixed(base, Reg::R10) {
                Some(base_off) => {
                    let actual_slot = base_off + (off as i64);
                    if size == MemSize::U64.bytes() {
                        state
                            .types
                            .set(dst, state.stack().get_slot_type(actual_slot as i16));
                    } else {
                        state.types.set(dst, RegType::ScalarValue);
                    }
                }
                None => {
                    // Unknown stack offset - can't determine which slot we're reading
                    // Conservative: result is scalar (could be anything)
                    state.types.set(dst, RegType::ScalarValue);
                }
            }
        }
        RegType::PtrToMapValue {
            offset: map_off_opt,
            map_idx,
            ..
        } => {
            // Kptr field load: produce a typed pointer rather than a
            // scalar. Generic bounds and kptr-overlap rules already ran
            // in `check_load`; here we just synthesize the right reg
            // type when the access exactly matches a kptr slot.
            let final_off = crate::analysis::transfer::memory::map::resolve_const_map_off(
                state,
                base,
                map_off_opt,
                off,
            );
            let map_def = env.ctx.map_defs.get(map_idx);
            if let (Some(off_val), Some(map_def)) = (final_off, map_def)
                && let Some(field) = crate::analysis::transfer::memory::map::kptr_field_at(
                    map_def,
                    off_val,
                    size as i64,
                )
            {
                let flags = match field.kind {
                    KptrFieldKind::Unref => PtrFlags::UNTRUSTED,
                    KptrFieldKind::Ref => PtrFlags::MEM_ALLOC,
                    KptrFieldKind::Rcu => PtrFlags::RCU,
                    KptrFieldKind::Percpu => PtrFlags::PERCPU,
                    KptrFieldKind::Uptr => {
                        // `__uptr` loads yield a userspace-pointer value.
                        // Kernel types this as `PTR_TO_MEM | MEM_USER |
                        // PTR_MAYBE_NULL` and rejects deref-before-
                        // null-check ("invalid mem access 'mem_or_null'").
                        // We mirror via `PtrToAllocMemOrNull` whose
                        // `mem_size` comes from the pointee struct's BTF
                        // size; deref through OrNull falls into the
                        // generic-load reject arm, and post-null-check
                        // refinement to `PtrToAllocMem` enables bounded
                        // field reads. Closes task_ls_uptr.c::on_enter
                        // (`v->udata->result` after null check).
                        let mem_size = env.ctx.btf.type_size_bytes(field.pointee_btf_id) as u64;
                        state.types.set(
                            dst,
                            RegType::PtrToAllocMemOrNull {
                                id: crate::analysis::machine::reg_types::new_ptr_id(),
                                mem_size,
                                ref_id: None,
                                dynptr_id: None,
                                rdonly: false,
                            },
                        );
                        return false;
                    }
                };
                state.types.set(
                    dst,
                    RegType::PtrToMapKptrOrNull {
                        pointee_btf_id: field.pointee_btf_id,
                        ref_id: None,
                        flags,
                        offset: 0,
                    },
                );
            } else {
                state.types.set(dst, RegType::ScalarValue);
            }
        }
        // load `*(u64*)(base + off)` from
        // `PtrToBtfId{X, flags}` where X.fields[off] is a `PTR -> Y`.
        // The default load yields ScalarValue (preserves the existing
        // FA-safe behavior — kfunc validators reject Scalar where they
        // expected a typed pointer). For a small allowlist of known-
        // safe (struct, field_name) pairs the loaded value is typed as
        // `PtrToBtfId{Y, TRUSTED}` so the matching kfunc validators
        // accept it (`task->cpus_ptr`, `skb->sk` are the load
        // surfaces driving the nested_trust_success FRs).
        //
        // Type-tag-based promotion (kernel `__rcu` / `__percpu` …) is
        // intentionally *not* applied here yet — it would require
        // RCU-section tracking we don't model, and the upstream
        // selftest corpus has only one __success test that depends on
        // it (`test_read_cpumask`'s `cpus_ptr`, which the allowlist
        // covers explicitly). When we ship RCU lock tracking, swap
        // `tags` → `flags` and drop the static allowlist.
        // BTF field-load typing for
        // any base whose static BTF type is known. PtrToBtfId
        // carries `type_name` directly. The acquire-tracked
        // specializations (`PtrToTask`, `PtrToCgroup`, `PtrToCpumask`)
        // are structurally pointers to the matching named struct for
        // field-access purposes — extract the implied name so
        // `task = bpf_get_current_task_btf(); task->bpf_storage`
        // resolves the same as `task` from a BPF_PROG entry arg.
        // Sock-family variants stay on the mem_region_model field
        // tables (richer per-field offsets); we don't divert them
        // here.
        ref t
            if size == MemSize::U64.bytes() && off >= 0 && implied_btf_struct_name(t).is_some() =>
        {
            use crate::parsing::btf::BtfFieldKind;
            let type_name = implied_btf_struct_name(t).unwrap();
            let mut typed = false;
            if let Some(struct_id) = env.ctx.btf.find_struct_by_name(type_name)
                && let Some(info) = env.ctx.btf.field_at_offset_descend(struct_id, off as u32)
                && let BtfFieldKind::Pointer {
                    pointee_name: Some(pointee),
                    type_tag,
                } = &info.kind
            {
                let trusted = trusted_field_load(type_name, info.name);
                let rcu = rcu_field_load(type_name, info.name);
                // BTF TYPE_TAG-driven flags: kernel `__percpu` / `__user`
                // pointers are non-derefable directly. memory/access.rs
                // rejects deref of PtrToBtfId carrying USER or PERCPU;
                // bpf_per_cpu_ptr / bpf_copy_from_user are the kernel
                // path through. Closes btf_type_tag_percpu::test_percpu_load
                // — `cgrp->rstat_cpu` is `__percpu *` and the test expects
                // direct deref to be rejected.
                // BTF TYPE_TAG-driven flags from the program's BTF.
                // Falls back to a static (struct, field) allowlist for
                // kernel-defined fields whose `__percpu` / `__user`
                // annotation lives in vmlinux BTF (which we don't ship).
                let tag_str = type_tag
                    .as_deref()
                    .or_else(|| percpu_or_user_field(type_name, info.name));
                let tag_flags = match tag_str {
                    Some("percpu") => PtrFlags::PERCPU,
                    Some("user") => PtrFlags::USER,
                    _ => PtrFlags::empty(),
                };
                // Three trust bands mirror kernel `btf_struct_walk`:
                //  - TRUSTED: explicit `__safe_trusted` allowlist
                //  - RCU: explicit `__safe_rcu` allowlist, gated on CS
                //  - UNTRUSTED (default): kernel "old-style ptr_to_btf_id"
                //    (verifier.c v6.15 ~L7140). Load is admitted, downstream
                //    chained derefs work, but consumer validators that
                //    require KF_TRUSTED_ARGS / KF_RCU reject.
                //
                // Previously the default arm collapsed to ScalarValue,
                // which broke chained pointer field walks (e.g.
                // `skb->dev->ifalias->...` in tracing programs). The
                // UNTRUSTED variant matches kernel exactly and preserves
                // the type chain; the FA risk is bounded to consumer
                // validators that don't enforce TRUSTED — those should
                // be tightened independently.
                // `__rcu` field outside an explicit CS still loads as
                // RCU/TRUSTED in non-sleepable tracing programs because
                // the kernel runs them with an implicit RCU read-side
                // CS held (auto_rcu in analysis::mod.rs covers Kprobe/
                // Tracepoint/RawTP/PerfEvent; Tracing/Lsm are
                // sometimes-sleepable and not on that list, so we
                // approximate "non-sleepable program" here). Sleepable
                // programs (`fentry.s`, `iter.s`, `lsm.s`) MUST enter
                // an explicit `bpf_rcu_read_lock` to load `__rcu`
                // fields as trusted; outside the CS the load lands
                // UNTRUSTED — kernel: "task->cgroups is untrusted in
                // sleepable prog outside of RCU CS" (closes
                // cgrp_ls_sleepable::no_rcu_lock).
                let rcu_implicit = !env.ctx.is_sleepable;
                let trust_flag = if trusted {
                    PtrFlags::TRUSTED
                } else if rcu && (state.in_rcu_read_section() || rcu_implicit) {
                    PtrFlags::RCU
                } else {
                    PtrFlags::UNTRUSTED
                };
                let flags = trust_flag.union(tag_flags);
                let pointee_static =
                    crate::analysis::machine::context::intern_btf_type_name_strict(pointee);
                state.types.set(
                    dst,
                    RegType::PtrToBtfId {
                        type_name: pointee_static,
                        flags,
                        ref_id: None,
                    },
                );
                typed = true;
            }
            // Fallback for kernel-internal structs whose full layout the
            // program's BTF doesn't carry (so the BTF descend above can't
            // resolve the field). `bpf_iter_meta` is the surface here: the
            // bpf_iter ctx-access path types `ctx->meta` as
            // PtrToBtfId{bpf_iter_meta}, but `meta->seq` (offset 0) loads as
            // a bare scalar because bpf_iter_meta isn't a named struct in the
            // .o BTF → bpf_seq_write then rejects its seq_file* arg
            // (verifier_bpf_get_stack::return_r0_range_is_refined). Hand-model
            // the pointer field like the existing field_tables/mem_region_model
            // hardcodes. Sound: the field IS a typed kernel pointer.
            if !typed && let Some(pointee) = kernel_internal_ptr_field(type_name, off) {
                let pointee_static =
                    crate::analysis::machine::context::intern_btf_type_name_strict(pointee);
                state.types.set(
                    dst,
                    RegType::PtrToBtfId {
                        type_name: pointee_static,
                        flags: PtrFlags::TRUSTED,
                        ref_id: None,
                    },
                );
                typed = true;
            }
            if !typed {
                state.types.set(dst, RegType::ScalarValue);
            }
        }
        _ => state.types.set(dst, RegType::ScalarValue),
    }
    false
}

/// Hand-modeled pointer fields of kernel-internal structs whose full BTF
/// layout the program's `.o` doesn't carry (so `field_at_offset_descend`
/// can't resolve them). Returns the pointee struct name for a `(struct,
/// byte-offset)` pair. Mirrors the existing `field_tables` /
/// `mem_region_model` hardcodes for kernel types.
fn kernel_internal_ptr_field(struct_name: &str, off: i16) -> Option<&'static str> {
    match (struct_name, off) {
        // struct bpf_iter_meta { struct seq_file *seq; u64 session_id; u64 seq_num; }
        ("bpf_iter_meta", 0) => Some("seq_file"),
        _ => None,
    }
}

/// Allowlist of `(struct_name, field_name)` pairs whose loaded pointer
/// value is treated as `PtrToBtfId{<pointee>, TRUSTED}`. Mirrors the
/// kernel's per-field "safe field" allowlist for tracing programs —
/// the kernel encodes most of these via BTF `__rcu` / `btf_type_tag`
/// metadata that we don't yet thread through `RegType` flags. The
/// intent is conservative: only fields whose kernel BTF actually marks
/// safe-to-load belong here, so unrelated `__failure` selftests that
/// rely on a non-allowlisted field landing as ScalarValue (and thus
/// getting rejected by the kfunc validator) keep their rejection.
///
/// Each entry is "this load yields a trusted pointer typed as the
/// declared pointee struct". Promote-from-allowlist is the *only*
/// way a load gets a typed pointer today; remove an entry to
/// re-introduce the lax-Scalar fallback.
/// Map a register type to the BTF struct name whose layout describes
/// what the program accesses through it. Used by the BTF field-load
/// typing path to look up `(struct_name, field@offset)` for
/// trusted-load promotion. Returns None for pointer kinds the path
/// doesn't handle (sock variants use mem_region_model field tables;
/// PtrToCtx / PtrToStack / etc. don't apply).
fn implied_btf_struct_name(ty: &RegType) -> Option<&'static str> {
    match ty {
        RegType::PtrToBtfId { type_name, .. } => Some(type_name),
        RegType::PtrToTask { .. } => Some("task_struct"),
        RegType::PtrToCgroup { .. } => Some("cgroup"),
        RegType::PtrToCpumask { .. } => Some("cpumask"),
        _ => None,
    }
}

use super::field_tables::{percpu_or_user_field, rcu_field_load, trusted_field_load};

/// Updates stack types after a Store operation.
/// `resolved_stack_offset` is the already-resolved stack slot (base_offset + insn_off),
/// or None if the base is not a stack pointer or offset is unknown.
pub(crate) fn update_store_types(
    stack: &mut StackState,
    src_type: RegType,
    size: MemSize,
    resolved_stack_offset: Option<i64>,
) {
    let stack_slot = resolved_stack_offset;

    if let Some(slot) = stack_slot {
        let slot = slot as i16;
        let byte_count = size.bytes() as i16; // U8=1, U16=2, U32=4, U64=8

        if size == MemSize::U64 {
            // Full 8-byte store preserves type info at the base slot
            stack.set_slot_type(slot, src_type, None);
            // Mark remaining bytes as initialized (but no type info)
            for i in 1..byte_count {
                stack.set_slot_type(slot + i, RegType::ScalarValue, None);
            }
        } else {
            // Partial store: mark all bytes as initialized, but poison type info
            for i in 0..byte_count {
                stack.set_slot_type(slot + i, RegType::ScalarValue, None);
            }
        }
    }
}

/// Checks if a helper invalidates packet pointers.
pub(crate) fn helper_invalidates_packets(helper: u32) -> bool {
    matches!(
        helper,
        constants::BPF_XDP_ADJUST_HEAD
            | constants::BPF_XDP_ADJUST_TAIL
            | constants::BPF_XDP_ADJUST_META
            | constants::BPF_SKB_PULL_DATA
            | constants::BPF_SKB_CHANGE_HEAD
            | constants::BPF_SKB_CHANGE_TAIL
            | constants::BPF_SKB_CHANGE_PROTO
            | constants::BPF_SKB_ADJUST_ROOM
            | constants::BPF_SKB_STORE_BYTES
            | constants::BPF_SKB_VLAN_PUSH
            | constants::BPF_SKB_VLAN_POP
            | constants::BPF_CLONE_REDIRECT
    )
}

/// Updates register types after a helper Call.
pub(crate) fn update_call_types(
    env: &mut VerifierEnv,
    in_types: &TypeState,
    state: &mut State,
    helper: u32,
) {
    // Default to scalar value
    state.types.set(Reg::R0, RegType::ScalarValue);

    // Try the proto-driven path first. For helpers whose proto
    // populates `ret`/`flags`/`side_effects`, this sets R0 and handles
    // acquire/release uniformly so kfuncs can reuse the same applier.
    // Returns false for helpers still on the legacy per-id match below.
    let routed = if let Some(proto) =
        crate::analysis::transfer::call::signatures::get_helper_proto(helper)
    {
        crate::analysis::transfer::call::side_effects::apply_call_proto_r0(
            in_types,
            state,
            &proto,
            env.ctx.prog_kind,
        )
    } else {
        false
    };

    // bpf_per_cpu_ptr / bpf_this_cpu_ptr R0 typing. Kernel
    // `check_helper_call` dispatches `RET_PTR_TO_MEM_OR_BTF_ID`:
    //   - typed ksyms (struct R1): R0 = PTR_TO_BTF_ID | MEM_RCU [| MAYBE_NULL]
    //     preserving the struct name, dropping PERCPU.
    //   - typeless ksyms (`extern const void X __ksym;`): would produce
    //     PTR_TO_MEM, but we never see those reach the helper today (they
    //     materialize as ScalarValue and the per_cpu_ptr arg gate rejects).
    // bpf_per_cpu_ptr returns NULL on invalid CPU; bpf_this_cpu_ptr never
    // returns NULL (always callable on the current CPU).
    if !routed && (helper == constants::BPF_PER_CPU_PTR || helper == constants::BPF_THIS_CPU_PTR) {
        // Resolve (type_name, in_flags) from the percpu source pointer.
        // Two source shapes today:
        //   - typed __ksym (`extern percpu T sym __ksym;`) → PtrToBtfId
        //   - `__percpu_kptr` map field load → PtrToMapKptr{PERCPU,
        //     pointee_btf_id} (kernel `PTR_TO_BTF_ID | MEM_PERCPU` on
        //     reg, mirrored as PtrToMapKptr in our model).
        let resolved: Option<(&'static str, crate::analysis::machine::reg_types::PtrFlags)> =
            match in_types.get(Reg::R1) {
                RegType::PtrToBtfId {
                    type_name, flags, ..
                } => Some((type_name, flags)),
                RegType::PtrToMapKptr {
                    pointee_btf_id,
                    flags,
                    ..
                }
                | RegType::PtrToMapKptrOrNull {
                    pointee_btf_id,
                    flags,
                    ..
                } => env.ctx.btf.struct_name(pointee_btf_id).map(|n| {
                    (
                        crate::analysis::machine::context::intern_btf_type_name_strict(n),
                        flags,
                    )
                }),
                _ => None,
            };
        if let Some((type_name, flags)) = resolved {
            // Drop PERCPU + RDONLY on the result; kernel marks the
            // post-call ptr as RCU-protected (typed ksym deref needs to
            // be inside an RCU read region, but our existing trust-band
            // model accepts TRUSTED-flagged BTF id pointers without
            // modeling RCU here). RDONLY is dropped because we don't
            // enforce ksym-derived per-cpu store rejection at the
            // field-store level today.
            let drop = crate::analysis::machine::reg_types::PtrFlags::PERCPU
                | crate::analysis::machine::reg_types::PtrFlags::RDONLY;
            let mut out_flags =
                flags.difference(drop) | crate::analysis::machine::reg_types::PtrFlags::TRUSTED;
            // Stamp MEM_ALLOC when the source was a `__percpu_kptr`
            // map field (PtrToMapKptr) — the dereferenced object is
            // program-owned (allocated via `bpf_percpu_obj_new`), so
            // direct field stores through R0 are allowed by the
            // kernel's `btf_struct_access`. Typed ksym sources
            // (PtrToBtfId) don't get MEM_ALLOC: those name kernel-
            // owned percpu vars (`__cpu_active_mask`-style) where
            // writes are rejected.
            let from_local_kptr = matches!(
                in_types.get(Reg::R1),
                RegType::PtrToMapKptr { .. } | RegType::PtrToMapKptrOrNull { .. }
            );
            if from_local_kptr {
                out_flags |= crate::analysis::machine::reg_types::PtrFlags::MEM_ALLOC;
            }
            if helper == constants::BPF_PER_CPU_PTR {
                let id = new_ptr_id();
                state.types.set(
                    Reg::R0,
                    RegType::PtrToBtfIdOrNull {
                        id,
                        type_name,
                        flags: out_flags,
                        ref_id: None,
                    },
                );
            } else {
                state.types.set(
                    Reg::R0,
                    RegType::PtrToBtfId {
                        type_name,
                        flags: out_flags,
                        ref_id: None,
                    },
                );
            }
            return;
        }
        // Fall through to default (Scalar) for typeless / non-BTF inputs.
    }

    // Set R0 based on helper return type (legacy path for non-migrated helpers)
    if !routed {
        match helper {
            constants::BPF_MAP_LOOKUP_ELEM
            | constants::BPF_MAP_LOOKUP_PERCPU_ELEM
            | constants::BPF_GET_LOCAL_STORAGE => {
                // Redirect through `inner_map_idx` only when R1 is itself
                // the result of an outer ARRAY_OF_MAPS / HASH_OF_MAPS
                // lookup (i.e. `PtrToMapValue`, not `PtrToMapObject`).
                // Without this, the inner-map lookup's R0 keeps the
                // outer's map_idx and subsequent helpers (`bpf_spin_lock`,
                // graph kfuncs) see the outer DATASEC's BTF instead of the
                // inner map's value type — they fail to find the
                // SpecialField at the offset (e.g.
                // linked_list.c::inner_map_list_push_pop pc 26 r1). The
                // outer lookup keeps its own map_idx so the next
                // `bpf_map_lookup_elem` validator's `is_inner_map_ptr`
                // check (which inspects R1's pointee map type) still
                // recognizes the chain.
                let map_idx = match in_types.get(Reg::R1) {
                    RegType::PtrToMapObject { map_idx } => map_idx,
                    RegType::PtrToMapValue {
                        map_idx: outer_idx, ..
                    } => env
                        .ctx
                        .map_defs
                        .get(outer_idx)
                        .and_then(|md| {
                            matches!(
                                md.type_,
                                constants::BPF_MAP_TYPE_ARRAY_OF_MAPS
                                    | constants::BPF_MAP_TYPE_HASH_OF_MAPS
                            )
                            .then_some(md.inner_map_idx)
                            .flatten()
                        })
                        .unwrap_or(outer_idx),
                    _ => 0,
                };
                let map_def_opt = env.ctx.map_defs.get(map_idx);
                if let Some(map_def) = map_def_opt {
                    match map_def.type_ {
                        constants::BPF_MAP_TYPE_SOCKMAP | constants::BPF_MAP_TYPE_SOCKHASH => {
                            let id = state.acquire_ref();
                            state
                                .types
                                .set(Reg::R0, RegType::PtrToSocketOrNull { ref_id: Some(id) });
                        }
                        _ => {
                            // bpf_get_local_storage returns a guaranteed non-null
                            // pointer (cgroup_storage / per-cpu storage is always
                            // allocated by the kernel for the prog's attach
                            // target) — type R0 as PtrToMapValue directly so the
                            // user can dereference without an explicit null check,
                            // matching kernel behaviour.
                            // map_uid: kernel mints a fresh per-lookup uid
                            // when the lookup target is a map-of-maps
                            // (each result represents a possibly-distinct
                            // inner-map instance). For inner-of-inner
                            // chains, R1 itself is a PtrToMapValue carrying
                            // the outer-lookup's uid; propagate. Reused by
                            // the bpf_timer_init / bpf_wq_init cross-arg
                            // check (timer_mim_reject::test1).
                            let map_uid: Option<u32> = match in_types.get(Reg::R1) {
                                RegType::PtrToMapObject { map_idx: outer } => {
                                    env.ctx.map_defs.get(outer).and_then(|m| {
                                        matches!(
                                            m.type_,
                                            constants::BPF_MAP_TYPE_ARRAY_OF_MAPS
                                                | constants::BPF_MAP_TYPE_HASH_OF_MAPS
                                        )
                                        .then(crate::analysis::machine::reg_types::new_map_uid)
                                    })
                                }
                                RegType::PtrToMapValue {
                                    map_uid: outer_uid, ..
                                } => outer_uid,
                                _ => None,
                            };
                            if helper == constants::BPF_GET_LOCAL_STORAGE {
                                let id = new_ptr_id();
                                state.types.set(
                                    Reg::R0,
                                    RegType::PtrToMapValue {
                                        id,
                                        offset: Some(0),
                                        map_idx,
                                        map_uid,
                                        rdonly: false,
                                    },
                                );
                                state.domain.init_map_value_ptr(Reg::R0);
                                bcf_anchor_map_value(state, Reg::R0);
                            } else if helper == constants::BPF_MAP_LOOKUP_ELEM
                                && matches!(
                                    map_def.type_,
                                    constants::BPF_MAP_TYPE_ARRAY
                                        | constants::BPF_MAP_TYPE_PERCPU_ARRAY
                                )
                                && const_key_in_bounds(state, map_def)
                            {
                                // Kernel: array-map lookups with a statically-known
                                // in-bounds key return PTR_TO_MAP_VALUE (non-null).
                                // verifier_array_access::*_no_nullness covers this.
                                let id = new_ptr_id();
                                state.types.set(
                                    Reg::R0,
                                    RegType::PtrToMapValue {
                                        id,
                                        offset: Some(0),
                                        map_idx,
                                        map_uid,
                                        rdonly: false,
                                    },
                                );
                                state.domain.init_map_value_ptr(Reg::R0);
                                bcf_anchor_map_value(state, Reg::R0);
                            } else {
                                let id = new_ptr_id();
                                state.types.set(
                                    Reg::R0,
                                    RegType::PtrToMapValueOrNull {
                                        id,
                                        map_idx,
                                        map_uid,
                                    },
                                );
                            }
                        }
                    }
                } else {
                    state.types.set(Reg::R0, RegType::ScalarValue);
                }
            }

            // Socket lookup helpers - return PTR_TO_SOCKET_OR_NULL
            constants::BPF_SK_LOOKUP_TCP | constants::BPF_SK_LOOKUP_UDP => {
                let id = state.acquire_ref();
                state
                    .types
                    .set(Reg::R0, RegType::PtrToSocketOrNull { ref_id: Some(id) });
            }

            // The socket reference from bpf_get_listener_sock doesn't need to be released
            constants::BPF_GET_LISTENER_SOCK => {
                state
                    .types
                    .set(Reg::R0, RegType::PtrToSocketOrNull { ref_id: None });
            }

            // Copies ref id from argument
            constants::BPF_SK_FULLSOCK => {
                let ref_id = state.types.get(Reg::R1).get_ref_id();
                state
                    .types
                    .set(Reg::R0, RegType::PtrToSocketOrNull { ref_id });
            }

            constants::BPF_TCP_SOCK => {
                let id = state.types.get(Reg::R1).get_ref_id();
                state.types.set(Reg::R0, RegType::PtrToTcpSockOrNull { id });
            }

            // bpf_sock_from_file(struct file *file): kernel returns
            // `struct socket *` or NULL. R0 = PtrToBtfIdOrNull{socket, TRUSTED}
            // so `sock->sk` field-load downstream resolves via the
            // `("socket", "sk")` trusted_field_load entry. Closes
            // bpf_iter_bpf_sk_storage_helpers::fill_socket_owner.
            constants::BPF_SOCK_FROM_FILE => {
                let id = new_ptr_id();
                state.types.set(
                    Reg::R0,
                    RegType::PtrToBtfIdOrNull {
                        id,
                        type_name: crate::analysis::machine::context::intern_btf_type_name_strict(
                            "socket",
                        ),
                        flags: PtrFlags::TRUSTED,
                        ref_id: None,
                    },
                );
            }

            // bpf_task_pt_regs(struct task_struct *task): kernel returns
            // `struct pt_regs *` (NULL only if `task` is invalid; treated as
            // PtrToBtfIdOrNull). Closes bpf_iter_tasks::dump_task_sleepable
            // (PT_REGS_IP(regs) reads regs->ip at offset 128 on x86_64).
            constants::BPF_TASK_PT_REGS => {
                let id = new_ptr_id();
                state.types.set(
                    Reg::R0,
                    RegType::PtrToBtfIdOrNull {
                        id,
                        type_name: crate::analysis::machine::context::intern_btf_type_name_strict(
                            "pt_regs",
                        ),
                        flags: PtrFlags::TRUSTED,
                        ref_id: None,
                    },
                );
            }

            // SKC lookup - returns PTR_TO_SOCK_COMMON_OR_NULL
            constants::BPF_SKC_LOOKUP_TCP => {
                let id = state.acquire_ref();
                state
                    .types
                    .set(Reg::R0, RegType::PtrToSockCommonOrNull { ref_id: Some(id) });
            }

            constants::BPF_SK_RELEASE => {
                if let Some(ref_id) = state.types.get(Reg::R1).get_ref_id() {
                    state.release_ref(ref_id);
                    state.invalidate_ref(ref_id);
                }
            }

            // SKC to kernel-struct sock conversion. The kernel's
            // `bpf_skc_to_*` helpers return `PTR_TO_BTF_ID | PTR_MAYBE_NULL`
            // typed as the kernel `struct tcp_sock` / `tcp6_sock` /
            // `tcp_timewait_sock` / `tcp_request_sock` / `udp6_sock` /
            // `unix_sock` — distinct from the UAPI `struct bpf_tcp_sock`
            // returned by the `bpf_tcp_sock()` helper. Programs deref
            // kernel-struct fields at offsets that exceed the UAPI snapshot
            // (e.g. `tcp_sock` offset 798 in bpf_iter_tcp6, offset 524 in
            // mptcp_subflow). Returning PtrToBtfIdOrNull{<kernel-struct>,
            // TRUSTED} routes through the existing PtrToBtfId machinery
            // (ALU preservation + lax field-load admit), unblocking the
            // bpf_iter_tcp/udp/unix family.
            //
            // Two acceptance shapes for R1:
            //   (a) acquire-tracked (ref_id Some) — refcounted sock pointer
            //       from bpf_sk_lookup_*; R0 inherits the same ref_id so
            //       `bpf_sk_release(R0)` finds it.
            //   (b) ctx-derived (trusted, no ref_id) — e.g. bpf_iter__tcp's
            //       `sk_common` field via the universal bpf_iter__*
            //       allowlist; KF_RCU treatment admits without acquire.
            constants::BPF_SKC_TO_TCP_SOCK
            | constants::BPF_SKC_TO_TCP6_SOCK
            | constants::BPF_SKC_TO_TCP_TIMEWAIT_SOCK
            | constants::BPF_SKC_TO_TCP_REQUEST_SOCK
            | constants::BPF_SKC_TO_UDP6_SOCK
            | constants::BPF_SKC_TO_UNIX_SOCK
            | constants::BPF_SKC_TO_MPTCP_SOCK => {
                let r1 = state.types.get(Reg::R1);
                let ref_id = r1.get_ref_id();
                let trusted = r1.is_trusted();
                // PtrToSockCommon / PtrToSocket from ctx-field reads
                // (sock_addr.sk, sock_ops.sk, …) carry neither ref_id nor
                // an explicit TRUSTED flag, but the kernel treats them as
                // valid input to skc_to_* — they originate from kernel-
                // managed ctx state. Without this acceptance, R0 falls
                // through to ScalarValue and downstream field reads
                // reject as "Unsafe generic load … type ScalarValue".
                let ctx_sock_ok = matches!(
                    r1,
                    RegType::PtrToSockCommon { .. }
                        | RegType::PtrToSocket { .. }
                        | RegType::PtrToTcpSock { .. }
                );
                if ref_id.is_some() || trusted || ctx_sock_ok {
                    let type_name = match helper {
                        constants::BPF_SKC_TO_TCP_SOCK => "tcp_sock",
                        constants::BPF_SKC_TO_TCP6_SOCK => "tcp6_sock",
                        constants::BPF_SKC_TO_TCP_TIMEWAIT_SOCK => "tcp_timewait_sock",
                        constants::BPF_SKC_TO_TCP_REQUEST_SOCK => "tcp_request_sock",
                        constants::BPF_SKC_TO_UDP6_SOCK => "udp6_sock",
                        constants::BPF_SKC_TO_UNIX_SOCK => "unix_sock",
                        constants::BPF_SKC_TO_MPTCP_SOCK => "mptcp_sock",
                        _ => unreachable!(),
                    };
                    let id = new_ptr_id();
                    state.types.set(
                        Reg::R0,
                        RegType::PtrToBtfIdOrNull {
                            id,
                            type_name:
                                crate::analysis::machine::context::intern_btf_type_name_strict(
                                    type_name,
                                ),
                            flags: PtrFlags::TRUSTED,
                            ref_id,
                        },
                    );
                }
            }

            // *_storage_get: R0 = PtrToMapValueOrNull keyed off the map (R1),
            // not the optional initial-value arg (R3). Real programs commonly
            // pass NULL for R3 (e.g. bpf_dctcp_init), and the prior version of
            // this arm fell through to Scalar in that case. fix.
            constants::BPF_SK_STORAGE_GET
            | constants::BPF_TASK_STORAGE_GET
            | constants::BPF_INODE_STORAGE_GET
            | constants::BPF_CGRP_STORAGE_GET => {
                let map_idx = match in_types.get(Reg::R1) {
                    RegType::PtrToMapObject { map_idx } => map_idx,
                    RegType::PtrToMapValue { map_idx, .. } => map_idx,
                    _ => 0,
                };
                let id = new_ptr_id();
                state.types.set(
                    Reg::R0,
                    RegType::PtrToMapValueOrNull {
                        id,
                        map_idx,
                        map_uid: None,
                    },
                );
            }

            // tail_call: R0 is undefined on failure path
            constants::BPF_TAIL_CALL => {
                state.types.set(Reg::R0, RegType::ScalarValue);
            }

            constants::BPF_SKB_LOAD_BYTES => {
                let mem_ptr_ty = in_types.get(Reg::R3);
                if let RegType::PtrToStack { frame_level } = mem_ptr_ty
                    && let Some(off) = state.domain.get_distance_fixed(Reg::R3, Reg::R10)
                {
                    let (_, hi) = state.domain.get_interval(Reg::R4);
                    let len = if hi <= 0xFFFF { hi as i16 } else { 0 };
                    if len > 0 {
                        // Kernel check_stack_range_initialized clobber semantics
                        // (verifier.c:8630 "helper can write anything into the
                        // stack" → STACK_MISC; :8635-8640 spilled slot →
                        // __mark_reg_unknown + whole-slot scrub_spilled_slot).
                        // (see the mem_size_pairs clobber in call/transfer.rs).
                        let stack = state.stack_at_mut(frame_level);
                        if let Ok(off16) = i16::try_from(off) {
                            stack.scrub_spilled_slots_for_write(off16, len as usize);
                        }
                        for i in 0..len {
                            stack.invalidate_slot((off + i as i64) as i16);
                        }
                    }
                }
            }

            constants::BPF_RINGBUF_RESERVE => {
                let (_, hi) = state.domain.get_interval(Reg::R2);
                state.types.set(
                    Reg::R0,
                    RegType::PtrToAllocMemOrNull {
                        id: new_ptr_id(),
                        mem_size: hi as u64,
                        ref_id: None,
                        dynptr_id: None,
                        rdonly: false,
                    },
                );
            }

            _ => {
                state.types.set(Reg::R0, RegType::ScalarValue);
            }
        }
    } // end if !routed

    // Clobber caller-saved registers - they are NOT readable after the call.
    // UNCONDITIONAL, incl. fastcall helpers: the kernel's
    // clear_caller_saved_regs (verifier.c:10994 "after the call registers
    // r0 - r5 were scratched") has no fastcall exception — bpf_fastcall
    // preserves VALUES only via the spill/fill pattern around the call
    // (mark_fastcall_pattern_for_call), and verification runs on the
    // original program with those spills/fills intact. A by-helper-id
    // skip would keep R1-R5 typed ScalarValue across fastcall calls,
    // so bcf_refine's seed rule (skip NOT_INIT) would include them
    // where the kernel doesn't.
    let _ = helper;
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        state.types.set(r, RegType::NotInit);
    }

    // 3. Invalidate packet pointers if needed
    if helper_invalidates_packets(helper) {
        for r in Reg::ALL {
            match state.types.get(r) {
                RegType::PtrToPacket | RegType::PtrToPacketEnd => {
                    state.types.set(r, RegType::ScalarValue);
                }
                _ => {}
            }
        }
        state.stack_mut().invalidate_packet_pointers();
        state
            .frames
            .invalidate_caller_reg_type(|ty| ty.is_packet_ptr(), RegType::NotInit);
        // Slices derived from a packet dynptr (`bpf_dynptr_slice` /
        // `_slice_rdwr` over an skb/xdp dynptr) become invalid when
        // the helper mutates packet data. Kernel sweeps every reg +
        // stack slot whose dynptr_id matches a packet-source dynptr
        // (verifier.c v6.15 L913-919). Mirrors `dynptr_fail.c`
        // `xdp_invalid_data_slice1/2` and the skb counterparts.
        let packet_dids = state.collect_packet_dynptr_ids();
        for did in packet_dids {
            state.invalidate_dynptr_slices(did);
        }
        // The helper changed packet geometry (data / data_end / length —
        // e.g. bpf_skb_pull_data extends the linear region, xdp_adjust_*
        // move the boundaries). Any previously-proven packet/meta size
        // bounds describe the OLD packet and no longer hold; the kernel
        // re-derives extent fresh from the post-helper pkt regs (which is
        // why a later `if pkt+N <= pkt_end` is feasible again). Without
        // this, a stale `packet_size < K` from a pre-helper "too small"
        // check makes the post-helper `pkt+N <= pkt_end` (N >= K) edge
        // domain-inconsistent and alivio drops the kernel's real path.
        // Mirrors the
        // function-entry `clear_packet_size_bounds` "start fresh"
        // rationale — same reason, different geometry-change trigger.
        if let crate::domains::numeric::NumericDomain::Interval(ref mut ivl) = state.domain {
            ivl.clear_packet_size_bounds();
        }
    }

    // bpf_dynptr_write: kernel only invalidates slices when the target
    // dynptr is BPF_DYNPTR_TYPE_SKB (verifier.c v6.15 ~L11512: "this will
    // trigger clear_all_pkt_pointers(), which will invalidate all dynptr
    // slices associated with the skb"). XDP-typed dynptrs don't trigger
    // the invalidation — `test_xdp_dynptr::_xdp_tx_iptunnel` writes
    // through a `bpf_dynptr_from_xdp` dynptr and continues using prior
    // slice-derived ptrs. Look up R1's stack-slot dynptr kind here
    // rather than blanket-invalidating via helper_invalidates_packets.
    // Closes dynptr_fail::skb_invalid_data_slice3, skb_invalid_data_slice4.
    if helper == constants::BPF_DYNPTR_WRITE {
        use crate::analysis::machine::stack_state::DynptrKind;
        if let RegType::PtrToStack { frame_level } = in_types.get(Reg::R1)
            && let Some(off) = state.domain.get_distance_fixed(Reg::R1, Reg::R10)
            && let Ok(off_i16) = i16::try_from(off)
            && let Some(slot) = state.stack_at(frame_level).stack_get_dynptr(off_i16)
            && matches!(slot.kind, DynptrKind::Skb)
        {
            let did = slot.dynptr_id;
            state.invalidate_dynptr_slices(did);
        }
    }
}

pub(crate) fn update_call_rel_types(state: &mut State) {
    state.types.set(Reg::R0, RegType::NotInit);
    state.types.set(
        Reg::R10,
        RegType::PtrToStack {
            frame_level: state.current_frame_level(),
        },
    );
}

pub(crate) fn update_packet_load_types(types: &mut TypeState) {
    // Clobber R1 - R5
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        types.set(r, RegType::NotInit);
    }

    // Set Result (R0)
    // The loaded data is placed in R0.
    types.set(Reg::R0, RegType::ScalarValue);
}

pub(crate) fn update_map_load_types(
    types: &mut TypeState,
    kind: MapLoadKind,
    map_fd: usize,
    dst: Reg,
    offset: i64,
    is_static_data_section: bool,
) {
    let new_type = match kind {
        MapLoadKind::MapPtr => RegType::PtrToMapObject { map_idx: map_fd },
        MapLoadKind::MapValue => RegType::PtrToMapValue {
            // Synthetic data sections (`.bss`, `.bss.<name>`, `.data`,
            // `.data.<name>`, `.rodata`, `.rodata.<name>`) load via
            // `BPF_PSEUDO_MAP_VALUE`, which the kernel does NOT mint a
            // fresh ptr_id for: every reload of `&alock` yields the
            // same identity. Required for `bpf_spin_lock` / `unlock` to
            // pair across two LD_IMM64s of the same `.bss.<name>`
            // global. Other map kinds (HASH/ARRAY etc.) keep fresh ids.
            id: if is_static_data_section {
                0
            } else {
                new_ptr_id()
            },
            map_idx: map_fd,
            offset: Some(offset),
            // Direct map decl — no map_uid (the per-instance identity
            // only matters for chained map-of-maps lookups).
            map_uid: None,
            rdonly: false,
        },
        // Modern kinds are filtered upstream in transfer_map_load; reaching
        // them here would be a bug.
        MapLoadKind::PseudoFunc { .. }
        | MapLoadKind::PseudoBtfId { .. }
        | MapLoadKind::PseudoMapIdx
        | MapLoadKind::PseudoMapIdxValue => {
            debug_assert!(
                false,
                "update_map_load_types reached with unsupported kind: {:?}",
                kind
            );
            return;
        }
    };

    types.set(dst, new_type);
}

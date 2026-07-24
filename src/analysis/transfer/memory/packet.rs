// src/analysis/transfer/memory/packet.rs

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::{MemSize, PacketLoadMode, ProgramKind};
use crate::common::constants;
use log::{debug, error};

use super::access::AccessKind;
use crate::analysis::transfer::common::check_reg_readable;

pub fn check_packet_alignment(state: &State, base: Reg, off: i16, size: i64) -> bool {
    if size == 1 {
        return true;
    }

    let (min_off, max_off) = get_packet_offset_range(state, base, off);

    match (min_off, max_off) {
        (Some(lo), Some(hi)) => {
            const NET_IP_ALIGN: i64 = 2;
            let lo_aligned = (NET_IP_ALIGN + lo) % size == 0;
            let hi_aligned = (NET_IP_ALIGN + hi) % size == 0;

            if lo % size != hi % size {
                return false;
            }

            lo_aligned && hi_aligned
        }
        _ => false,
    }
}

fn get_packet_offset_range(state: &State, base: Reg, insn_off: i16) -> (Option<i64>, Option<i64>) {
    let base_type = state.types.get(base);

    match base_type {
        RegType::PtrToPacket => {
            let insn_off = insn_off as i64;
            (Some(insn_off), Some(insn_off))
        }
        _ => {
            let pkt_start_reg = crate::analysis::machine::reg::REG_ENV
                .all()
                .iter()
                .find(|&&r| matches!(state.types.get(r), RegType::PtrToPacket));

            if let Some(&start_reg) = pkt_start_reg {
                let (lo, hi) = state.domain.get_distance_interval(base, start_reg);
                (
                    if lo != i64::MIN {
                        Some(lo + insn_off as i64)
                    } else {
                        None
                    },
                    if hi != i64::MAX {
                        Some(hi + insn_off as i64)
                    } else {
                        None
                    },
                )
            } else {
                (None, None)
            }
        }
    }
}

pub fn prog_kind_support_direct_packet_write(prog_kind: ProgramKind) -> bool {
    !matches!(prog_kind, ProgramKind::LwtIn | ProgramKind::LwtOut)
}

pub fn check_packet_access(
    env: &mut VerifierEnv,
    state: &State,
    base: Reg,
    off: i16,
    size: i64,
    pc: usize,
    kind: AccessKind,
) {
    if matches!(kind, AccessKind::Write)
        && !prog_kind_support_direct_packet_write(env.ctx.prog_kind)
    {
        error!(
            "Direct packet store at pc {} is not supported for {:?} program",
            pc, env.ctx.prog_kind
        );
        env.fail(VerificationError::IllegalPacketStore { pc, off, size });
        return;
    }

    let (start_ok, end_ok) = state.domain.verify_packet_bounds(base, off as i64, size);
    if std::env::var("ZOVIA_DUMP_PKTACC").ok().as_deref() == Some("1") {
        use crate::domains::numeric::NumericDomain;
        let po = match state.domain {
            NumericDomain::Interval(ref ivl) => ivl.get_ptr_offset(base).cloned(),
            _ => None,
        };
        eprintln!(
            "[pktacc] pc={} base={:?} off={} size={} start_ok={} end_ok={} po={:?}",
            pc, base, off, size, start_ok, end_ok, po
        );
    }
    debug!(
        "Packet access check at pc {}: base {} offset {} size {} => start_ok {}, end_ok {}",
        pc,
        base.name(),
        off,
        size,
        start_ok,
        end_ok
    );
    if !start_ok || !end_ok {
        if matches!(kind, AccessKind::Read) {
            env.fail(VerificationError::UnsafePacketLoad { pc, off, size });
        } else {
            env.fail(VerificationError::UnsafePacketStore { pc, off, size });
        }
    }

    if env.ctx.has_flag(constants::F_LOAD_WITH_STRICT_ALIGNMENT)
        && !matches!(kind, AccessKind::HelperBuffer)
        && !check_packet_alignment(state, base, off, size)
    {
        env.fail(VerificationError::MisalignedPacketAccess { pc, off, size });
    }
}

pub fn check_packet_meta_access(
    env: &mut VerifierEnv,
    state: &State,
    base: Reg,
    off: i16,
    size: i64,
    pc: usize,
) {
    let (start_ok, end_ok) = state
        .domain
        .verify_packet_meta_bounds(base, off as i64, size);
    if !start_ok || !end_ok {
        env.fail(VerificationError::UnsafePacketLoad { pc, off, size });
    }
}

pub(crate) fn transfer_packet_load(
    env: &mut VerifierEnv,
    mut state: State,
    size: MemSize,
    mode: PacketLoadMode,
    _offset_imm: i32,
    src: Option<Reg>,
) -> Vec<State> {
    let r6_type = state.types.get(Reg::R6);
    if !matches!(r6_type, RegType::PtrToCtx) {
        return vec![];
    }

    if let Some(reg) = src
        && !check_reg_readable(env, &mut state, reg)
    {
        return vec![];
    }

    if state.has_active_lock() && mode == PacketLoadMode::Abs {
        env.fail(VerificationError::LoadAbsUnderLock { pc: state.pc });
        return vec![];
    }

    crate::analysis::transfer::types::update_packet_load_types(&mut state.types);

    // Clobber R1 - R5 in DBM and Tnums as well
    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
        state.domain.forget(r);
        state.set_tnum(r, crate::domains::tnum::Tnum::unknown());
    }

    state.domain.forget(Reg::R0);
    // Reset R0's Tnum based on size
    match size {
        MemSize::U8 => {
            state.domain.assume_range(Reg::R0, 0, 255);
            let mut t = crate::domains::tnum::Tnum::unknown();
            t.value = 0;
            t.mask = 0xFF;
            state.set_tnum(Reg::R0, t);
        }
        MemSize::U16 => {
            state.domain.assume_range(Reg::R0, 0, 65535);
            let mut t = crate::domains::tnum::Tnum::unknown();
            t.value = 0;
            t.mask = 0xFFFF;
            state.set_tnum(Reg::R0, t);
        }
        MemSize::U32 => {
            state.domain.assume_range(Reg::R0, 0, 4294967295);
            state.set_tnum(Reg::R0, crate::domains::tnum::Tnum::u32_unknown());
        }
        MemSize::U64 => {
            state.set_tnum(Reg::R0, crate::domains::tnum::Tnum::unknown());
        }
    }

    state.pc += 1;
    vec![state]
}

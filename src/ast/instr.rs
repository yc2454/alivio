// src/ast/instr.rs

use super::{
    AluOp, AtomicOp, CmpOp, EndianOp, MapLoadKind, MemSize, Operand, PacketLoadMode, SxWidth, Width,
};
use crate::analysis::machine::reg::Reg;
use std::collections::HashSet;
use std::fmt;

/// What kind of call is this? Kernel distinguishes the three via the `src_reg`
/// field of the BPF_CALL insn: 0 = helper, 1 = subprog (lowered as `CallRel`),
/// 2 = kfunc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    Helper {
        id: u32,
    },
    /// `btf_id` names the kfunc in its owning BTF module; `offset` selects the
    /// module (0 = vmlinux). Transfer semantics are unimplemented today.
    Kfunc {
        btf_id: u32,
        offset: i16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instr {
    Alu {
        width: Width,
        op: AluOp,
        dst: Reg,
        src: Operand,
    },
    /// Sign-extending move (MOVSX, v6.6). Takes the low `src_bits` of `src`,
    /// sign-extends to `width` (W32 or W64), and writes to `dst`. Encoded in
    /// the kernel as BPF_MOV with off ∈ {8, 16, 32}.
    MovSx {
        width: Width,
        src_bits: SxWidth,
        dst: Reg,
        src: Operand,
    },
    Endian {
        dst: Reg,
        width: Width,
        op: EndianOp,
        size: u32,
    },
    If {
        width: Width,
        left: Reg,
        op: CmpOp,
        right: Operand,
        target: usize,
    },
    Jmp {
        target: usize,
    },
    /// may_goto / BPF_JCOND (v6.8). A conditional jump that may transfer
    /// control to `target` or fall through; the kernel models the choice
    /// with an iteration-bounded counter, capping loop iterations at ~8M.
    /// Decodes the instruction but does not implement counter
    /// semantics — transfer rejects with UnsupportedModernFeature.
    MayGoto {
        target: usize,
    },
    Load {
        size: MemSize,
        dst: Reg,
        base: Reg,
        off: i16,
    },
    /// Sign-extending load (LDSX, v6.6). Loads `size` bytes from
    /// `[base + off]` and sign-extends the result to 64 bits in `dst`.
    /// Only B/H/W sizes are defined by the ISA; U64 is not a valid LDSX
    /// size and is rejected at decode time.
    LoadSx {
        size: MemSize,
        dst: Reg,
        base: Reg,
        off: i16,
    },
    Store {
        size: MemSize,
        base: Reg,
        off: i16,
        src: Operand,
    },
    /// Load-acquire (BPF_LOAD_ACQ, v6.11). Semantically a typed load with
    /// acquire ordering; ordering does not affect static memory-safety
    /// analysis, so the value transfer is identical to Load. The kernel
    /// additionally bans BPF_ATOMIC reads from ctx/pkt/flow_keys pointers,
    /// which is what separates this variant from a plain Load.
    LoadAcq {
        size: MemSize,
        dst: Reg,
        base: Reg,
        off: i16,
    },
    /// Store-release (BPF_STORE_REL, v6.11). Mirror of LoadAcq on the store
    /// side: identical value transfer to Store, but BPF_ATOMIC writes into
    /// ctx/pkt/flow_keys pointers are rejected.
    StoreRel {
        size: MemSize,
        base: Reg,
        off: i16,
        src: Reg,
    },
    Atomic {
        op: AtomicOp,
        size: MemSize,
        fetch: bool,
        base: Reg,
        off: i16,
        src: Reg,
    },
    Call {
        kind: CallKind,
    },
    CallRel {
        target: usize,
    },
    LoadPacket {
        size: MemSize,
        mode: PacketLoadMode,
        offset_imm: i32,
        src: Option<Reg>,
    },
    LoadMap {
        dst: Reg,
        kind: MapLoadKind,
        map_fd: i32,
        off: i32,
    },
    Exit,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub instrs: Vec<Instr>,
    pub invalid_pc_set: HashSet<usize>,
    /// PCs of `BPF_MOV | BPF_X` instructions encoded as
    /// `bpf_addr_space_cast(dst_as=0, src_as=1)` — `off=1, imm=1` per
    /// kernel `verifier.c` ~L15402 (v6.15). Semantically: take a value
    /// in arena address space and produce a `PTR_TO_ARENA` (the
    /// 32-bit kernel-side handle to arena memory). The Mov transfer
    /// consults this set to retype dst as `PtrToArena` regardless of
    /// the source register's type (kernel does `mark_reg_unknown` then
    /// unconditionally sets `dst_reg->type = PTR_TO_ARENA`).
    /// The reverse direction (`imm == 0x10000`, `as(0)→as(1)`) leaves
    /// dst as `mark_reg_unknown` (Scalar) — kernel doesn't tag it.
    pub addr_space_cast_to_arena_pcs: HashSet<usize>,
}

impl fmt::Display for Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Instr::*;
        match *self {
            Alu {
                width,
                op,
                dst,
                src,
            } => {
                let op_str = match op {
                    AluOp::Add => "+",
                    AluOp::Sub => "-",
                    AluOp::And => "&",
                    AluOp::Or => "|",
                    AluOp::Xor => "^",
                    AluOp::Mov => "=",
                    AluOp::Shl => "<<",
                    AluOp::Shr => ">>",
                    AluOp::Arsh => "s>>",
                    AluOp::Mul => "*",
                    AluOp::Mod => "%",
                    AluOp::Div => "/",
                    AluOp::Neg => "-",
                    AluOp::Rsh => ">>",
                    AluOp::Lsh => "<<",
                };
                let src_str = match src {
                    Operand::Reg(r) => r.name().to_string(),
                    Operand::Imm(i) => format!("0x{:016x}", i),
                };
                let base = dst.name();
                let idx = &base[1..];
                let lhs = match width {
                    Width::W32 => format!("w{}", idx),
                    Width::W64 => format!("r{}", idx),
                };
                if let AluOp::Mov = op {
                    return write!(f, "{} = {}", lhs, src_str);
                }
                write!(f, "{} = {} {} {}", lhs, dst.name(), op_str, src_str)
            }
            Endian {
                dst,
                width: _,
                op,
                size,
            } => {
                let kind_str = match (op, size) {
                    (EndianOp::ToBe, 16) => "be16",
                    (EndianOp::ToBe, 32) => "be32",
                    (EndianOp::ToBe, 64) => "be64",
                    (EndianOp::ToLe, 16) => "le16",
                    (EndianOp::ToLe, 32) => "le32",
                    (EndianOp::ToLe, 64) => "le64",
                    (EndianOp::Bswap, 16) => "bswap16",
                    (EndianOp::Bswap, 32) => "bswap32",
                    (EndianOp::Bswap, 64) => "bswap64",
                    _ => "unknown",
                };
                write!(f, "{} = endian_{}", dst.name(), kind_str)
            }
            If {
                width,
                left,
                op,
                right,
                target,
            } => {
                let op_str = match op {
                    CmpOp::UGe => ">=u",
                    CmpOp::ULe => "<=u",
                    CmpOp::UGt => ">u",
                    CmpOp::ULt => "<u",
                    CmpOp::Eq => "==",
                    CmpOp::Ne => "!=",
                    CmpOp::SLt => "<",
                    CmpOp::SGt => ">",
                    CmpOp::SLe => "<=",
                    CmpOp::SGe => ">=",
                    CmpOp::Test => "&",
                };
                let right_str = match right {
                    Operand::Reg(r) => r.name().to_string(),
                    Operand::Imm(i) => format!("0x{:016x}", i),
                };
                let width_str = match width {
                    Width::W32 => "32",
                    Width::W64 => "64",
                };
                write!(
                    f,
                    "if {} {}{} {} goto {}",
                    left.name(),
                    op_str,
                    width_str,
                    right_str,
                    target
                )
            }
            Jmp { target } => write!(f, "goto {}", target),
            MayGoto { target } => write!(f, "may_goto {}", target),
            Load {
                size,
                dst,
                base,
                off,
            } => {
                let size_str = match size {
                    MemSize::U8 => "u8",
                    MemSize::U16 => "u16",
                    MemSize::U32 => "u32",
                    MemSize::U64 => "u64",
                };
                write!(
                    f,
                    "{} = *({} *)({} + {})",
                    dst.name(),
                    size_str,
                    base.name(),
                    off
                )
            }
            LoadSx {
                size,
                dst,
                base,
                off,
            } => {
                let size_str = match size {
                    MemSize::U8 => "s8",
                    MemSize::U16 => "s16",
                    MemSize::U32 => "s32",
                    MemSize::U64 => "s64",
                };
                write!(
                    f,
                    "{} = *({} *)({} + {})",
                    dst.name(),
                    size_str,
                    base.name(),
                    off
                )
            }
            MovSx {
                width,
                src_bits,
                dst,
                src,
            } => {
                let base = dst.name();
                let idx = &base[1..];
                let lhs = match width {
                    Width::W32 => format!("w{}", idx),
                    Width::W64 => format!("r{}", idx),
                };
                let src_str = match src {
                    Operand::Reg(r) => r.name().to_string(),
                    Operand::Imm(i) => format!("0x{:016x}", i),
                };
                write!(f, "{} = (s{}) {}", lhs, src_bits.bits(), src_str)
            }
            Store {
                size,
                base,
                off,
                src,
            } => {
                let size_str = match size {
                    MemSize::U8 => "u8",
                    MemSize::U16 => "u16",
                    MemSize::U32 => "u32",
                    MemSize::U64 => "u64",
                };
                let src_str = match src {
                    Operand::Reg(r) => r.name().to_string(),
                    Operand::Imm(i) => format!("0x{:016x}", i),
                };
                write!(
                    f,
                    "*({} *)({} + {}) = {}",
                    size_str,
                    base.name(),
                    off,
                    src_str
                )
            }
            LoadAcq {
                size,
                dst,
                base,
                off,
            } => {
                let size_str = match size {
                    MemSize::U8 => "u8",
                    MemSize::U16 => "u16",
                    MemSize::U32 => "u32",
                    MemSize::U64 => "u64",
                };
                write!(
                    f,
                    "{} = load_acquire *({} *)({} + {})",
                    dst.name(),
                    size_str,
                    base.name(),
                    off
                )
            }
            StoreRel {
                size,
                base,
                off,
                src,
            } => {
                let size_str = match size {
                    MemSize::U8 => "u8",
                    MemSize::U16 => "u16",
                    MemSize::U32 => "u32",
                    MemSize::U64 => "u64",
                };
                write!(
                    f,
                    "store_release *({} *)({} + {}) = {}",
                    size_str,
                    base.name(),
                    off,
                    src.name()
                )
            }
            Atomic {
                op,
                size,
                base,
                off,
                src,
                fetch: _,
            } => {
                let size_str = match size {
                    MemSize::U8 => "u8",
                    MemSize::U16 => "u16",
                    MemSize::U32 => "u32",
                    MemSize::U64 => "u64",
                };
                let op_str = match op {
                    AtomicOp::Add => "+",
                    AtomicOp::Or => "||",
                    AtomicOp::And => "&&",
                    AtomicOp::CmpXchg => "cmpxchg",
                    AtomicOp::Xor => "^",
                    AtomicOp::Xchg => "xchg",
                };
                write!(
                    f,
                    "lock *({} *)({} {} {}) += {}",
                    size_str,
                    base.name(),
                    op_str,
                    off,
                    src.name()
                )
            }
            Call { kind } => match kind {
                CallKind::Helper { id } => write!(f, "call {}", id),
                CallKind::Kfunc { btf_id, offset } => {
                    write!(f, "call kfunc #{}:{}", offset, btf_id)
                }
            },
            CallRel { target } => write!(f, "call {}", target),
            LoadPacket { .. } => write!(f, "ld_abs or ld_ind"),
            LoadMap { map_fd, .. } => write!(f, "load map {}", map_fd),
            Exit => write!(f, "exit"),
        }
    }
}

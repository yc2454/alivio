// src/bpf_to_ast.rs
use crate::analysis::machine::reg::Reg;
use crate::ast::{
    AluOp, AtomicOp, CallKind, CmpOp, EndianOp, Instr, MapLoadKind, MemSize, Operand,
    PacketLoadMode, Program, SxWidth, Width,
};
use crate::parsing::bpf_insn::RawBpfInsn;
use std::collections::HashSet;

#[derive(Debug)]
pub enum LowerErrorKind {
    UnknownOpcode,
    InvalidLDIMM64,
    BranchTargetOutOfRange,
    CallTargetOutOfBounds,
    InvalidSrcReg,
    UnknownAtomicOp,
    CallUsedReservedFields,
    InvalidRegister,
}

#[derive(Debug)]
pub struct LowerError {
    pub pc: usize,
    pub code: u8,
    pub msg: String,
    pub kind: LowerErrorKind,
}

fn reg_to_var(insn: &RawBpfInsn, r: u8, pc: usize) -> Result<Reg, LowerError> {
    match r {
        0 => Ok(Reg::R0),
        1 => Ok(Reg::R1),
        2 => Ok(Reg::R2),
        3 => Ok(Reg::R3),
        4 => Ok(Reg::R4),
        5 => Ok(Reg::R5),
        6 => Ok(Reg::R6),
        7 => Ok(Reg::R7),
        8 => Ok(Reg::R8),
        9 => Ok(Reg::R9),
        10 => Ok(Reg::R10),
        _ => Err(LowerError {
            pc,
            code: insn.code,
            msg: "invalid register".to_string(),
            kind: LowerErrorKind::InvalidRegister,
        }),
    }
}

fn branch_target(pc: usize, off: i16, len: usize, code: u8) -> Result<usize, LowerError> {
    branch_target_disp(pc, off as i32, len, code)
}

/// `gotol` (v6.7, opcode 0x06) widens the 16-bit displacement to a signed
/// 32-bit displacement carried in the `imm` field. This helper takes the
/// wider form; the classic 16-bit variant goes through `branch_target`.
fn branch_target_disp(pc: usize, disp: i32, len: usize, code: u8) -> Result<usize, LowerError> {
    let t = pc as isize + 1 + disp as isize;
    if t < 0 || (t as usize) >= len {
        return Err(LowerError {
            pc,
            code,
            msg: format!("branch target out of range: {}", t),
            kind: LowerErrorKind::BranchTargetOutOfRange,
        });
    }
    Ok(t as usize)
}

pub fn lower_raw_to_program(raw: &[RawBpfInsn]) -> Result<Program, LowerError> {
    let mut instrs = Vec::with_capacity(raw.len());
    let mut invalid_pc_set = HashSet::new();
    let mut addr_space_cast_to_arena_pcs: HashSet<usize> = HashSet::new();
    let mut pc: usize = 0;

    while pc < raw.len() {
        let insn = &raw[pc];
        let dst = reg_to_var(insn, insn.dst, pc)?;
        let src = reg_to_var(insn, insn.src, pc)?;

        if insn.code == 0x18 {
            // src_reg encoding (kernel uapi/linux/bpf.h BPF_PSEUDO_*):
            //   0 = immediate value
            //   1 = BPF_PSEUDO_MAP_FD         (map pointer)
            //   2 = BPF_PSEUDO_MAP_VALUE      (map value, e.g. .bss/.data/.rodata)
            //   3 = BPF_PSEUDO_BTF_ID         (ksym / percpu var, v5.10+)
            //   4 = BPF_PSEUDO_FUNC           (callback function pointer, v5.13+)
            //   5 = BPF_PSEUDO_MAP_IDX        (aux table index, v5.17+)
            //   6 = BPF_PSEUDO_MAP_IDX_VALUE  (aux table map value, v5.17+)
            if (insn.src > 6) || insn.off != 0 {
                return Err(LowerError {
                    pc,
                    code: insn.code,
                    msg: format!(
                        "invalid BPF_LD_IMM insn: src_reg={} off={} (expected src 0..=6 and off 0)",
                        insn.src, insn.off
                    ),
                    kind: LowerErrorKind::InvalidLDIMM64,
                });
            }
            if pc + 1 >= raw.len() {
                return Err(LowerError {
                    pc,
                    code: insn.code,
                    msg: "unexpected end of instructions after LDDW".to_string(),
                    kind: LowerErrorKind::InvalidLDIMM64,
                });
            }
            let cont = &raw[pc + 1];
            if cont.code != 0x00 {
                return Err(LowerError {
                    pc,
                    code: cont.code,
                    msg: "expected continuation instruction after LDDW".to_string(),
                    kind: LowerErrorKind::InvalidLDIMM64,
                });
            }
            if cont.code != 0 || cont.dst != 0 || cont.src != 0 || cont.off != 0 {
                return Err(LowerError {
                    pc,
                    code: cont.code,
                    msg: "invalid BPF_LD_IMM insn: next insn fields must be 0".to_string(),
                    kind: LowerErrorKind::InvalidLDIMM64,
                });
            }

            let low: u32 = insn.imm as u32;
            let high: u32 = cont.imm as u32;
            let imm_u64: u64 = (low as u64) | ((high as u64) << 32);
            let imm_i64: i64 = imm_u64 as i64;

            // AST 1: The Load
            match src {
                Reg::R0 => {
                    instrs.push(Instr::Alu {
                        width: Width::W64,
                        op: AluOp::Mov,
                        dst,
                        src: Operand::Imm(imm_i64),
                    });
                }
                Reg::R1 => {
                    if cont.imm != 0 {
                        return Err(LowerError {
                            pc,
                            code: insn.code,
                            msg: "invalid BPF_LD_IMM insn: imm must be 0".to_string(),
                            kind: LowerErrorKind::InvalidLDIMM64,
                        });
                    }
                    instrs.push(Instr::LoadMap {
                        dst,
                        kind: MapLoadKind::MapPtr,
                        map_fd: imm_i64 as i32,
                        off: 0,
                    });
                }
                Reg::R2 => {
                    let off = if pc + 1 < raw.len() {
                        raw[pc + 1].imm
                    } else {
                        0
                    };
                    instrs.push(Instr::LoadMap {
                        dst,
                        kind: MapLoadKind::MapValue,
                        map_fd: imm_i64 as i32,
                        off,
                    });
                }
                // BPF_PSEUDO_BTF_ID (src=3): imm holds the BTF id of a ksym / percpu var.
                Reg::R3 => {
                    instrs.push(Instr::LoadMap {
                        dst,
                        kind: MapLoadKind::PseudoBtfId {
                            btf_id: imm_i64 as u32,
                        },
                        map_fd: 0,
                        off: 0,
                    });
                }
                // BPF_PSEUDO_FUNC (src=4): imm holds a PC-relative offset to a subprog.
                Reg::R4 => {
                    let next_pc = pc as i64 + 2; // LD_IMM64 is a 2-slot insn
                    let target = next_pc + imm_i64;
                    if target < 0 || target as usize >= raw.len() {
                        return Err(LowerError {
                            pc,
                            code: cont.code,
                            msg: "BPF_PSEUDO_FUNC target out of bounds".to_string(),
                            kind: LowerErrorKind::InvalidLDIMM64,
                        });
                    }
                    instrs.push(Instr::LoadMap {
                        dst,
                        kind: MapLoadKind::PseudoFunc {
                            subprog_pc: target as u32,
                        },
                        map_fd: 0,
                        off: 0,
                    });
                }
                // BPF_PSEUDO_MAP_IDX (src=5): map index in aux table (pre-relocation).
                Reg::R5 => {
                    instrs.push(Instr::LoadMap {
                        dst,
                        kind: MapLoadKind::PseudoMapIdx,
                        map_fd: imm_i64 as i32,
                        off: 0,
                    });
                }
                // BPF_PSEUDO_MAP_IDX_VALUE (src=6): like MAP_VALUE but by aux index.
                Reg::R6 => {
                    let off = if pc + 1 < raw.len() {
                        raw[pc + 1].imm
                    } else {
                        0
                    };
                    instrs.push(Instr::LoadMap {
                        dst,
                        kind: MapLoadKind::PseudoMapIdxValue,
                        map_fd: imm_i64 as i32,
                        off,
                    });
                }
                _ => {
                    return Err(LowerError {
                        pc,
                        code: cont.code,
                        msg: "invalid BPF_LD_IMM insn: invalid source reg".to_string(),
                        kind: LowerErrorKind::InvalidLDIMM64,
                    });
                }
            }

            // AST 2: The No-Op (Maps to 'pc + 1')
            // We record this PC. If we reach here later, it's an error
            invalid_pc_set.insert(pc + 1);

            instrs.push(Instr::Alu {
                width: Width::W64,
                op: AluOp::Mov,
                dst: Reg::R0,
                src: Operand::Reg(Reg::R0),
            });

            pc += 2;
            continue;
        }

        let ir: Instr = match insn.code {
            // --- ALU64 ---

            // 0xbc: MOV32 reg  (w_dst = w_src)
            // v6.6 overloads `off` ∈ {8, 16, 32} to select MOVSX width; off=0
            // is the classic zero-extending MOV32.
            0xbc => match insn.off {
                0 => Instr::Alu {
                    width: Width::W32,
                    op: AluOp::Mov,
                    dst,
                    src: Operand::Reg(src),
                },
                8 | 16 => Instr::MovSx {
                    width: Width::W32,
                    src_bits: if insn.off == 8 {
                        SxWidth::B8
                    } else {
                        SxWidth::B16
                    },
                    dst,
                    src: Operand::Reg(src),
                },
                _ => {
                    return Err(LowerError {
                        pc,
                        code: insn.code,
                        msg: format!(
                            "invalid MOV32 off field: {} (expected 0, 8, or 16)",
                            insn.off
                        ),
                        kind: LowerErrorKind::UnknownOpcode,
                    });
                }
            },

            // 0xbf: rX = rY   (ALU64 | MOV | X)
            // v6.6 overloads `off` ∈ {8, 16, 32} to select MOVSX width; off=0
            // is the classic 64-bit MOV. v6.7 reuses `off=1` to mark
            // `bpf_addr_space_cast` (BPF_ADDR_SPACE_CAST), which casts a
            // pointer between kernel and arena address spaces. From the
            // verifier's perspective the resulting register inherits the
            // source's type/bounds — the cast is a runtime address rewrite,
            // not a precision-affecting operation — so we lower it as a
            // plain MOV. This keeps `PtrToArena` mem_size and ref tracking
            // intact across the cast.
            0xbf => match insn.off {
                0 | 1 => {
                    // off=1 marks `bpf_addr_space_cast` (kernel
                    // `verifier.c` ~L15361, v6.15). Valid imms are 1
                    // (cast as(1)→as(0), result is PTR_TO_ARENA) and
                    // 0x10000 (cast as(0)→as(1), result is unknown
                    // scalar). Other imms are rejected by the kernel —
                    // leave the lowering tolerant and let runtime
                    // checks catch malformed inputs. Only the
                    // `imm == 1` form needs special transfer handling
                    // (Mov retypes dst to PtrToArena).
                    if insn.off == 1 && insn.imm == 1 {
                        addr_space_cast_to_arena_pcs.insert(pc);
                    }
                    Instr::Alu {
                        width: Width::W64,
                        op: AluOp::Mov,
                        dst,
                        src: Operand::Reg(src),
                    }
                }
                8 | 16 | 32 => Instr::MovSx {
                    width: Width::W64,
                    src_bits: match insn.off {
                        8 => SxWidth::B8,
                        16 => SxWidth::B16,
                        _ => SxWidth::B32,
                    },
                    dst,
                    src: Operand::Reg(src),
                },
                _ => {
                    return Err(LowerError {
                        pc,
                        code: insn.code,
                        msg: format!(
                            "invalid MOV64 off field: {} (expected 0, 1, 8, 16, or 32)",
                            insn.off
                        ),
                        kind: LowerErrorKind::UnknownOpcode,
                    });
                }
            },

            // 0xb7: rX = imm  (ALU64 | MOV | K)
            0xb7 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Mov,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x04: ADD32_K  w_dst += imm
            0x04 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Add,
                dst,
                // imm is signed; keep sign so "w2 += -1" behaves like subtract 1
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x0c: ADD32_X  w_dst += w_src
            0x0c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Add,
                dst,
                src: Operand::Reg(src),
            },

            // 0x07: rX += imm (ALU64 | ADD | K)
            0x07 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Add,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x0f: rX += rY  (ALU64 | ADD | X)
            0x0f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Add,
                dst,
                src: Operand::Reg(src),
            },

            // 0x1f: SUB64_X  (dst -= src)
            0x1f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Sub,
                dst,
                src: Operand::Reg(src),
            },

            // 0x14: SUB32_K  w_dst -= imm
            0x14 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Sub,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x17: SUB64_K  r_dst -= imm
            0x17 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Sub,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x1c: SUB32_X  w_dst -= w_src
            0x1c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Sub,
                dst,
                src: Operand::Reg(src),
            },

            // 0x24: MUL32_K  w_dst *= imm
            0x24 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Mul,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x2c: MUL32_X  w_dst *= w_src
            0x2c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Mul,
                dst,
                src: Operand::Reg(src),
            },

            // 0x27: MUL64_K  r_dst *= imm
            0x27 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Mul,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x2f: MUL64_X  r_dst *= r_src
            0x2f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Mul,
                dst,
                src: Operand::Reg(src),
            },

            // 0x37: DIV64_K  r_dst /= imm
            0x37 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Div,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x3f: DIV64_X  r_dst /= r_src
            0x3f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Div,
                dst,
                src: Operand::Reg(src),
            },

            // 0x34: DIV32_K  w_dst /= imm
            0x34 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Div,
                dst,
                // Zero-extend 32-bit immediate for division
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0x3c: DIV32_X  w_dst /= w_src
            0x3c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Div,
                dst,
                src: Operand::Reg(src),
            },

            // 0x4f: OR64_X r_dst |= r_src
            0x4f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Or,
                dst,
                src: Operand::Reg(src),
            },

            // 0x5c: AND32_X  w_dst &= w_src
            0x5c => Instr::Alu {
                width: Width::W32,
                op: AluOp::And,
                dst,
                src: Operand::Reg(src),
            },

            // 0x5f: AND64_X r_dst &= r_src
            0x5f => Instr::Alu {
                width: Width::W64,
                op: AluOp::And,
                dst,
                src: Operand::Reg(src),
            },

            // 0x6f: LSH64_X r_dst <<= r_src
            0x6f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Shl,
                dst,
                src: Operand::Reg(src),
            },

            // 0x7f: RSH64_X r_dst >>= r_src
            0x7f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Shr,
                dst,
                src: Operand::Reg(src),
            },

            // 0x54: AND32 imm  (wX &= imm32)
            0x54 => Instr::Alu {
                width: Width::W32,
                op: AluOp::And,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64), // u32 mask
            },

            // 0x57: rX &= imm (ALU64 | AND | K)
            0x57 => Instr::Alu {
                width: Width::W64,
                op: AluOp::And,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x44: OR32_K  (w_dst |= imm)
            0x44 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Or,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0x4c: OR32_X  w_dst |= w_src
            0x4c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Or,
                dst,
                src: Operand::Reg(src),
            },

            // 0x47: OR64_K  r_dst |= imm
            0x47 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Or,
                dst,
                // immediate is effectively used as an unsigned bitmask
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0x64: LSH32_K  (w_dst <<= imm)
            0x64 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Shl,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0x6c: LSH32_X  (w_dst <<= w_src)
            0x6c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Shl,
                dst,
                src: Operand::Reg(src),
            },

            // 0x67: LSH64 imm  (rX <<= imm)
            0x67 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Shl,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0x74: RSH32_K  w_dst >>= imm (logical)
            0x74 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Shr,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0x77: RSH64 imm  (logical) (rX >>= imm)
            0x77 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Shr,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0x7c: RSH32_X  w_dst >>= w_src
            0x7c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Shr,
                dst,
                src: Operand::Reg(src),
            },

            // 0x84: NEG32 (w_dst = -w_dst)
            0x84 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Neg,
                dst,
                src: Operand::Imm(0), // Neg is unary; src is ignored/dummy
            },

            // 0x87: NEG64 (dst = -dst)
            0x87 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Neg,
                dst,
                src: Operand::Imm(0), // Unary op, src is ignored
            },

            // 0x94: MOD32_K  w_dst %= imm
            0x94 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Mod,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x9c: MOD32_X  w_dst %= w_src
            0x9c => Instr::Alu {
                width: Width::W32,
                op: AluOp::Mod,
                dst,
                src: Operand::Reg(src),
            },

            0x97 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Mod,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x9f: MOD64_X  r_dst %= r_src
            0x9f => Instr::Alu {
                width: Width::W64,
                op: AluOp::Mod,
                dst,
                src: Operand::Reg(src),
            },

            // 0xa4: XOR32_K  w_dst ^= imm
            0xa4 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Xor,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0xac: XOR32_X  w_dst ^= w_src
            0xac => Instr::Alu {
                width: Width::W32,
                op: AluOp::Xor,
                dst,
                src: Operand::Reg(src),
            },

            // 0xa7: XOR64_K  r_dst ^= imm
            0xa7 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Xor,
                dst,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0xaf: XOR64_X  r_dst ^= r_src
            0xaf => Instr::Alu {
                width: Width::W64,
                op: AluOp::Xor,
                dst,
                src: Operand::Reg(src),
            },

            // 0xc4: ARSH32_K  w_dst s>>= imm
            0xc4 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Arsh,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0xcc: ARSH32_X  w_dst s>>= w_src
            0xcc => Instr::Alu {
                width: Width::W32,
                op: AluOp::Arsh,
                dst,
                src: Operand::Reg(src),
            },

            // 0xc7: ARSH64_K  r_dst s>>= imm
            0xc7 => Instr::Alu {
                width: Width::W64,
                op: AluOp::Arsh,
                dst,
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0xcf: ARSH64_X  r_dst s>>= r_src
            0xcf => Instr::Alu {
                width: Width::W64,
                op: AluOp::Arsh,
                dst,
                src: Operand::Reg(src),
            },

            // --- ENDIAN ---
            // 0xd4: BPF_END: endian conversion on dst.
            0xd4 => Instr::Endian {
                width: Width::W32,
                dst,
                op: EndianOp::ToLe,
                size: insn.imm as u32,
            },

            // 0xdc: BPF_END: endian conversion on dst.
            0xdc => Instr::Endian {
                width: Width::W32,
                dst,
                op: EndianOp::ToBe,
                size: insn.imm as u32,
            },

            // 0xd7: BPF_ALU64 | BPF_END | BPF_K — BSWAP (BPF v4).
            // dst = bswap_{imm}(dst); imm ∈ {16, 32, 64}.
            0xd7 => Instr::Endian {
                width: Width::W64,
                dst,
                op: EndianOp::Bswap,
                size: insn.imm as u32,
            },

            // --- JMP ---
            // 0x95: exit (JMP | EXIT)
            0x95 => Instr::Exit,

            // 0x15: JEQ imm (if dst == imm goto target)
            0x15 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::Eq,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x1d: JEQ_X (if dst == src goto target, 64-bit)
            0x1d => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::Eq,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x1e: JEQ32_X (if (u32)dst == (u32)src goto target)
            0x1e => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::Eq,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x25: JGT_K (if dst > imm, 64-bit)
            0x25 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::UGt,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x26: JGT32_K  (if (u32)dst > (u32)imm goto target)
            //
            // MVP semantics: we lower to UGt, but transfer_if does no refinement
            // for UGt, so this only creates the branch structure and keeps DBM
            // unchanged on both paths (sound for unsigned comparison).
            0x26 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::UGt,
                    right: Operand::Imm(insn.imm as u32 as i64),
                    target,
                }
            }

            // 0x2d: JGT_X (if dst > src goto target)
            0x2d => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::UGt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x2e: JGT_X (if dst > (u32)src goto target)
            0x2e => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::UGt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x35: JGE_K (if u64(dst) >= u64(imm) goto target)
            0x35 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::UGe,
                    // The immediate is sign-extended from i32 to i64,
                    // but the comparison treats the bits as unsigned.
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x36: JGE_K_32 (if (u32)dst >= imm32)
            0x36 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::UGe,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x3d: JGE_X (if dst >= src goto target, 64-bit)
            0x3d => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::UGe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x3e: JGE32_X (if (u32)dst >= (u32)src goto target)
            0x3e => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::UGe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x45: JSET_K (if (u64)dst & imm)
            0x45 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::Test,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x46: JSET_K_32 (if (u32)dst & imm32)
            0x46 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::Test,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x4d: JSET_X_64 (if (u64)dst & (u64)src)
            // Class: BPF_JMP (0x05) | Op: BPF_JSET (0x40) | Src: BPF_X (0x08)
            0x4d => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::Test,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x4e: JSET_X_32 (if (u32)dst & (u32)src)
            0x4e => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::Test,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x55: JNE imm (if dst != imm goto target)
            0x55 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::Ne,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x56: JNE32 imm  (if (u32)dst != (u32)imm goto target)
            0x56 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::Ne,
                    right: Operand::Imm((insn.imm as u32) as i64),
                    target,
                }
            }

            // 0x5d: JNE_X (if dst != src goto target)
            0x5d => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::Ne,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x5e: JNE32_X  (if (u32)dst != (u32)src goto target)
            0x5e => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::Ne,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x65: JSGT_K (if s64(dst) > s64(imm) goto target)
            0x65 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SGt,
                    // insn.imm is i32, casting to i64 sign-extends it correctly
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x66: JSGT32_K  (if (s32)dst > (s32)imm goto target)
            0x66 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SGt,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x6d: JSGT_X (if s64(dst) > s64(src) goto target)
            0x6d => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SGt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x6e: JSGT32_X (if (s32)dst > (s32)src goto target)
            0x6e => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SGt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x75: JSGE_K_64 (if (s64)dst >= imm)
            // Class: BPF_JMP (0x05) | Op: BPF_JSGE (0x70) | Src: BPF_K (0x00)
            0x75 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SGe,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x76: JSGE_K_32 (if (s32)dst >= imm32)
            0x76 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SGe,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0x7d: JSGE_X_64 (if (s64)dst >= (s64)src)
            0x7d => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SGe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x7e: JSGE_X_32 (if (s32)dst >= (s32)src)
            0x7e => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SGe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xa5: JLT_K (if dst < imm goto target, unsigned 64-bit)
            0xa5 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::ULt,
                    // BPF immediates are sign-extended to 64-bit before comparison,
                    // even for unsigned checks (e.g. comparing against -1 / UMAX).
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0xa6: JLT32_K  (if (u32)dst < (u32)imm goto target)
            0xa6 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::ULt,
                    right: Operand::Imm((insn.imm as u32) as i64),
                    target,
                }
            }

            // 0xad: JLT_X (if dst < src goto target)
            0xad => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::ULt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xae: JLT32_X  (if (u32)dst < (u32)src goto target)
            //
            // MVP semantics: we treat this as an unsigned <.
            // transfer_if already *does not refine* for JMP32 with reg RHS,
            // so this only creates the branch and keeps zones unchanged.
            0xae => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::ULt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xbd: if rX <= rY goto +off (JMP | JLE | X)  (unsigned compare)
            0xbd => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::ULe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xb4: wX = imm  (ALU32 | MOV | K)  == mov32 imm (zero-extend)
            0xb4 => Instr::Alu {
                width: Width::W32,
                op: AluOp::Mov,
                dst,
                // IMPORTANT: mov32 uses u32 then zero-extends to 64
                src: Operand::Imm((insn.imm as u32) as i64),
            },

            // 0xb5: if rX <= imm goto +off (JMP | JLE | K)  (unsigned compare)
            0xb5 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::ULe,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0xb6: JLE32_K (if (u32)dst <= (u32)imm goto target)
            0xb6 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::ULe,
                    // Treat immediate as unsigned 32-bit
                    right: Operand::Imm((insn.imm as u32) as i64),
                    target,
                }
            }

            // 0xbe: JLE32_X (if (u32)dst <= (u32)src goto target)
            0xbe => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::ULe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xc5: JSLT_K_64 (if (s64)dst < imm)
            0xc5 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SLt,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0xc6: JSLT32_K (if (s32)dst < (s32)imm goto target)
            0xc6 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SLt,
                    // insn.imm is i32; casting to i64 preserves sign, which is what we want
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0xcd: JSLT_X_64 (if (s64)dst < (s64)src goto target)
            0xcd => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SLt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xce: JSLT32_X (if (s32)dst < (s32)src goto target)
            0xce => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SLt,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xd5: JSLE_K_64 (if (s64)dst <= imm)
            0xd5 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SLe,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0xd6: JSLE32_K (if (s32)dst <= (s32)imm goto target)
            0xd6 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SLe,
                    right: Operand::Imm(insn.imm as i64),
                    target,
                }
            }

            // 0xdd: JSLE_X_64 (if (s64)dst <= (s64)src goto target)
            0xdd => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W64,
                    left: dst,
                    op: CmpOp::SLe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0xde: JSLE32_X (if (s32)dst <= (s32)src goto target)
            0xde => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst,
                    op: CmpOp::SLe,
                    right: Operand::Reg(src),
                    target,
                }
            }

            // 0x16: JEQ32 imm  if (u32)dst == (u32)imm goto target
            0x16 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::If {
                    width: Width::W32,
                    left: dst, // dst field is the left operand for jumps
                    op: CmpOp::Eq,
                    right: Operand::Imm((insn.imm as u32) as i64),
                    target,
                }
            }

            // 0x05: JA (unconditional jump): goto pc + 1 + off
            0x05 => {
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::Jmp { target }
            }

            // 0xe5: may_goto (v6.8) — BPF_JMP | BPF_JCOND | BPF_K.
            // Target = pc + 1 + off; src, dst, imm must be zero.
            0xe5 => {
                if insn.src != 0 || insn.dst != 0 || insn.imm != 0 {
                    return Err(LowerError {
                        pc,
                        code: insn.code,
                        msg: "may_goto requires src=0, dst=0, imm=0".to_string(),
                        kind: LowerErrorKind::UnknownOpcode,
                    });
                }
                let target = branch_target(pc, insn.off, raw.len(), insn.code)?;
                Instr::MayGoto { target }
            }

            // 0x06: gotol (v6.7) — BPF_JMP32 | BPF_JA | BPF_K.
            // Target = pc + 1 + imm (signed 32-bit displacement, in `imm`,
            // not `off`). `off` must be zero.
            0x06 => {
                if insn.off != 0 {
                    return Err(LowerError {
                        pc,
                        code: insn.code,
                        msg: format!("gotol requires off=0 (got {})", insn.off),
                        kind: LowerErrorKind::UnknownOpcode,
                    });
                }
                let target = branch_target_disp(pc, insn.imm, raw.len(), insn.code)?;
                Instr::Jmp { target }
            }

            // --- LD/LDX --- (minimal support for your current 0x61 case)

            // 0x61: LDXW dst = *(u32 *)(src + off)
            // In objdump: "w1 = *(u32 *)(r8 + 0x4c)"
            0x61 => Instr::Load {
                size: MemSize::U32,
                dst,
                base: src,
                off: insn.off,
            },

            // 0x69: LDXH dst = *(u16 *)(src + off)
            0x69 => Instr::Load {
                size: MemSize::U16,
                dst,
                base: src,
                off: insn.off,
            },

            // 0x71: LDXB dst = *(u8 *)(src + off)
            0x71 => Instr::Load {
                size: MemSize::U8,
                dst,
                base: src,
                off: insn.off,
            },

            // 0x79: LDXDW dst = *(u64 *)(src + off)
            0x79 => Instr::Load {
                size: MemSize::U64,
                dst,
                base: src,
                off: insn.off,
            },

            // --- LDSX (v6.6): BPF_LDX | BPF_MEMSX ---
            // 0x91: LDSXB  dst = (s64)*(s8  *)(src + off)
            0x91 => Instr::LoadSx {
                size: MemSize::U8,
                dst,
                base: src,
                off: insn.off,
            },
            // 0x89: LDSXH  dst = (s64)*(s16 *)(src + off)
            0x89 => Instr::LoadSx {
                size: MemSize::U16,
                dst,
                base: src,
                off: insn.off,
            },
            // 0x81: LDSXW  dst = (s64)*(s32 *)(src + off)
            0x81 => Instr::LoadSx {
                size: MemSize::U32,
                dst,
                base: src,
                off: insn.off,
            },

            // 0x62: BPF_ST | BPF_MEM | BPF_W ( *(u32 *)(dst + off) = imm )
            0x62 => Instr::Store {
                size: MemSize::U32,
                base: dst,
                off: insn.off,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x63: STXW *(u32 *)(dst + off) = src
            0x63 => Instr::Store {
                size: MemSize::U32,
                base: dst, // dst field is the base register for stores
                off: insn.off,
                src: Operand::Reg(src), // src field is the value register
            },

            // 0x6a: BPF_ST | BPF_MEM | BPF_H ( *(u16 *)(dst + off) = imm )
            0x6a => Instr::Store {
                size: MemSize::U16,
                base: dst,
                off: insn.off,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x6b: STXH *(u16 *)(dst + off) = src
            0x6b => Instr::Store {
                size: MemSize::U16,
                base: dst, // for stores, dst is the base register
                off: insn.off,
                src: Operand::Reg(src), // value comes from src register
            },

            // 0x72: BPF_ST | BPF_MEM | BPF_B ( *(u8 *)(dst + off) = imm )
            0x72 => Instr::Store {
                size: MemSize::U8,
                base: dst,
                off: insn.off,
                src: Operand::Imm(insn.imm as i64),
            },

            // 0x73: STXB *(u8 *)(dst + off) = src
            0x73 => Instr::Store {
                size: MemSize::U8,
                base: dst, // dst field is the base register for stores
                off: insn.off,
                src: Operand::Reg(src), // src field is the value register
            },

            // 0x7a: ST_MEM_DW ( *(u64 *)(dst + off) = imm32 )
            0x7a => Instr::Store {
                size: MemSize::U64,
                base: dst,                          // Base address register (e.g., r10)
                off: insn.off,                      // Offset (e.g., -8)
                src: Operand::Imm(insn.imm as i64), // The value to write (sign-extended to 64-bit)
            },

            // 0x7b: STXDW *(u64 *)(dst + off) = src
            0x7b => Instr::Store {
                size: MemSize::U64,
                base: dst,
                off: insn.off,
                src: Operand::Reg(src),
            },

            // 0x85: call imm (JMP | CALL)
            0x85 => {
                // off is a reserved field for helper calls and subprog calls,
                // but kfunc calls (src=2) repurpose off as the BTF module index.
                let off_reserved = insn.src != 2;
                if (off_reserved && insn.off != 0) || insn.dst != 0 {
                    return Err(LowerError {
                        pc,
                        code: insn.code,
                        // "BPF_CALL uses reserved fields" is the exact kernel error
                        msg: "BPF_CALL uses reserved fields".to_string(),
                        kind: LowerErrorKind::CallUsedReservedFields,
                    });
                }
                if src == Reg::R0 {
                    // Standard Helper Call (src_reg=0)
                    Instr::Call {
                        kind: CallKind::Helper {
                            id: insn.imm as u32,
                        },
                    }
                } else if src == Reg::R1 {
                    // BPF_PSEUDO_CALL (src_reg=1): BPF-to-BPF subprog call.
                    // imm is a 32-bit PC-relative offset
                    let next_pc = pc as i64 + 1;
                    let offset = insn.imm as i64;
                    let target = next_pc + offset;

                    // Verify bounds
                    if target < 0 || target >= raw.len() as i64 {
                        return Err(LowerError {
                            pc,
                            code: 0x85,
                            msg: "Call target out of bounds".to_string(),
                            kind: LowerErrorKind::CallTargetOutOfBounds,
                        });
                    }

                    Instr::CallRel {
                        target: target as usize,
                    }
                } else if src == Reg::R2 {
                    // BPF_PSEUDO_KFUNC_CALL (src_reg=2): kfunc dispatched via BTF id.
                    // imm = BTF id of the kfunc; off = index into BTF module table
                    // (0 = vmlinux). Transfer semantics are unimplemented today;
                    // the decoder only recognizes the shape.
                    Instr::Call {
                        kind: CallKind::Kfunc {
                            btf_id: insn.imm as u32,
                            offset: insn.off,
                        },
                    }
                } else {
                    return Err(LowerError {
                        pc,
                        code: 0x85,
                        msg: "Invalid src register for call".to_string(),
                        kind: LowerErrorKind::InvalidSrcReg,
                    });
                }
            }

            // BPF_STX | BPF_ATOMIC: 0xDB (DW), 0xC3 (W), plus 0xCB (H) and
            // 0xD3 (B) which v6.11 added for BPF_LOAD_ACQ / BPF_STORE_REL.
            // Historical atomic ops (ADD/OR/AND/XOR/XCHG/CMPXCHG) are only
            // defined for W and DW; B/H on those imm values is rejected.
            0xDB | 0xC3 | 0xCB | 0xD3 => {
                let size = match insn.code {
                    0xDB => MemSize::U64,
                    0xC3 => MemSize::U32,
                    0xCB => MemSize::U16,
                    0xD3 => MemSize::U8,
                    _ => unreachable!(),
                };

                // BPF_LOAD_ACQ (0x100) / BPF_STORE_REL (0x110), v6.11.
                // Acquire/release ordering does not affect the static-analysis
                // view of memory safety, but the kernel rejects BPF_ATOMIC
                // against ctx/pkt/flow_keys pointers — we use dedicated
                // variants so transfer can enforce that before delegating to
                // plain load/store semantics.
                // Register-role convention matches the kernel's BPF_ATOMIC
                // encoding: for LOAD_ACQ, dst is the destination register and
                // src is the address; for STORE_REL, dst is the address and
                // src is the value.
                if insn.imm == 0x100 {
                    Instr::LoadAcq {
                        size,
                        dst,
                        base: src,
                        off: insn.off,
                    }
                } else if insn.imm == 0x110 {
                    Instr::StoreRel {
                        size,
                        base: dst,
                        off: insn.off,
                        src,
                    }
                } else if matches!(insn.code, 0xCB | 0xD3) {
                    // Historical atomic RMW ops only support W / DW sizes.
                    return Err(LowerError {
                        pc,
                        code: insn.code,
                        msg: format!(
                            "unknown atomic opcode imm: 0x{:x} (B/H atomics are only defined for LOAD_ACQ/STORE_REL)",
                            insn.imm
                        ),
                        kind: LowerErrorKind::UnknownAtomicOp,
                    });
                } else {
                    // 1. Check for Complex Ops (XCHG, CMPXCHG)
                    // These specific values are hardcoded in the kernel spec.
                    let (op, fetch) = match insn.imm {
                        // BPF_ADD (0x00) with/without Fetch (0x01)
                        0x00 => (AtomicOp::Add, false),
                        0x01 => (AtomicOp::Add, true),

                        // BPF_OR (0x40)
                        0x40 => (AtomicOp::Or, false),
                        0x41 => (AtomicOp::Or, true),

                        // BPF_AND (0x50)
                        0x50 => (AtomicOp::And, false),
                        0x51 => (AtomicOp::And, true),

                        // BPF_XOR (0xA0)
                        0xA0 => (AtomicOp::Xor, false),
                        0xA1 => (AtomicOp::Xor, true),

                        // BPF_XCHG (0xE1) - Always implies Fetch
                        0xE1 => (AtomicOp::Xchg, true),

                        // BPF_CMPXCHG (0xF1) - Always implies Fetch
                        0xF1 => (AtomicOp::CmpXchg, true),

                        _ => {
                            return Err(LowerError {
                                pc,
                                code: insn.code,
                                msg: format!("unknown atomic opcode imm: 0x{:x}", insn.imm),
                                kind: LowerErrorKind::UnknownAtomicOp,
                            });
                        }
                    };

                    Instr::Atomic {
                        op,
                        size,
                        fetch,
                        base: dst, // In BPF STX, 'dst' is the memory pointer
                        off: insn.off,
                        src, // In BPF STX, 'src' is the value
                    }
                }
            }

            // --- LEGACY PACKET LOADS (LD_ABS) ---
            0x20 => Instr::LoadPacket {
                size: MemSize::U32,
                mode: PacketLoadMode::Abs,
                offset_imm: insn.imm,
                src: None,
            },
            0x28 => Instr::LoadPacket {
                size: MemSize::U16,
                mode: PacketLoadMode::Abs,
                offset_imm: insn.imm,
                src: None,
            },
            0x30 => Instr::LoadPacket {
                size: MemSize::U8,
                mode: PacketLoadMode::Abs,
                offset_imm: insn.imm,
                src: None,
            },

            // --- LEGACY PACKET LOADS (LD_IND) ---
            0x40 => Instr::LoadPacket {
                size: MemSize::U32,
                mode: PacketLoadMode::Ind,
                offset_imm: insn.imm,
                src: Some(src),
            },
            0x48 => Instr::LoadPacket {
                size: MemSize::U16,
                mode: PacketLoadMode::Ind,
                offset_imm: insn.imm,
                src: Some(src),
            },
            0x50 => Instr::LoadPacket {
                size: MemSize::U8,
                mode: PacketLoadMode::Ind,
                offset_imm: insn.imm,
                src: Some(src),
            },

            // Guard against stray continuation opcodes outside 0x18
            0x00 => {
                return Err(LowerError {
                    pc,
                    code: insn.code,
                    msg: "unexpected opcode 0x00 (LDIMM64 continuation without prefix?)"
                        .to_string(),
                    kind: LowerErrorKind::InvalidLDIMM64,
                });
            }

            other => {
                return Err(LowerError {
                    pc,
                    code: other,
                    msg: format!("unsupported opcode 0x{:02x} at pc {}", other, pc),
                    kind: LowerErrorKind::UnknownOpcode,
                });
            }
        };

        instrs.push(ir);
        pc += 1;
    }

    Ok(Program {
        instrs,
        invalid_pc_set,
        addr_space_cast_to_arena_pcs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a 2-slot LD_IMM64 insn pair with the given src_reg and imm.
    fn ld_imm64(src: u8, imm_lo: i32, imm_hi: i32) -> Vec<RawBpfInsn> {
        vec![
            RawBpfInsn {
                code: 0x18,
                dst: 0,
                src,
                off: 0,
                imm: imm_lo,
            },
            RawBpfInsn {
                code: 0x00,
                dst: 0,
                src: 0,
                off: 0,
                imm: imm_hi,
            },
        ]
    }

    fn exit() -> RawBpfInsn {
        RawBpfInsn {
            code: 0x95,
            dst: 0,
            src: 0,
            off: 0,
            imm: 0,
        }
    }

    #[test]
    fn decodes_helper_call() {
        let raw = vec![
            RawBpfInsn {
                code: 0x85,
                dst: 0,
                src: 0,
                off: 0,
                imm: 1,
            },
            exit(),
        ];
        let prog = lower_raw_to_program(&raw).unwrap();
        assert_eq!(
            prog.instrs[0],
            Instr::Call {
                kind: CallKind::Helper { id: 1 }
            }
        );
    }

    #[test]
    fn decodes_kfunc_call() {
        // src=2 → BPF_PSEUDO_KFUNC_CALL; imm = btf_id, off = module index
        let raw = vec![
            RawBpfInsn {
                code: 0x85,
                dst: 0,
                src: 2,
                off: 3,
                imm: 42,
            },
            exit(),
        ];
        let prog = lower_raw_to_program(&raw).unwrap();
        assert_eq!(
            prog.instrs[0],
            Instr::Call {
                kind: CallKind::Kfunc {
                    btf_id: 42,
                    offset: 3
                }
            }
        );
    }

    #[test]
    fn decodes_pseudo_btf_id() {
        // src=3 → BPF_PSEUDO_BTF_ID
        let mut raw = ld_imm64(3, 99, 0);
        raw.push(exit());
        let prog = lower_raw_to_program(&raw).unwrap();
        assert!(matches!(
            prog.instrs[0],
            Instr::LoadMap {
                kind: MapLoadKind::PseudoBtfId { btf_id: 99 },
                ..
            }
        ));
    }

    #[test]
    fn decodes_pseudo_func() {
        // src=4 → BPF_PSEUDO_FUNC; imm is PC-relative offset to subprog.
        // pc=0, LD_IMM64 is 2 slots, so next_pc=2. imm=1 → target=3.
        // Need at least 4 insns to keep target in-bounds.
        let mut raw = ld_imm64(4, 1, 0);
        raw.push(exit()); // pc=2
        raw.push(exit()); // pc=3 (the "subprog" target)
        let prog = lower_raw_to_program(&raw).unwrap();
        assert!(matches!(
            prog.instrs[0],
            Instr::LoadMap {
                kind: MapLoadKind::PseudoFunc { subprog_pc: 3 },
                ..
            }
        ));
    }

    #[test]
    fn decodes_pseudo_map_idx() {
        let mut raw = ld_imm64(5, 7, 0);
        raw.push(exit());
        let prog = lower_raw_to_program(&raw).unwrap();
        assert!(matches!(
            prog.instrs[0],
            Instr::LoadMap {
                kind: MapLoadKind::PseudoMapIdx,
                map_fd: 7,
                ..
            }
        ));
    }

    #[test]
    fn decodes_pseudo_map_idx_value() {
        let mut raw = ld_imm64(6, 11, 0);
        raw.push(exit());
        let prog = lower_raw_to_program(&raw).unwrap();
        assert!(matches!(
            prog.instrs[0],
            Instr::LoadMap {
                kind: MapLoadKind::PseudoMapIdxValue,
                map_fd: 11,
                ..
            }
        ));
    }
}

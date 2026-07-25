use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;

/// Top-level PCC certificate container for the prototype pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramCertificate {
    pub version: u32,
    pub program_hash: String,
    #[serde(default)]
    pub pc_annotations: Vec<PcAnnotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcAnnotation {
    pub pc: usize,
    pub entries: Vec<AnnotationEntry>,
}

/// A single annotation at a load instruction.
///
/// Claims that `left_reg - right_reg <= bound` holds in the pre-state of the annotated
/// instruction, and carries a proof chain ([`ProofStep`]) that the interval checker
/// can replay to independently verify the claim.
///
/// The constraint follows DBM convention: a negative `bound` means the left register
/// is at least `|bound|` units below the right register. For packet-safety annotations,
/// `right_reg` is always `@data_end` (index 14) and `bound <= -(offset + access_size)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnnotationEntry {
    pub left_reg: usize,
    pub right_reg: usize,
    pub bound: i64,
    pub proof: Vec<ProofStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ProofStep {
    /// Base fact: the interval state at `pc` proves `left_reg - right_reg <= c`,
    /// either directly from the abstract state or from a branch condition visible
    /// to the interval verifier. Always the first step in a proof chain.
    #[serde(rename = "Fact")]
    Fact {
        pc: usize,
        left_reg: usize,
        right_reg: usize,
        c: i64,
    },
    /// Register aliasing step: instructions from `pc_start` to `pc_end` establish
    /// that `source_reg = target_reg + offset`.
    ///
    /// This allows the proof chain to "switch" which register it tracks:
    /// if the preceding Guard proved `source_reg <= c`, then after Derive
    /// we know `target_reg <= c - offset`.
    ///
    /// The checker verifies by replaying the instructions `pc_start..=pc_end` and
    /// confirming they establish the claimed constant relationship.
    #[serde(rename = "Derive")]
    Derive {
        pc_start: usize,
        pc_end: usize,
        /// The register constrained by the preceding Guard.
        source_reg: usize,
        /// The register we need a bound on (used by a later Transfer).
        target_reg: usize,
        /// The constant offset: source_reg = target_reg + offset.
        offset: i64,
    },
    /// Transitive composition: combines two sub-proofs through an intermediate
    /// register to establish a bound that neither sub-proof can prove alone.
    ///
    /// If `left` proves `L - K ≤ a` and `right` proves `K - R ≤ b`, then
    /// `Compose` proves `L - R ≤ a + b` via the intermediate index `K = via`.
    ///
    /// Sub-proofs are themselves valid proof chains (`[Fact, Derive*, Transfer+]`)
    /// or nested Compose nodes.
    #[serde(rename = "Compose")]
    Compose {
        left: Vec<ProofStep>,
        right: Vec<ProofStep>,
        /// Intermediate register index K that connects left and right sub-proofs.
        via: usize,
    },
    /// Inductive step: the instruction at `pc` transforms the pre-state constraint
    /// `pre_left_reg - pre_right_reg <= b` into the post-state constraint
    /// `post_left_reg - post_right_reg <= b + delta`.
    ///
    /// The claimed `delta` is sound only for specific instruction shapes. Let
    /// `L = pre_left_reg` and `R = pre_right_reg`. The algebraic derivations are:
    ///
    /// | Instruction          | Condition   | Derivation                                                          | Required `delta`    |
    /// |----------------------|-------------|---------------------------------------------------------------------|---------------------|
    /// | `add dst, imm`       | `dst == L`  | `(L+imm) - R = (L-R) + imm <= b + imm`                              | exactly `imm`       |
    /// | `add dst, imm`       | `dst == R`  | `L - (R+imm) = (L-R) - imm <= b - imm`                              | exactly `-imm`      |
    /// | `add dst, src`       | `dst == L`  | `(L+src) - R <= b + ub(src)` since `src <= ub(src)`                 | `>= ub(src)`        |
    /// | `add dst, src`       | `dst == R`  | `L - (R+src) = (L-R) - src <= b - lb(src)` since `src >= lb(src)`   | `>= -lb(src)`       |
    /// | `mov dst, src`       | `src == L`  | value copied; track in `dst`: `post_left = dst`, bound unchanged    | exactly 0           |
    /// | passthrough          | `dst` ∉ {L,R} | constraint registers untouched                                    | exactly 0           |
    ///
    /// Here `ub(src)` and `lb(src)` are the interval upper/lower bounds of `src`
    /// read from the interval pre-state at `pc`.
    ///
    /// The optional `hint` is a human-readable description of the instruction and why
    /// it causes `delta` to be what it is (e.g. `"r5 += r4  (r4 <= 3)"`).
    /// It carries no semantic weight — the checker ignores it — but makes the proof
    /// chain much easier to read.
    #[serde(rename = "Transfer")]
    Transfer {
        pc: usize,
        pre_left_reg: usize,
        pre_right_reg: usize,
        post_left_reg: usize,
        post_right_reg: usize,
        delta: i64,
        /// Human-readable explanation of why `delta` is what it is.
        /// Informational only; omitted from JSON when absent.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        hint: Option<String>,
    },
}

impl ProofStep {
    /// The PC this step refers to.
    pub fn pc(&self) -> usize {
        match self {
            ProofStep::Fact { pc, .. } | ProofStep::Transfer { pc, .. } => *pc,
            ProofStep::Derive { pc_end, .. } => *pc_end,
            ProofStep::Compose { left, right, .. } => {
                // Return the max PC across both sub-proofs.
                let l = left.last().map_or(0, |s| s.pc());
                let r = right.last().map_or(0, |s| s.pc());
                l.max(r)
            }
        }
    }

    /// The output left register index after this step.
    /// Fact: `left_reg`; Transfer: `post_left_reg`; Derive: `target_reg`;
    /// Compose: left sub-proof's output left register.
    pub fn output_left_reg(&self) -> usize {
        match self {
            ProofStep::Fact { left_reg, .. } => *left_reg,
            ProofStep::Transfer { post_left_reg, .. } => *post_left_reg,
            ProofStep::Derive { target_reg, .. } => *target_reg,
            ProofStep::Compose { left, .. } => left.last().map_or(0, |s| s.output_left_reg()),
        }
    }

    /// The output right register index after this step.
    /// Fact: `right_reg`; Transfer: `post_right_reg`; Derive: `0` (Zero);
    /// Compose: right sub-proof's output right register.
    pub fn output_right_reg(&self) -> usize {
        match self {
            ProofStep::Fact { right_reg, .. } => *right_reg,
            ProofStep::Transfer { post_right_reg, .. } => *post_right_reg,
            ProofStep::Derive { .. } => 0, // Derive switches to target_reg - Zero
            ProofStep::Compose { right, .. } => right.last().map_or(0, |s| s.output_right_reg()),
        }
    }

    /// The bound contribution of this step.
    /// Fact: `c`; Transfer: `delta`; Derive: `-offset`;
    /// Compose: sum of all bound contributions across both sub-proofs.
    pub fn bound_contribution(&self) -> i64 {
        match self {
            ProofStep::Fact { c, .. } => *c,
            ProofStep::Transfer { delta, .. } => *delta,
            ProofStep::Derive { offset, .. } => -*offset,
            ProofStep::Compose { left, right, .. } => {
                let left_sum: i64 = left.iter().map(|s| s.bound_contribution()).sum();
                let right_sum: i64 = right.iter().map(|s| s.bound_contribution()).sum();
                left_sum + right_sum
            }
        }
    }

    /// Total number of nodes in the proof step tree, counting recursively
    /// into Compose sub-proofs. Used for enforcing MAX_STEPS_PER_ENTRY.
    pub fn node_count(&self) -> usize {
        match self {
            ProofStep::Fact { .. } | ProofStep::Transfer { .. } | ProofStep::Derive { .. } => 1,
            ProofStep::Compose { left, right, .. } => {
                1 + left.iter().map(|s| s.node_count()).sum::<usize>()
                    + right.iter().map(|s| s.node_count()).sum::<usize>()
            }
        }
    }
}

/// Maximum proof steps allowed per annotation entry.
/// Shared between the validator and checker to ensure they agree.
pub const MAX_STEPS_PER_ENTRY: usize = 32;

/// Maximum annotation entries allowed per PC.
///
/// This is a **defensive cap** on the checker side, not a reflection of what the
/// generator currently produces. The generator emits at most one entry per PC
/// (one constraint per load instruction). The cap exists to bound the work an
/// adversarial certificate could force the checker to perform.
pub const MAX_ENTRIES_PER_PC: usize = 8;

/// Overflow-safe sum of step bounds.
#[allow(dead_code)]
pub fn checked_sum(weights: impl Iterator<Item = i64>) -> Option<i64> {
    let mut sum = 0i64;
    for w in weights {
        sum = sum.checked_add(w)?;
    }
    Some(sum)
}

impl ProgramCertificate {
    /// Prototype certificate schema version.
    pub const VERSION: u32 = 3;

    #[allow(dead_code)]
    pub fn empty(program_hash: String) -> Self {
        Self {
            version: Self::VERSION,
            program_hash,
            pc_annotations: Vec::new(),
        }
    }

    pub fn load_from_path(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read certificate file '{}'", path))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse certificate JSON '{}'", path))
    }

    #[allow(dead_code)]
    pub fn save_to_path(&self, path: &str) -> Result<()> {
        let raw =
            serde_json::to_string_pretty(self).context("failed to serialize certificate JSON")?;
        fs::write(path, raw).with_context(|| format!("failed to write certificate file '{}'", path))
    }
}

// ---------------------------------------------------------------------------
// Human-readable display
// ---------------------------------------------------------------------------

/// Maps a register index to its canonical name.
/// Mirrors `Reg::name()` without importing the analysis crate to avoid cycles.
fn reg_name(idx: usize) -> &'static str {
    match idx {
        0 => "0",
        1 => "r0",
        2 => "r1",
        3 => "r2",
        4 => "r3",
        5 => "r4",
        6 => "r5",
        7 => "r6",
        8 => "r7",
        9 => "r8",
        10 => "r9",
        11 => "r10",
        12 => "@data_meta",
        13 => "@data",
        14 => "@data_end",
        _ => "?",
    }
}

/// Recursively display proof steps with indentation.
/// Returns the running bound sum across all displayed steps.
fn display_proof_steps(
    f: &mut fmt::Formatter<'_>,
    steps: &[ProofStep],
    indent: usize,
) -> fmt::Result {
    let pad = " ".repeat(indent);
    let mut running: i64 = 0;
    for (si, step) in steps.iter().enumerate() {
        match step {
            ProofStep::Fact {
                pc,
                left_reg,
                right_reg,
                c,
            } => {
                running += c;
                writeln!(
                    f,
                    "{pad}[{si}] Fact     @ pc {:>3}:  {} - {} <= {}",
                    pc,
                    reg_name(*left_reg),
                    reg_name(*right_reg),
                    c,
                )?;
            }
            ProofStep::Derive {
                pc_start,
                pc_end,
                source_reg,
                target_reg,
                offset,
            } => {
                running -= offset;
                writeln!(
                    f,
                    "{pad}[{si}] Derive   @ pc {}→{}:  {} = {} + {}   =>  {} <= {}",
                    pc_start,
                    pc_end,
                    reg_name(*source_reg),
                    reg_name(*target_reg),
                    offset,
                    reg_name(*target_reg),
                    running,
                )?;
            }
            ProofStep::Compose { left, right, via } => {
                let left_bound: i64 = left.iter().map(|s| s.bound_contribution()).sum();
                let right_bound: i64 = right.iter().map(|s| s.bound_contribution()).sum();
                let composed = left_bound + right_bound;
                running += composed;
                writeln!(
                    f,
                    "{pad}[{si}] Compose  via {}:  {} + {} = {}",
                    reg_name(*via),
                    left_bound,
                    right_bound,
                    composed,
                )?;
                writeln!(f, "{pad}  left:")?;
                display_proof_steps(f, left, indent + 4)?;
                writeln!(f, "{pad}  right:")?;
                display_proof_steps(f, right, indent + 4)?;
            }
            ProofStep::Transfer {
                pc,
                pre_left_reg,
                pre_right_reg,
                post_left_reg,
                post_right_reg,
                delta,
                hint,
            } => {
                let prev_running = running;
                running += delta;

                let constraint_str =
                    if pre_left_reg != post_left_reg || pre_right_reg != post_right_reg {
                        format!(
                            "{}-{}  ->  {}-{}",
                            reg_name(*pre_left_reg),
                            reg_name(*pre_right_reg),
                            reg_name(*post_left_reg),
                            reg_name(*post_right_reg),
                        )
                    } else {
                        format!("{}-{}", reg_name(*pre_left_reg), reg_name(*pre_right_reg),)
                    };
                let desc = if let Some(h) = hint {
                    h.clone()
                } else if *delta != 0 {
                    format!("{}  delta={:+}", constraint_str, delta)
                } else {
                    format!("{}  [passthrough]", constraint_str)
                };

                let arith = if *delta == 0 {
                    format!("bound: {} (unchanged)", prev_running)
                } else {
                    let sign = if *delta >= 0 { "+" } else { "-" };
                    format!(
                        "bound: {} {} {} = {}",
                        prev_running,
                        sign,
                        delta.abs(),
                        running,
                    )
                };

                writeln!(
                    f,
                    "{pad}[{si}] Transfer @ pc {:>3}:  {}   =>  {}",
                    pc, desc, arith,
                )?;
            }
        }
    }
    Ok(())
}

impl fmt::Display for ProgramCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Certificate v{}  |  hash: {}  |  {} annotated PC(s)",
            self.version,
            self.program_hash,
            self.pc_annotations.len()
        )?;

        for ann in &self.pc_annotations {
            writeln!(f)?;
            writeln!(
                f,
                "  pc {:>4}:  {} constraint(s)",
                ann.pc,
                ann.entries.len()
            )?;

            for (ei, entry) in ann.entries.iter().enumerate() {
                let lname = reg_name(entry.left_reg);
                let rname = reg_name(entry.right_reg);
                writeln!(
                    f,
                    "    [entry {}]  {} - {} <= {}   ({} proof step(s))",
                    ei,
                    lname,
                    rname,
                    entry.bound,
                    entry.proof.len(),
                )?;

                display_proof_steps(f, &entry.proof, 6)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_step_fact_json_round_trip() {
        let step = ProofStep::Fact {
            pc: 5,
            left_reg: 6,
            right_reg: 14,
            c: -8,
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"kind\":\"Fact\""));
        assert!(json.contains("\"pc\":5"));
        let back: ProofStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    #[test]
    fn proof_step_fact_accessors() {
        let fact = ProofStep::Fact {
            pc: 5,
            left_reg: 6,
            right_reg: 14,
            c: -8,
        };
        assert_eq!(fact.pc(), 5);
        assert_eq!(fact.output_left_reg(), 6);
        assert_eq!(fact.output_right_reg(), 14);
        assert_eq!(fact.bound_contribution(), -8);
    }

    #[test]
    fn proof_step_transfer_json_round_trip() {
        let step = ProofStep::Transfer {
            pc: 9,
            pre_left_reg: 6,
            pre_right_reg: 14,
            post_left_reg: 6,
            post_right_reg: 14,
            delta: 3,
            hint: None,
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"kind\":\"Transfer\""));
        assert!(json.contains("\"pre_left_reg\":6"));
        assert!(json.contains("\"delta\":3"));
        let back: ProofStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    #[test]
    fn certificate_v3_round_trip() {
        let cert = ProgramCertificate {
            version: 3,
            program_hash: "abc123".to_string(),
            pc_annotations: vec![PcAnnotation {
                pc: 10,
                entries: vec![AnnotationEntry {
                    left_reg: 6,
                    right_reg: 14,
                    bound: -5,
                    proof: vec![
                        ProofStep::Fact {
                            pc: 5,
                            left_reg: 6,
                            right_reg: 14,
                            c: -8,
                        },
                        ProofStep::Transfer {
                            pc: 9,
                            pre_left_reg: 6,
                            pre_right_reg: 14,
                            post_left_reg: 6,
                            post_right_reg: 14,
                            delta: 3,
                            hint: None,
                        },
                    ],
                }],
            }],
        };
        let json = serde_json::to_string_pretty(&cert).unwrap();
        let back: ProgramCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    #[test]
    fn proof_step_transfer_accessors() {
        let transfer = ProofStep::Transfer {
            pc: 9,
            pre_left_reg: 5,
            pre_right_reg: 14,
            post_left_reg: 6,
            post_right_reg: 14,
            delta: 3,
            hint: None,
        };
        assert_eq!(transfer.pc(), 9);
        assert_eq!(transfer.output_left_reg(), 6);
        assert_eq!(transfer.output_right_reg(), 14);
        assert_eq!(transfer.bound_contribution(), 3);
    }

    #[test]
    fn proof_step_compose_json_round_trip() {
        let step = ProofStep::Compose {
            left: vec![ProofStep::Fact {
                pc: 7,
                left_reg: 5,
                right_reg: 2,
                c: 3,
            }],
            right: vec![ProofStep::Fact {
                pc: 4,
                left_reg: 2,
                right_reg: 14,
                c: -8,
            }],
            via: 2,
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("\"kind\":\"Compose\""));
        assert!(json.contains("\"via\":2"));
        let back: ProofStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    #[test]
    fn proof_step_compose_accessors() {
        // left proves r4 - r1 ≤ 3, right proves r1 - @end ≤ -8
        let compose = ProofStep::Compose {
            left: vec![ProofStep::Fact {
                pc: 7,
                left_reg: 5,  // r4
                right_reg: 2, // r1
                c: 3,
            }],
            right: vec![ProofStep::Fact {
                pc: 4,
                left_reg: 2,   // r1
                right_reg: 14, // @data_end
                c: -8,
            }],
            via: 2, // r1
        };
        assert_eq!(compose.pc(), 7); // max of sub-proof PCs
        assert_eq!(compose.output_left_reg(), 5); // r4 from left
        assert_eq!(compose.output_right_reg(), 14); // @data_end from right
        assert_eq!(compose.bound_contribution(), -5); // 3 + (-8)
        assert_eq!(compose.node_count(), 3); // 1 Compose + 1 Fact + 1 Fact
    }

    #[test]
    fn certificate_with_compose_round_trip() {
        let cert = ProgramCertificate {
            version: 3,
            program_hash: "def456".to_string(),
            pc_annotations: vec![PcAnnotation {
                pc: 8,
                entries: vec![AnnotationEntry {
                    left_reg: 5,
                    right_reg: 14,
                    bound: -5,
                    proof: vec![ProofStep::Compose {
                        left: vec![
                            ProofStep::Fact {
                                pc: 7,
                                left_reg: 5,
                                right_reg: 2,
                                c: 3,
                            },
                            ProofStep::Transfer {
                                pc: 7,
                                pre_left_reg: 5,
                                pre_right_reg: 2,
                                post_left_reg: 5,
                                post_right_reg: 2,
                                delta: 0,
                                hint: None,
                            },
                        ],
                        right: vec![ProofStep::Fact {
                            pc: 4,
                            left_reg: 2,
                            right_reg: 14,
                            c: -8,
                        }],
                        via: 2,
                    }],
                }],
            }],
        };
        let json = serde_json::to_string_pretty(&cert).unwrap();
        let back: ProgramCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }
}

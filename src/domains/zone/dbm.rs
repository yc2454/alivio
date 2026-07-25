// src/dbm.rs
use crate::analysis::machine::reg::{REG_ENV, Reg};

pub const INF: i64 = i64::MAX / 4;

// ══════════════════════════════════════════════════════════════════════════════
//  Provenance tracking for PCC certificate generation
// ══════════════════════════════════════════════════════════════════════════════

/// Tracks how a DBM cell got its current value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeOrigin {
    /// Default: diagonal (0) or unconstrained (INF).
    Init,
    /// Set directly by `add_constraint` at the given program counter.
    Primitive { pc: usize },
    /// Derived by Floyd-Warshall transitive closure through intermediate index `via`.
    Derived { via: usize },
}

/// Shadow matrix that records provenance for each DBM cell.
/// Only allocated when PCC certificate generation is active.
#[derive(Debug, Clone)]
pub struct ProvenanceTracker {
    edges: Vec<Vec<EdgeOrigin>>,
    current_pc: usize,
}

impl ProvenanceTracker {
    fn new(n: usize) -> Self {
        Self {
            edges: vec![vec![EdgeOrigin::Init; n]; n],
            current_pc: 0,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn get(&self, i: usize, j: usize) -> EdgeOrigin {
        self.edges[i][j]
    }
}

// Bounds for finite constraints inside the DBM.
// We never store anything > POS_BOUND or < NEG_BOUND.
const POS_BOUND: i64 = INF / 2;
const NEG_BOUND: i64 = -POS_BOUND;

#[inline]
pub fn clamp_upper_bound(c: i64) -> i64 {
    // We represent "no constraint" as INF.
    // For x - y <= c with huge positive c, we can treat it as no constraint.
    if c > POS_BOUND {
        INF
    } else if c < NEG_BOUND {
        // Very strong negative bound; weaken to NEG_BOUND
        NEG_BOUND
    } else {
        c
    }
}

#[inline]
pub fn clamped_add(a: i64, b: i64) -> i64 {
    // Safe addition for Floyd–Warshall.
    // If either side is INF, or the sum overflows, treat as INF (no useful bound).
    if a >= INF || b >= INF {
        return INF;
    }
    match a.checked_add(b) {
        Some(sum) => clamp_upper_bound(sum),
        None => INF,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_can_be_enabled_for_path_reconstruction() {
        let mut dbm = Dbm::new();
        dbm.enable_provenance();
        dbm.set_current_pc(42);
        dbm.add_constraint(Reg::R2, Reg::R3, 5);
        dbm.close();

        let path = dbm
            .reconstruct_path(Reg::R2, Reg::R3)
            .expect("provenance should be active");
        assert_eq!(path.len(), 1);
        let edge = &path[0];
        assert_eq!(edge.to, Reg::R2);
        assert_eq!(edge.from, Reg::R3);
        assert_eq!(edge.weight, 5);
        assert_eq!(edge.pc, 42);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub s32_min: i32,
    pub s32_max: i32,
    pub u32_min: u32,
    pub u32_max: u32,
    pub s64_min: i64,
    pub s64_max: i64,
    pub u64_min: u64,
    pub u64_max: u64,
}

impl Bounds {
    pub fn unknown() -> Self {
        Self {
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
            s64_min: i64::MIN,
            s64_max: i64::MAX,
            u64_min: 0,
            u64_max: u64::MAX,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dbm {
    pub data: Vec<Vec<i64>>,
    pub bounds: Vec<Bounds>,
    /// Shadow provenance matrix — None when PCC is not active, zero overhead.
    provenance: Option<Box<ProvenanceTracker>>,
}

impl Dbm {
    pub fn new() -> Self {
        let n = Reg::DBM_DIM;
        let mut data = vec![vec![INF; n]; n];
        for (i, row) in data.iter_mut().enumerate() {
            row[i] = 0;
        }
        Self {
            data,
            bounds: vec![Bounds::unknown(); n],
            provenance: None,
        }
    }

    /// Activates provenance tracking. Call once before analysis when PCC generation is needed.
    pub fn enable_provenance(&mut self) {
        let n = self.num_vars();
        self.provenance = Some(Box::new(ProvenanceTracker::new(n)));
    }

    /// Sets the current program counter for provenance attribution.
    /// Call before each instruction's transfer function.
    #[inline]
    pub fn set_current_pc(&mut self, pc: usize) {
        if let Some(prov) = &mut self.provenance {
            prov.current_pc = pc;
        }
    }

    /// Returns a reference to the provenance tracker, if active.
    #[allow(dead_code)]
    pub fn provenance(&self) -> Option<&ProvenanceTracker> {
        self.provenance.as_deref()
    }

    pub fn num_vars(&self) -> usize {
        self.data.len()
    }

    pub fn dim(&self) -> usize {
        self.data.len()
    }

    pub fn raw(&self, i: usize, j: usize) -> i64 {
        self.data[i][j]
    }

    // low-level idx ops if you need them
    pub fn get_idx(&self, i: usize, j: usize) -> i64 {
        self.data[i][j]
    }

    pub fn set_idx(&mut self, i: usize, j: usize, val: i64) {
        self.data[i][j] = val;
    }

    // Var-level helpers
    #[inline]
    pub fn get(&self, i: Reg, j: Reg) -> i64 {
        self.data[i.idx()][j.idx()]
    }

    #[inline]
    pub fn set(&mut self, i: Reg, j: Reg, val: i64) {
        self.data[i.idx()][j.idx()] = val;
    }

    /// Stamps all finite edges involving `reg_idx` with `Primitive{pc: current_pc}`.
    /// Called after `set_idx` shifts in `apply_add_reg` to keep provenance
    /// consistent with the shifted constraint values.
    pub fn stamp_provenance_for_var(&mut self, reg_idx: usize) {
        // Detach provenance to avoid borrow conflict with self.data
        let mut prov = self.provenance.take();
        if let Some(p) = &mut prov {
            let n = self.data.len();
            for j in 0..n {
                if self.data[reg_idx][j] < INF && reg_idx != j {
                    p.edges[reg_idx][j] = EdgeOrigin::Primitive { pc: p.current_pc };
                }
                if self.data[j][reg_idx] < INF && reg_idx != j {
                    p.edges[j][reg_idx] = EdgeOrigin::Primitive { pc: p.current_pc };
                }
            }
        }
        self.provenance = prov;
    }

    pub fn add_constraint(&mut self, i: Reg, j: Reg, c: i64) {
        // Constraint: i - j <= c
        let c = clamp_upper_bound(c);
        let old = self.get(i, j);

        // If c becomes INF, it's "no constraint". Only tighten if we had a finite bound before.
        if c == INF {
            return;
        }
        if c < old {
            self.set(i, j, c);
            if let Some(prov) = &mut self.provenance {
                prov.edges[i.idx()][j.idx()] = EdgeOrigin::Primitive {
                    pc: prov.current_pc,
                };
            }
        }
    }

    pub fn forget_var(&mut self, x: Reg) {
        debug_assert!(!x.is_anchor(), "BUG: cannot forget anchor {:?}", x);
        let i = x.idx();
        let n = self.num_vars();
        for j in 0..n {
            if i == j {
                self.data[i][j] = 0;
            } else {
                self.data[i][j] = INF;
            }
        }
        for k in 0..n {
            if k == i {
                self.data[k][i] = 0;
            } else {
                self.data[k][i] = INF;
            }
        }
        self.bounds[i] = Bounds::unknown();
        if let Some(prov) = &mut self.provenance {
            for j in 0..n {
                prov.edges[i][j] = EdgeOrigin::Init;
                prov.edges[j][i] = EdgeOrigin::Init;
            }
        }
    }

    pub fn close(&mut self) {
        let n = self.num_vars();
        // Detach provenance to avoid borrow conflict with self.data
        let mut prov = self.provenance.take();
        for k in 0..n {
            for i in 0..n {
                let dik = self.data[i][k];
                if dik >= INF {
                    continue;
                }
                for j in 0..n {
                    let dkj = self.data[k][j];
                    if dkj >= INF {
                        continue;
                    }

                    let via = clamped_add(dik, dkj);
                    if via < self.data[i][j] {
                        self.data[i][j] = via;
                        if let Some(p) = &mut prov {
                            p.edges[i][j] = EdgeOrigin::Derived { via: k };
                        }
                    }
                }
            }
        }
        self.provenance = prov;
    }

    pub fn is_inconsistent(&self) -> bool {
        for i in 0..self.num_vars() {
            if self.data[i][i] < 0 {
                return true;
            }
        }
        // Empty 32/64-bit shadow ranges are also infeasible. They arise
        // from jmp32 narrowing (`apply_w32_*_fallback`) where the
        // 32-bit bounds get tightened past each other; the DBM
        // diagonal stays >= 0 because relational entries are unchanged.
        for b in &self.bounds {
            if b.s32_min > b.s32_max
                || b.u32_min > b.u32_max
                || b.s64_min > b.s64_max
                || b.u64_min > b.u64_max
            {
                return true;
            }
        }
        false
    }

    /// Returns the DBM as a formatted matrix string (real registers only, no anchors).
    /// The caller is responsible for logging the result at the desired level.
    #[allow(dead_code)]
    pub fn matrix_str(&self) -> String {
        use std::fmt::Write;
        let vars = REG_ENV.all();
        let n = vars.len();

        let mut output = String::new();
        writeln!(output, "DBM [{} x {}]:", n, n).unwrap();

        write!(output, "{:>8} ", "").unwrap();
        for v in vars {
            write!(output, "{:>12} ", v.name()).unwrap();
        }
        writeln!(output).unwrap();

        for (row_idx, vi) in vars.iter().enumerate() {
            write!(output, "{:>8} ", vi.name()).unwrap();
            for col_idx in 0..n {
                let v = self.data[row_idx][col_idx];
                if v >= INF {
                    write!(output, "{:>12} ", "INF").unwrap();
                } else {
                    write!(output, "{:>12} ", v).unwrap();
                }
            }
            writeln!(output).unwrap();
        }

        output
    }

    /// Returns the full DBM as a formatted matrix string (all registers including anchors).
    /// The caller is responsible for logging the result at the desired level.
    pub fn matrix_full_str(&self) -> String {
        use std::fmt::Write;
        let n = self.num_vars();
        let mut output = String::new();
        writeln!(output, "DBM [{} x {}] (full, with anchors):", n, n).unwrap();

        write!(output, "{:>12} ", "").unwrap();
        for j in 0..n {
            let name = Reg::idx_to_reg(j).map(|r| r.name()).unwrap_or("???");
            write!(output, "{:>12} ", name).unwrap();
        }
        writeln!(output).unwrap();

        for i in 0..n {
            let name = Reg::idx_to_reg(i).map(|r| r.name()).unwrap_or("???");
            write!(output, "{:>12} ", name).unwrap();
            for j in 0..n {
                let v = self.data[i][j];
                if v >= INF {
                    write!(output, "{:>12} ", "INF").unwrap();
                } else {
                    write!(output, "{:>12} ", v).unwrap();
                }
            }
            writeln!(output).unwrap();
        }

        output
    }

    /// Returns a compact, single-line string of non-trivial relational constraints
    /// suitable for embedding in a log line.
    ///
    /// Only register-register and register-anchor pairs are shown (pairs involving
    /// `Zero` encode absolute bounds and are already covered by the Ranges section).
    /// Each unique unordered pair `{ri, rj}` is emitted once (ri.idx() < rj.idx()),
    /// so symmetric entries are collapsed:
    ///
    ///   `ri-rj=={k}`          when both sides pin to the same value
    ///   `ri-rj in [lo,hi]`    when both sides are finite
    ///   `ri-rj<={hi}`         upper bound only
    ///   `ri-rj>={lo}`         lower bound only
    pub fn relations_str(&self) -> String {
        let n = self.dim();

        // Collect all non-Zero registers in index order (real regs + anchors).
        let regs: Vec<Reg> = (0..n)
            .filter_map(Reg::idx_to_reg)
            .filter(|r| *r != Reg::Zero)
            .collect();

        let mut parts: Vec<String> = Vec::new();

        for (a, &ri) in regs.iter().enumerate() {
            for &rj in &regs[a + 1..] {
                // c_ij: ri - rj <= c_ij
                // c_ji: rj - ri <= c_ji  (=> ri - rj >= -c_ji)
                let c_ij = self.get(ri, rj);
                let c_ji = self.get(rj, ri);

                if c_ij >= INF && c_ji >= INF {
                    continue; // no constraint between this pair
                }

                let hi = if c_ij >= INF { None } else { Some(c_ij) };
                let lo = if c_ji >= INF { None } else { Some(-c_ji) };

                let s = match (lo, hi) {
                    (Some(lo), Some(hi)) if lo == hi => {
                        format!("{}-{}=={}", ri.name(), rj.name(), lo)
                    }
                    (Some(lo), Some(hi)) => {
                        format!("{}-{} in [{},{}]", ri.name(), rj.name(), lo, hi)
                    }
                    (None, Some(hi)) => {
                        format!("{}-{}<={}", ri.name(), rj.name(), hi)
                    }
                    (Some(lo), None) => {
                        format!("{}-{}>={}", ri.name(), rj.name(), lo)
                    }
                    _ => continue,
                };
                parts.push(s);
            }
        }

        parts.join("  ")
    }

    /// Standard DBM widening: entries that loosen become INF.
    /// Guarantees convergence since each step can only introduce INF entries.
    #[allow(dead_code)]
    pub fn widen(&self, newer: &Dbm) -> Dbm {
        let n = self.num_vars();
        let mut result = self.clone();
        result.provenance = None; // provenance doesn't survive widening
        // The `bounds[]` shadow (s64/s32/u64/u32 mins/maxes) is initialized
        // to "unknown" (e.g. s64_min=i64::MIN) and only ever tightened —
        // unless `sync_bounds` has been called to import information from
        // the DBM matrix (which carries the real bounds via `Zero <-> r`
        // edges), the shadow stays loose. Cousot widening on a loose
        // shadow is a one-way trap: once `b1.s64_min == i64::MIN`,
        // `b2.s64_min < b1.s64_min` is impossible, so result.s64_min
        // stays i64::MIN forever even when the DBM clearly bounds the
        // register (e.g. arena_htab_llvm's `r7 in [0, 99999]` after
        // bounds checks). Sync both inputs first so the per-bounds
        // widen sees the real abstract values.
        let mut self_synced = self.clone();
        let mut newer_synced = newer.clone();
        for i in 0..n {
            let r = REG_ENV.all().get(i).copied();
            if let Some(reg) = r
                && reg != Reg::Zero
                && !reg.is_anchor()
            {
                crate::domains::zone::ops::sync_bounds(&mut self_synced, reg);
                crate::domains::zone::ops::sync_bounds(&mut newer_synced, reg);
            }
        }
        for i in 0..n {
            for j in 0..n {
                if newer.data[i][j] > self.data[i][j] {
                    result.data[i][j] = INF;
                }
                // If newer <= self, keep self (stable/tightening)
            }
            let b1 = &self_synced.bounds[i];
            let b2 = &newer_synced.bounds[i];
            result.bounds[i].s32_min = if b2.s32_min < b1.s32_min {
                i32::MIN
            } else {
                b1.s32_min
            };
            result.bounds[i].s32_max = if b2.s32_max > b1.s32_max {
                i32::MAX
            } else {
                b1.s32_max
            };
            result.bounds[i].u32_min = if b2.u32_min < b1.u32_min {
                0
            } else {
                b1.u32_min
            };
            result.bounds[i].u32_max = if b2.u32_max > b1.u32_max {
                u32::MAX
            } else {
                b1.u32_max
            };
            result.bounds[i].s64_min = if b2.s64_min < b1.s64_min {
                i64::MIN
            } else {
                b1.s64_min
            };
            result.bounds[i].s64_max = if b2.s64_max > b1.s64_max {
                i64::MAX
            } else {
                b1.s64_max
            };
            result.bounds[i].u64_min = if b2.u64_min < b1.u64_min {
                0
            } else {
                b1.u64_min
            };
            result.bounds[i].u64_max = if b2.u64_max > b1.u64_max {
                u64::MAX
            } else {
                b1.u64_max
            };
        }
        result
    }

    /// Narrowing: intersect constraints from two DBMs.
    /// Takes the tighter (smaller) constraint for each entry.
    /// Used after widening to recover precision from the actual loop state.
    #[allow(dead_code)]
    pub fn narrow(&self, other: &Dbm) -> Dbm {
        let n = self.num_vars();
        let mut result = self.clone();
        result.provenance = None; // provenance doesn't survive narrowing
        for i in 0..n {
            for j in 0..n {
                // Take the tighter constraint (smaller value = tighter bound)
                result.data[i][j] = self.data[i][j].min(other.data[i][j]);
            }
            let b1 = &self.bounds[i];
            let b2 = &other.bounds[i];
            result.bounds[i].s32_min = b1.s32_min.max(b2.s32_min);
            result.bounds[i].s32_max = b1.s32_max.min(b2.s32_max);
            result.bounds[i].u32_min = b1.u32_min.max(b2.u32_min);
            result.bounds[i].u32_max = b1.u32_max.min(b2.u32_max);
            result.bounds[i].s64_min = b1.s64_min.max(b2.s64_min);
            result.bounds[i].s64_max = b1.s64_max.min(b2.s64_max);
            result.bounds[i].u64_min = b1.u64_min.max(b2.u64_min);
            result.bounds[i].u64_max = b1.u64_max.min(b2.u64_max);
        }
        result
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Provenance: path reconstruction
    // ══════════════════════════════════════════════════════════════════════════

    /// Decomposes the shortest path for `dbm[i][j]` into primitive edges.
    /// Returns `None` if provenance is not active or no constraint exists.
    pub fn reconstruct_path(&self, i: Reg, j: Reg) -> Option<Vec<PrimitiveEdge>> {
        let prov = self.provenance.as_ref()?;
        let val = self.get(i, j);
        if val >= INF {
            return None; // no constraint
        }
        let mut edges = Vec::new();
        self.decompose(prov, i.idx(), j.idx(), &mut edges);
        Some(edges)
    }

    fn decompose(
        &self,
        prov: &ProvenanceTracker,
        i: usize,
        j: usize,
        out: &mut Vec<PrimitiveEdge>,
    ) {
        match prov.edges[i][j] {
            EdgeOrigin::Primitive { pc } => {
                out.push(PrimitiveEdge {
                    to: Reg::idx_to_reg(i).unwrap(),
                    from: Reg::idx_to_reg(j).unwrap(),
                    weight: self.data[i][j],
                    pc,
                });
            }
            EdgeOrigin::Derived { via } => {
                self.decompose(prov, i, via, out);
                self.decompose(prov, via, j, out);
            }
            EdgeOrigin::Init => {
                // Diagonal (i==j, weight 0) or initial anchor constraint.
                // Emit as a trivial edge if meaningful.
                if i != j && self.data[i][j] < INF {
                    out.push(PrimitiveEdge {
                        to: Reg::idx_to_reg(i).unwrap(),
                        from: Reg::idx_to_reg(j).unwrap(),
                        weight: self.data[i][j],
                        pc: 0,
                    });
                }
            }
        }
    }
}

/// A primitive edge in a DBM shortest-path decomposition.
#[derive(Debug, Clone)]
pub struct PrimitiveEdge {
    /// The "to" register: constraint is `to - from <= weight`.
    pub to: Reg,
    /// The "from" register.
    pub from: Reg,
    /// The weight of this edge.
    pub weight: i64,
    /// The program counter of the instruction that established this edge.
    #[allow(dead_code)]
    pub pc: usize,
}

// Provenance is metadata — it should not affect semantic equality of DBMs.
impl PartialEq for Dbm {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.bounds == other.bounds
    }
}
impl Eq for Dbm {}

impl Default for Dbm {
    fn default() -> Self {
        Self::new()
    }
}

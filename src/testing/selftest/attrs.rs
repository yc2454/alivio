//! Scrape `bpf_misc.h` attribute macros from a `.c` source file.
//!
//! Modern upstream tests annotate each program function with macros like:
//!
//!     SEC("socket")
//!     __description("gotol, small_imm")
//!     __success __success_unpriv __retval(1)
//!     __naked void gotol_small_imm(void) { ... }
//!
//! This module performs a line-oriented scan that, for each function
//! definition, collects the contiguous block of attribute lines immediately
//! preceding it. No real C parsing; we rely on upstream's strict house style.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct ProgAttrs {
    /// `SEC("…")` string, with the libbpf `?` "optional" prefix stripped.
    pub sec: Option<String>,
    /// `__description("…")` — used as the test name in JSON.
    pub description: Option<String>,
    pub success: bool,
    pub failure: bool,
    pub success_unpriv: bool,
    pub failure_unpriv: bool,
    /// `__retval(N)` — expected program return value, if asserted.
    pub retval: Option<i64>,
    /// `__msg("…")` substrings expected in the verifier log.
    pub msgs: Vec<String>,
    pub log_level: Option<u32>,
    /// `__load_if_JITed()` — upstream test_loader only loads this prog
    /// when JIT is enabled. We don't model JIT specifics (e.g. JIT-mode
    /// may_goto stores its counter off-stack), so we treat such progs as
    /// skipped: an ACCEPT verdict on them only applies under JIT, which
    /// our (interpreter-mode) analysis cannot soundly assert.
    pub load_if_jited: bool,
    /// Program-load flags from `__flag(...)` annotations (encoded in
    /// upstream as the `comment:test_prog_flags=...` BTF decl_tag).
    /// We OR each flag into a single u32; the runner translates this
    /// to `ExecContext::flags` so the analysis honors gate-style
    /// flags such as `BPF_F_STRICT_ALIGNMENT`.
    pub prog_flags: u32,
    /// Function name (the C identifier before the parameter list).
    pub func_name: String,
}

impl ProgAttrs {
    fn is_empty(&self) -> bool {
        self.sec.is_none() && self.description.is_none() && !self.has_any_verdict()
    }

    fn has_any_verdict(&self) -> bool {
        self.success || self.failure || self.success_unpriv || self.failure_unpriv
    }
}

/// Scrape every annotated program in a source file. Order matches source order.
pub fn scrape<P: AsRef<Path>>(src: P) -> Result<Vec<ProgAttrs>> {
    let path = src.as_ref();
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(scrape_str(&text))
}

/// Same as [`scrape`] but operates on an in-memory string. Useful for tests.
pub fn scrape_str(text: &str) -> Vec<ProgAttrs> {
    let mut out = Vec::new();
    let mut cur = ProgAttrs::default();

    for raw_line in text.lines() {
        let line = raw_line.trim_start();
        // Skip pure comment / preprocessor / blank lines without resetting state.
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }

        // Apply attribute matchers (a single line may carry several, e.g.
        // `__success __success_unpriv __retval(1)`).
        apply_attrs(line, &mut cur);

        // Look for the function definition that terminates this attribute block.
        // Two emission triggers:
        //   1. cur has at least one annotation (SEC/__description/__success/...).
        //   2. The function uses a libbpf wrapper macro (BPF_STRUCT_OPS, BPF_PROG,
        //      ...). For struct_ops corpora the SEC lives on the outer ops-struct
        //      initializer, not on the per-callback function — without #2, only
        //      the first callback after the file-level `SEC("license")` attribute
        //      gets emitted; the rest are silently dropped. expectations.json
        //      is consulted by the runner when no in-source verdict annotation is
        //      present, so emitting with an empty `cur` is safe.
        if let Some(name) = extract_func_name(line) {
            let wrapper_sec = wrapper_macro_sec(line, &name);
            let wrapped = wrapper_sec.is_some();
            if !cur.is_empty() || wrapped {
                cur.func_name = name;
                // For BPF_STRUCT_OPS / BPF_STRUCT_OPS_SLEEPABLE the SEC
                // lives in the macro expansion, not on a preceding
                // attribute line — fill it in if the scraper hasn't
                // already captured one. (BPF_PROG and other plain
                // wrappers don't synthesize a SEC; the user's SEC()
                // attribute on the preceding line is what counts.)
                if cur.sec.is_none()
                    && let Some(s) = wrapper_sec
                {
                    cur.sec = Some(s);
                }
                out.push(std::mem::take(&mut cur));
            }
        }
    }

    out
}

/// Update `cur` with any attribute macros found on `line`.
fn apply_attrs(line: &str, cur: &mut ProgAttrs) {
    if let Some(s) = extract_quoted(line, "SEC") {
        let s = s.strip_prefix('?').unwrap_or(&s).to_string();
        cur.sec = Some(s);
    }
    if let Some(s) = extract_quoted(line, "__description") {
        cur.description = Some(s);
    }
    // Multiple `__msg(...)` per program are allowed; collect each occurrence.
    for m in extract_quoted_all(line, "__msg") {
        cur.msgs.push(m);
    }
    if has_word(line, "__success") {
        cur.success = true;
    }
    if has_word(line, "__failure") {
        cur.failure = true;
    }
    if has_word(line, "__success_unpriv") {
        cur.success_unpriv = true;
    }
    if has_word(line, "__failure_unpriv") {
        cur.failure_unpriv = true;
    }
    if has_word(line, "__load_if_JITed") {
        cur.load_if_jited = true;
    }
    if let Some(flag_name) = extract_macro_ident(line, "__flag") {
        cur.prog_flags |= match flag_name.as_str() {
            "BPF_F_STRICT_ALIGNMENT" => crate::common::constants::F_LOAD_WITH_STRICT_ALIGNMENT,
            "BPF_F_TEST_STATE_FREQ" => crate::common::constants::F_TEST_STATE_FREQ,
            // Other flags (BPF_F_ANY_ALIGNMENT, BPF_F_SLEEPABLE, …) aren't
            // currently consumed by the analysis — leave them as no-ops
            // rather than failing the scrape. test_loader treats unknown
            // values as a fatal error, but for us silent-ignore is sound.
            _ => 0,
        };
    }
    if let Some(n) = extract_int_arg(line, "__retval") {
        cur.retval = Some(n);
    }
    if let Some(n) = extract_int_arg(line, "__log_level") {
        cur.log_level = Some(n as u32);
    }
}

/// True iff `kw` appears in `line` as a complete identifier (not a prefix
/// of a longer one). Lets `__success` match without also matching
/// `__success_unpriv`.
fn has_word(line: &str, kw: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = line[start..].find(kw) {
        let abs = start + idx;
        let before_ok = abs == 0 || !is_ident_char(line.as_bytes()[abs - 1] as char);
        let after = abs + kw.len();
        let after_ok = after == line.len() || !is_ident_char(line.as_bytes()[after] as char);
        if before_ok && after_ok {
            return true;
        }
        start = abs + kw.len();
    }
    false
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Extract the first `MACRO("…")` argument string, e.g.
/// `SEC("socket")` → `"socket"`.
fn extract_quoted(line: &str, macro_name: &str) -> Option<String> {
    extract_quoted_all(line, macro_name).into_iter().next()
}

/// Extract every `MACRO("…")` argument on `line`, in source order.
fn extract_quoted_all(line: &str, macro_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(idx) = line[start..].find(macro_name) {
        let abs = start + idx;
        // Must be a whole identifier match.
        let before_ok = abs == 0 || !is_ident_char(line.as_bytes()[abs - 1] as char);
        let after = abs + macro_name.len();
        if !before_ok || after >= line.len() {
            start = abs + macro_name.len();
            continue;
        }
        // Skip whitespace, then expect `(` then `"`.
        let rest = line[after..].trim_start();
        if !rest.starts_with('(') {
            start = abs + macro_name.len();
            continue;
        }
        let inside = rest[1..].trim_start();
        if !inside.starts_with('"') {
            start = abs + macro_name.len();
            continue;
        }
        // Find closing quote (no escape handling — upstream strings don't use them).
        if let Some(end) = inside[1..].find('"') {
            out.push(inside[1..1 + end].to_string());
            // Advance past this match.
            let consumed = (after - abs) + (rest.len() - inside.len()) + 1 + end + 1;
            start = abs + consumed;
        } else {
            start = abs + macro_name.len();
        }
    }
    out
}

/// Extract `MACRO(IDENT)` identifier argument — for macros like
/// `__flag(BPF_F_STRICT_ALIGNMENT)` whose arg is an unquoted symbol,
/// not a string literal. Returns the first match on `line`.
fn extract_macro_ident(line: &str, macro_name: &str) -> Option<String> {
    let mut start = 0;
    while let Some(idx) = line[start..].find(macro_name) {
        let abs = start + idx;
        let before_ok = abs == 0 || !is_ident_char(line.as_bytes()[abs - 1] as char);
        let after = abs + macro_name.len();
        if !before_ok || after >= line.len() {
            start = abs + macro_name.len();
            continue;
        }
        let rest = line[after..].trim_start();
        if !rest.starts_with('(') {
            start = abs + macro_name.len();
            continue;
        }
        let inner = rest[1..].trim_start();
        let close = inner.find(')')?;
        let arg = inner[..close].trim();
        if !arg.is_empty() && !arg.starts_with('"') && arg.chars().all(is_ident_char) {
            return Some(arg.to_string());
        }
        start = abs + macro_name.len();
    }
    None
}

/// Extract `MACRO(N)` integer argument. Accepts decimal and `-N`.
fn extract_int_arg(line: &str, macro_name: &str) -> Option<i64> {
    let mut start = 0;
    while let Some(idx) = line[start..].find(macro_name) {
        let abs = start + idx;
        let before_ok = abs == 0 || !is_ident_char(line.as_bytes()[abs - 1] as char);
        let after = abs + macro_name.len();
        if !before_ok || after >= line.len() {
            start = abs + macro_name.len();
            continue;
        }
        let rest = line[after..].trim_start();
        if !rest.starts_with('(') {
            start = abs + macro_name.len();
            continue;
        }
        let inner = &rest[1..];
        if let Some(close) = inner.find(')') {
            let arg = inner[..close].trim();
            // Strip a trailing `LL` / `ULL` if present (rare in this corpus).
            let arg = arg.trim_end_matches(['L', 'l', 'U', 'u']);
            if let Ok(n) = arg.parse::<i64>() {
                return Some(n);
            }
        }
        start = abs + macro_name.len();
    }
    None
}

/// If `line` looks like a C function definition, return the function name.
///
/// Recognized shapes (this is enough for the verifier_*.c corpus):
///     `__naked void NAME(...)`
///     `int NAME(...)`
///     `void NAME(...)`
///     `static <type> NAME(...)`
///     `int BPF_PROG(NAME, …)` and friends — libbpf wrapper macros that
///     generate the real ELF symbol from the first arg.
fn extract_func_name(line: &str) -> Option<String> {
    let l = line.trim_end_matches(|c: char| c == '{' || c.is_whitespace());
    // Reject extern declarations / prototypes — they end with `;` after
    // the closing paren (or after attribute macros like `__ksym`). Only
    // function definitions are interesting to the runner; a definition's
    // signature line never ends in `;`. Multi-line signatures end in
    // `,` or the param-list close paren — both fine.
    if l.ends_with(';') {
        return None;
    }
    let lparen = l.find('(')?;
    let head = &l[..lparen];

    let tokens: Vec<&str> = head.split_whitespace().collect();
    let last = *tokens.last()?;

    if tokens.len() < 2 {
        return None;
    }
    if !last.chars().all(is_ident_char) || last.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }

    let prev = tokens[tokens.len() - 2];
    let is_typeish = matches!(
        prev,
        "void"
            | "int"
            | "long"
            | "short"
            | "char"
            | "unsigned"
            | "signed"
            | "bool"
            | "s32"
            | "u32"
            | "s64"
            | "u64"
            | "size_t"
    ) || prev.ends_with('*')
        || prev.ends_with("_t");
    if !is_typeish {
        return None;
    }

    // libbpf wrapper macros (`BPF_PROG(name, ...)`, `BPF_KPROBE(name, ...)`,
    // etc.) emit the real ELF symbol under the first argument's name. The
    // identifier we just lifted is the macro itself; pull the actual name
    // from inside the parens.
    if is_libbpf_wrapper_macro(last) {
        let inside = &l[lparen + 1..];
        let close = inside.find([',', ')'])?;
        let first_arg = inside[..close].trim();
        if !first_arg.is_empty() && first_arg.chars().all(is_ident_char) {
            return Some(first_arg.to_string());
        }
    }

    Some(last.to_string())
}

/// If `line` opens a function whose definition uses a libbpf wrapper
/// macro that implies a SEC (currently BPF_STRUCT_OPS variants), return
/// the implied SEC string. Returns None for plain BPF_PROG / BPF_KPROBE
/// / etc., where the user wrote their own SEC() above.
fn wrapper_macro_sec(line: &str, func_name: &str) -> Option<String> {
    let l = line.trim_end_matches(|c: char| c == '{' || c.is_whitespace());
    let lparen = l.find('(')?;
    let head = &l[..lparen];
    let last = head.split_whitespace().last()?;
    if !is_libbpf_wrapper_macro(last) {
        return None;
    }
    match last {
        "BPF_STRUCT_OPS" => Some(format!("struct_ops/{func_name}")),
        "BPF_STRUCT_OPS_SLEEPABLE" => Some(format!("struct_ops.s/{func_name}")),
        // Other wrappers (BPF_PROG, BPF_KPROBE, ...) don't synthesize a
        // SEC. Returning Some("") would still trigger force-emit —
        // return Some of an empty string only if the caller wants the
        // emit-without-SEC behavior. Today they go through the
        // SEC-attribute path, so return None here.
        _ => Some(String::new()),
    }
}

fn is_libbpf_wrapper_macro(name: &str) -> bool {
    matches!(
        name,
        "BPF_PROG"
            | "BPF_KPROBE"
            | "BPF_KRETPROBE"
            | "BPF_KPROBE_SYSCALL"
            | "BPF_KSYSCALL"
            | "BPF_KRETPROBE_SYSCALL"
            | "BPF_TP_PROG"
            | "BPF_USDT"
            | "BPF_UPROBE"
            | "BPF_URETPROBE"
            | "BPF_STRUCT_OPS"
            | "BPF_STRUCT_OPS_SLEEPABLE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrapes_gotol_small_imm() {
        let src = r#"
SEC("socket")
__description("gotol, small_imm")
__success __success_unpriv __retval(1)
__naked void gotol_small_imm(void)
{
    asm volatile (...);
}
"#;
        let progs = scrape_str(src);
        assert_eq!(progs.len(), 1);
        let p = &progs[0];
        assert_eq!(p.sec.as_deref(), Some("socket"));
        assert_eq!(p.description.as_deref(), Some("gotol, small_imm"));
        assert!(p.success);
        assert!(p.success_unpriv);
        assert_eq!(p.retval, Some(1));
        assert_eq!(p.func_name, "gotol_small_imm");
    }

    #[test]
    fn scrapes_dummy_int_func() {
        let src = r#"
SEC("socket")
__description("dummy")
__success
int dummy_test(void)
{
    return 0;
}
"#;
        let progs = scrape_str(src);
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].func_name, "dummy_test");
        assert!(progs[0].success);
    }

    #[test]
    fn scrapes_two_progs_in_a_row() {
        let src = r#"
SEC("socket")
__description("first")
__success __retval(1)
__naked void first(void) { ... }

SEC("socket")
__description("second")
__failure __msg("invalid bpf_context access")
__naked void second(void) { ... }
"#;
        let progs = scrape_str(src);
        assert_eq!(progs.len(), 2);
        assert_eq!(progs[0].description.as_deref(), Some("first"));
        assert_eq!(progs[0].retval, Some(1));
        assert_eq!(progs[1].description.as_deref(), Some("second"));
        assert!(progs[1].failure);
        assert_eq!(
            progs[1].msgs,
            vec!["invalid bpf_context access".to_string()]
        );
    }

    #[test]
    fn strips_optional_sec_prefix() {
        let src = r#"
SEC("?cgroup_skb/egress")
__description("opt")
__success
__naked void opt(void) { ... }
"#;
        let progs = scrape_str(src);
        assert_eq!(progs[0].sec.as_deref(), Some("cgroup_skb/egress"));
    }

    #[test]
    fn has_word_does_not_prefix_match() {
        assert!(has_word("__success __retval(1)", "__success"));
        assert!(!has_word("__success_unpriv __retval(1)", "__success"));
        assert!(has_word("__success __success_unpriv", "__success"));
        assert!(has_word("__success __success_unpriv", "__success_unpriv"));
    }

    #[test]
    fn scrapes_real_verifier_gotol() {
        let progs = scrape("selftests/progs/verifier_gotol.c").expect("read verifier_gotol.c");
        let names: Vec<&str> = progs.iter().map(|p| p.func_name.as_str()).collect();
        // Three functions: gotol_small_imm, gotol_large_imm, dummy_test
        // (the last only compiled when CAN_USE_GOTOL is unset; the scraper
        // doesn't see the #ifdef, so it picks all three up).
        assert!(names.contains(&"gotol_small_imm"), "names = {names:?}");
        assert!(names.contains(&"gotol_large_imm"), "names = {names:?}");
        let small = progs
            .iter()
            .find(|p| p.func_name == "gotol_small_imm")
            .unwrap();
        assert_eq!(small.sec.as_deref(), Some("socket"));
        assert_eq!(small.description.as_deref(), Some("gotol, small_imm"));
        assert!(small.success);
        assert!(small.success_unpriv);
        assert_eq!(small.retval, Some(1));
    }

    #[test]
    fn unwraps_bpf_prog_macro() {
        let src = r#"
SEC("perf_event")
__success
int BPF_PROG(perf_event_prog, struct pt_regs *ctx) { return 0; }
"#;
        let progs = scrape_str(src);
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].func_name, "perf_event_prog");
    }

    #[test]
    fn unwraps_bpf_kprobe_macro() {
        let src = r#"
SEC("kprobe/do_unlinkat")
__success
int BPF_KPROBE(do_unlinkat_probe, int dfd, struct filename *name) { return 0; }
"#;
        let progs = scrape_str(src);
        assert_eq!(progs[0].func_name, "do_unlinkat_probe");
    }

    #[test]
    fn retval_negative() {
        let src = r#"
SEC("socket")
__description("neg")
__success __retval(-1)
__naked void neg(void) { ... }
"#;
        let progs = scrape_str(src);
        assert_eq!(progs[0].retval, Some(-1));
    }
}

//! The edit script for saves above
//! [`super::engine::LINE_DIFF_THRESHOLD_BYTES`] (ADR 0081 §8, #1029).
//!
//! **Why not `LoroText::update_by_line`.** loro 1.16.2's line diff deletes
//! every changed line whole and inserts its new version whole. The
//! unchanged characters of that line come back as NEW ops. A concurrent
//! delete of the originals cannot remove the copies, so text another member
//! deleted comes back, and two members who edit the same line concurrently
//! end up with the line twice.
//!
//! **What this does instead.** A diff that is line-first for speed and
//! character-exact in its output:
//!
//! 1. Trim the common prefix and suffix, cut back to whole lines.
//! 2. Myers diff over the remaining lines (each line interned to an id).
//!    Each changed run of lines is widened to the nearest *anchor*: a
//!    non-blank line that occurs exactly once in each text. A blank or
//!    repeated line may be matched to the wrong occurrence; an anchor can
//!    only be wrong if the user moved it.
//! 3. Myers diff over the characters of each widened run.
//!
//! The result is applied as explicit `insert` / `delete` ops, so every
//! character the diff leaves unchanged keeps its original op.
//!
//! **Bounds.**
//! - Both diffs share one work budget ([`DIFF_WORK_BUDGET`]). A region
//!   still unresolved when it runs out is replaced whole, as
//!   `update_by_line` would replace its lines;
//!   [`EditScript::replaced_chars`] counts it. Only a save that rewrites,
//!   rather than edits, a large part of a note runs out (for example
//!   thousands of scattered edits in one save).
//! - Like loro's own character diff below the threshold, Myers picks one
//!   of several minimal scripts. When an edit both deletes and inserts a
//!   repeated character (a newline), a minimal script may re-insert a
//!   character next to it instead.
//!
//! The Myers middle-snake search follows the `similar` crate
//! (<https://github.com/mitsuhiko/similar>, MIT/Apache-2.0), which loro's
//! own `diff_impl` also copies. It depends only on `std` and `loro`.

use loro::{LoroError, LoroResult, LoroText};
use std::collections::HashMap;

/// Work units (one diagonal step or one compared element) the line and
/// character diffs of one save may spend together: about 100 ms in a
/// release build when all of it is spent. 500 scattered edits on a 4 MiB
/// note spend about 1.7 M.
pub const DIFF_WORK_BUDGET: u64 = 16 * 1024 * 1024;

/// One replacement, as byte ranges into the old and the new text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replace {
    /// Start of the replaced bytes in the old text.
    pub old_start: usize,
    /// End (exclusive) of the replaced bytes in the old text.
    pub old_end: usize,
    /// Start of the replacement bytes in the new text.
    pub new_start: usize,
    /// End (exclusive) of the replacement bytes in the new text.
    pub new_end: usize,
}

/// The edits that turn one text into another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EditScript {
    /// Non-overlapping replacements in ascending order.
    pub edits: Vec<Replace>,
    /// Old characters replaced whole because the work budget ran out
    /// (0 = every edit is character-exact).
    pub replaced_chars: usize,
    /// Work units the diffs spent (see [`DIFF_WORK_BUDGET`]).
    pub work: u64,
}

/// Index ranges into two sequences: `old[o0..o1]` becomes `new[n0..n1]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    o0: usize,
    o1: usize,
    n0: usize,
    n1: usize,
}

/// Remaining work units. Once spent, every open sub-problem is replaced
/// whole.
#[derive(Debug)]
struct Budget {
    left: u64,
}

impl Budget {
    /// Spend `n` units; `false` (and an empty budget) when not enough are
    /// left.
    fn spend(&mut self, n: usize) -> bool {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        if n > self.left {
            self.left = 0;
            false
        } else {
            self.left -= n;
            true
        }
    }
}

/// Compute the edit script from `old` to `new` with the given work budget.
#[must_use]
pub fn edit_script(old: &str, new: &str, budget: u64) -> EditScript {
    let initial = budget;
    let mut budget = Budget { left: budget };
    let (ob, nb) = (old.as_bytes(), new.as_bytes());

    // 1. Common prefix and suffix, cut back to whole lines so the middle is
    // whole lines in both texts (a byte after `\n` is a char boundary).
    let prefix = common_prefix(ob, nb);
    let prefix = ob[..prefix]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    let suffix = common_suffix(&ob[prefix..], &nb[prefix..]);
    let suffix = ob[ob.len() - suffix..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(0, |i| suffix - i - 1);
    let (old_end, new_end) = (ob.len() - suffix, nb.len() - suffix);
    let mut script = EditScript::default();
    if prefix == old_end && prefix == new_end {
        return script;
    }
    let old_mid = &old[prefix..old_end];
    let new_mid = &new[prefix..new_end];

    // 2. Lines, then widen each changed run to the nearest anchor lines.
    let lines = intern_lines(old_mid, new_mid);
    let mut line_spans = Vec::new();
    myers(&lines.old_ids, &lines.new_ids, &mut budget, &mut line_spans);
    let hunks = widen_to_anchors(&line_spans, &lines);

    // 3. Characters within each hunk. A hunk also takes the `\n` that ends
    // the line before it (an anchor, or the prefix): only an anchor's other
    // characters are fixed, so the diff may pair that newline differently.
    for hunk in hunks {
        let byte = |starts: &[usize], i: usize| prefix + starts.get(i).copied().unwrap_or(0);
        let (mut ob0, ob1) = (
            byte(&lines.old_starts, hunk.o0),
            byte(&lines.old_starts, hunk.o1),
        );
        let (mut nb0, nb1) = (
            byte(&lines.new_starts, hunk.n0),
            byte(&lines.new_starts, hunk.n1),
        );
        if ob0 > 0 && nb0 > 0 {
            ob0 -= 1;
            nb0 -= 1;
        }
        let (Some(old_hunk), Some(new_hunk)) = (old.get(ob0..ob1), new.get(nb0..nb1)) else {
            continue;
        };
        let old_chars: Vec<char> = old_hunk.chars().collect();
        let new_chars: Vec<char> = new_hunk.chars().collect();
        let mut spans = Vec::new();
        script.replaced_chars += myers(&old_chars, &new_chars, &mut budget, &mut spans);
        let mut old_cursor = CharCursor::default();
        let mut new_cursor = CharCursor::default();
        for s in spans {
            script.edits.push(Replace {
                old_start: ob0 + old_cursor.byte_at(old_hunk, s.o0),
                old_end: ob0 + old_cursor.byte_at(old_hunk, s.o1),
                new_start: nb0 + new_cursor.byte_at(new_hunk, s.n0),
                new_end: nb0 + new_cursor.byte_at(new_hunk, s.n1),
            });
        }
    }
    script.work = initial - budget.left;
    script
}

/// Save `new` into `text` by applying the edit script from its current
/// value as explicit ops.
///
/// # Errors
///
/// A loro error from `insert` / `delete`, or a
/// `TransactionError` if the result is not exactly `new` (the caller
/// discards the fork either way).
pub fn apply_edit_script(text: &LoroText, new: &str, budget: u64) -> LoroResult<EditScript> {
    let old = text.to_string();
    let script = edit_script(&old, new, budget);
    // Ascending order, unicode positions, and each replacement's insert
    // before its delete. On a 4 MiB note loro 1.16.2 spends ~0.8 ms on a
    // delete issued right after another delete in the same transaction and
    // ~5 µs otherwise (500 edits: 420 ms against 3 ms).
    let mut cursor = ByteCursor::default();
    let mut shift = 0usize; // new-text chars before the old position
    let mut consumed = 0usize; // old-text chars before the old position
    for e in &script.edits {
        let at = cursor.chars_to(&old, e.old_start);
        let end = cursor.chars_to(&old, e.old_end);
        let pos = shift + (at - consumed);
        let inserted = new.get(e.new_start..e.new_end).unwrap_or("");
        let inserted_chars = inserted.chars().count();
        if inserted_chars > 0 {
            text.insert(pos, inserted)?;
        }
        if end > at {
            text.delete(pos + inserted_chars, end - at)?;
        }
        shift = pos + inserted_chars;
        consumed = end;
    }
    if text.to_string() != new {
        return Err(LoroError::TransactionError(
            "edit script did not reproduce the saved text".into(),
        ));
    }
    Ok(script)
}

/// The lines of both texts (each keeps its `\n`) as interned ids.
#[derive(Debug)]
struct Lines {
    old_ids: Vec<u32>,
    new_ids: Vec<u32>,
    /// Byte offset of each old line, plus the end offset.
    old_starts: Vec<usize>,
    /// Byte offset of each new line, plus the end offset.
    new_starts: Vec<usize>,
    /// Per id: occurrences in the old and in the new text, or `None` for a
    /// blank (whitespace-only) line, which is never an anchor.
    counts: Vec<Option<[u32; 2]>>,
}

impl Lines {
    /// A non-blank line that occurs exactly once in each text. Matching it
    /// is wrong only if the user moved it. Any other matched line (a blank
    /// line, a repeated `}`) may pair two different occurrences, or carry
    /// only characters that the edit moved across it.
    fn is_anchor(&self, id: u32) -> bool {
        usize::try_from(id)
            .ok()
            .and_then(|i| self.counts.get(i))
            .is_some_and(|c| *c == Some([1, 1]))
    }
}

fn intern_lines<'a>(old: &'a str, new: &'a str) -> Lines {
    let mut table: HashMap<&'a str, u32> = HashMap::new();
    let mut counts: Vec<Option<[u32; 2]>> = Vec::new();
    let mut split = |s: &'a str, side: usize| {
        let mut ids = Vec::new();
        let mut starts = Vec::new();
        let mut at = 0;
        for line in s.split_inclusive('\n') {
            let id = match table.get(line) {
                Some(&id) => id,
                None => {
                    let id = u32::try_from(counts.len()).unwrap_or(u32::MAX);
                    table.insert(line, id);
                    counts.push((!line.trim().is_empty()).then_some([0, 0]));
                    id
                }
            };
            if let Some(Some(c)) = usize::try_from(id).ok().and_then(|i| counts.get_mut(i)) {
                c[side] = c[side].saturating_add(1);
            }
            ids.push(id);
            starts.push(at);
            at += line.len();
        }
        starts.push(at);
        (ids, starts)
    };
    let (old_ids, old_starts) = split(old, 0);
    let (new_ids, new_starts) = split(new, 1);
    Lines {
        old_ids,
        new_ids,
        old_starts,
        new_starts,
        counts,
    }
}

/// Merge changed line runs whose separating equal lines hold no anchor,
/// and extend the first and last run to the edge of the text when no
/// anchor lies between. Every hunk is then bounded by anchors or edges, so
/// a character that an edit (not a move) leaves in place has its old and
/// new position inside one hunk, where the character diff keeps it.
fn widen_to_anchors(spans: &[Span], lines: &Lines) -> Vec<Span> {
    let no_anchor = |from: usize, to: usize| {
        lines
            .old_ids
            .get(from..to)
            .is_some_and(|ids| !ids.iter().any(|&id| lines.is_anchor(id)))
    };
    let mut out: Vec<Span> = Vec::new();
    for s in spans {
        match out.last_mut() {
            Some(last) if no_anchor(last.o1, s.o0) => {
                last.o1 = s.o1;
                last.n1 = s.n1;
            }
            None if no_anchor(0, s.o0) => out.push(Span { o0: 0, n0: 0, ..*s }),
            _ => out.push(*s),
        }
    }
    let (old_len, new_len) = (lines.old_ids.len(), lines.new_ids.len());
    if let Some(last) = out.last_mut() {
        if no_anchor(last.o1, old_len) {
            last.o1 = old_len;
            last.n1 = new_len;
        }
    }
    out
}

/// Converts ascending byte offsets of one string to character indices.
#[derive(Debug, Default)]
struct ByteCursor {
    chars: usize,
    bytes: usize,
}

impl ByteCursor {
    fn chars_to(&mut self, s: &str, byte: usize) -> usize {
        if byte > self.bytes {
            self.chars += s.get(self.bytes..byte).map_or(0, |t| t.chars().count());
            self.bytes = byte;
        }
        self.chars
    }
}

/// Converts ascending character indices of one string to byte offsets.
#[derive(Debug, Default)]
struct CharCursor {
    chars: usize,
    bytes: usize,
}

impl CharCursor {
    fn byte_at(&mut self, s: &str, char_index: usize) -> usize {
        if char_index > self.chars {
            let skip = char_index - self.chars;
            let tail = s.get(self.bytes..).unwrap_or("");
            self.bytes += tail.chars().take(skip).map(char::len_utf8).sum::<usize>();
            self.chars = char_index;
        }
        self.bytes
    }
}

fn common_prefix<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn common_suffix<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

/// Append to `out` the spans turning `old` into `new` (ascending, adjacent
/// spans merged). Returns how many old elements were replaced whole
/// because the budget ran out.
fn myers<T: PartialEq>(old: &[T], new: &[T], budget: &mut Budget, out: &mut Vec<Span>) -> usize {
    // A middle-snake search that reaches d costs at least d² units, so the
    // diagonals never exceed √budget: size the vectors for that, not for
    // the whole input.
    let by_len = (old.len() + new.len()) / 2 + 2;
    let by_budget = usize::try_from(budget.left.isqrt()).unwrap_or(usize::MAX) + 2;
    let max_d = by_len.min(by_budget);
    let mut v = (OffsetVec::new(max_d), OffsetVec::new(max_d));
    let mut unresolved = 0;
    let whole = Span {
        o0: 0,
        o1: old.len(),
        n0: 0,
        n1: new.len(),
    };
    conquer(old, new, whole, &mut v, budget, out, &mut unresolved);
    unresolved
}

fn push(out: &mut Vec<Span>, s: Span) {
    if let Some(last) = out.last_mut() {
        if last.o1 == s.o0 && last.n1 == s.n0 {
            last.o1 = s.o1;
            last.n1 = s.n1;
            return;
        }
    }
    out.push(s);
}

/// Divide and conquer on the middle snake. A sub-problem the budget cannot
/// resolve is replaced whole and counted in `unresolved`.
fn conquer<T: PartialEq>(
    old: &[T],
    new: &[T],
    mut s: Span,
    v: &mut (OffsetVec, OffsetVec),
    budget: &mut Budget,
    out: &mut Vec<Span>,
    unresolved: &mut usize,
) {
    // Trimming is linear and always done, even with the budget spent.
    let p = common_prefix(&old[s.o0..s.o1], &new[s.n0..s.n1]);
    s.o0 += p;
    s.n0 += p;
    let q = common_suffix(&old[s.o0..s.o1], &new[s.n0..s.n1]);
    s.o1 -= q;
    s.n1 -= q;
    if s.o0 == s.o1 && s.n0 == s.n1 {
        return;
    }
    if s.o0 == s.o1 || s.n0 == s.n1 {
        push(out, s);
        return;
    }
    match find_middle_snake(old, new, s, v, budget) {
        // The split must make progress on both sides.
        Some((x, y)) if (x, y) != (s.o0, s.n0) && (x, y) != (s.o1, s.n1) => {
            let left = Span { o1: x, n1: y, ..s };
            let right = Span { o0: x, n0: y, ..s };
            conquer(old, new, left, v, budget, out, unresolved);
            conquer(old, new, right, v, budget, out, unresolved);
        }
        _ => {
            *unresolved += s.o1 - s.o0;
            push(out, s);
        }
    }
}

/// The start of the middle snake of `s` (Myers 1986, §4b), or `None` when
/// the budget or the diagonal vectors run out first.
fn find_middle_snake<T: PartialEq>(
    old: &[T],
    new: &[T],
    s: Span,
    v: &mut (OffsetVec, OffsetVec),
    budget: &mut Budget,
) -> Option<(usize, usize)> {
    let (vf, vb) = (&mut v.0, &mut v.1);
    let old = &old[s.o0..s.o1];
    let new = &new[s.n0..s.n1];
    let (n, m) = (old.len(), new.len());
    let delta = isize::try_from(n).ok()? - isize::try_from(m).ok()?;
    let odd = delta & 1 != 0;
    let d_max = ((n + m).div_ceil(2) + 1).min(vf.cap).min(vb.cap);
    vf.set(1, 0);
    vb.set(1, 0);
    for d in 0..isize::try_from(d_max).ok()? {
        for k in (-d..=d).rev().step_by(2) {
            if !budget.spend(1) {
                return None;
            }
            let mut x = if k == -d || (k != d && vf.get(k - 1) < vf.get(k + 1)) {
                vf.get(k + 1)
            } else {
                vf.get(k - 1) + 1
            };
            let y = usize::try_from(isize::try_from(x).ok()? - k).ok()?;
            let (x0, y0) = (x, y);
            if x < n && y < m {
                let advance = common_prefix(&old[x..], &new[y..]);
                if !budget.spend(advance) {
                    return None;
                }
                x += advance;
            }
            vf.set(k, x);
            if odd && (k - delta).abs() < d && vf.get(k) + vb.get(delta - k) >= n {
                return Some((x0 + s.o0, y0 + s.n0));
            }
        }
        for k in (-d..=d).rev().step_by(2) {
            if !budget.spend(1) {
                return None;
            }
            let mut x = if k == -d || (k != d && vb.get(k - 1) < vb.get(k + 1)) {
                vb.get(k + 1)
            } else {
                vb.get(k - 1) + 1
            };
            let mut y = usize::try_from(isize::try_from(x).ok()? - k).ok()?;
            if x < n && y < m {
                let advance = common_suffix(&old[..n - x], &new[..m - y]);
                if !budget.spend(advance) {
                    return None;
                }
                x += advance;
                y += advance;
            }
            vb.set(k, x);
            if !odd && (k - delta).abs() <= d && vb.get(k) + vf.get(delta - k) >= n {
                return Some((n - x + s.o0, m - y + s.n0));
            }
        }
    }
    None
}

/// Furthest-reaching x per diagonal k, for k in `-cap..cap`.
#[derive(Debug)]
struct OffsetVec {
    cap: usize,
    v: Vec<usize>,
}

impl OffsetVec {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            v: vec![0; cap.saturating_mul(2).saturating_add(2)],
        }
    }

    fn slot(&self, k: isize) -> usize {
        usize::try_from(k.saturating_add_unsigned(self.cap)).unwrap_or(usize::MAX)
    }

    fn get(&self, k: isize) -> usize {
        self.v.get(self.slot(k)).copied().unwrap_or(0)
    }

    fn set(&mut self, k: isize, x: usize) {
        let slot = self.slot(k);
        if let Some(cell) = self.v.get_mut(slot) {
            *cell = x;
        }
    }
}

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
//! **What this does instead.** The script is applied as explicit
//! `insert` / `delete` ops, so a character the script leaves unchanged
//! keeps its original op. It is built in three steps:
//!
//! 1. Trim the common prefix and suffix, cut back to whole lines.
//! 2. Split the rest into *hunks* at anchors: a non-blank line that occurs
//!    exactly once in each text. Anchors are matched by patience (longest
//!    increasing run of unique lines, `O(n log n)`). A hunk is the text
//!    between two matched anchors where old and new differ.
//! 3. Diff each hunk down a ladder of rungs:
//!    - **Exact.** Myers over the hunk's characters, within the shared
//!      [`EXACT_WORK_BUDGET`]. The result is a minimal character script.
//!    - **Line-paired.** Reached only when the exact diff runs out of budget.
//!      The hunk's lines are aligned by Myers over line ids. If that runs
//!      out and the old and new hunk have the same number of lines, they
//!      are paired by position instead. Each span of changed lines is then
//!      diffed by character (line against line when the counts match). This
//!      uses the shared [`LINE_WORK_BUDGET`]. A line whose character diff
//!      still runs out is replaced whole and counted in
//!      [`EditScript::replaced_lines`].
//!    - **Refuse.** The line alignment ran out and the line counts differ.
//!      There is no safe script within the budgets:
//!      [`TooLargeToMergeSafely`], and the caller refuses the save.
//!
//! **Loss bound.** A character the user did not change is deleted and
//! re-inserted, so a concurrent delete of it is undone, only when:
//! - (a) Myers breaks a tie between equal minimal scripts that way. This is
//!   the same tie loro's character diff below the threshold has; it needs an
//!   edit that deletes and inserts a repeated character such as a newline.
//! - (b) It lies on an old line counted in `replaced_lines`, which is
//!   reported with each save.
//!
//! No region larger than one span of changed lines is ever replaced whole.
//! Every old line in a hunk is changed, moved, blank or repeated: an
//! unchanged unique line would have been an anchor.
//!
//! The Myers middle-snake search follows the `similar` crate
//! (<https://github.com/mitsuhiko/similar>, MIT/Apache-2.0), which loro's
//! own `diff_impl` also copies. It depends only on `std` and `loro`.

use loro::LoroText;
use std::collections::HashMap;

/// Work units (one diagonal step or one compared element) the exact rung may
/// spend across all hunks of one save: about 100 ms in a release build when
/// all of it is spent. 500 scattered edits on a 4 MiB note spend about 1.7 M.
pub const EXACT_WORK_BUDGET: u64 = 16 * 1024 * 1024;

/// Work units the line-paired rung may spend across all hunks of one save.
pub const LINE_WORK_BUDGET: u64 = 16 * 1024 * 1024;

/// Most of [`LINE_WORK_BUDGET`] one hunk's line alignment may spend. The
/// rest is left for the character diffs of its lines.
pub const LINE_ALIGN_WORK: u64 = 4 * 1024 * 1024;

/// The work budgets of one save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// For the exact rung.
    pub exact: u64,
    /// For the line-paired rung.
    pub line: u64,
}

impl Budgets {
    /// The production budgets.
    pub const DEFAULT: Self = Self {
        exact: EXACT_WORK_BUDGET,
        line: LINE_WORK_BUDGET,
    };
}

/// The lowest rung of the ladder a save needed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiffRung {
    /// Every hunk has a minimal character script.
    #[default]
    Exact,
    /// At least one hunk was diffed line by line.
    LinePaired,
}

impl DiffRung {
    /// Stable name for the save result and diagnostics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::LinePaired => "line_paired",
        }
    }
}

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
    /// The lowest rung used.
    pub rung: DiffRung,
    /// Old lines replaced whole (loss bound (b)); 0 on the exact rung.
    pub replaced_lines: usize,
    /// Characters of those lines.
    pub replaced_chars: usize,
    /// Work units spent on both rungs.
    pub work: u64,
}

/// No safe edit script exists within the budgets: the save must be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLargeToMergeSafely {
    /// Old lines in the hunk that could not be aligned.
    pub old_lines: usize,
    /// New lines in that hunk.
    pub new_lines: usize,
}

/// Why [`apply_edit_script`] failed.
#[derive(Debug)]
pub enum ApplyError {
    /// The save is too large to merge safely; nothing was applied.
    TooLarge(TooLargeToMergeSafely),
    /// loro refused an op (the caller discards the fork).
    Loro,
    /// The ops did not reproduce the saved text (the caller discards the
    /// fork).
    Mismatch,
}

/// Index ranges into two sequences: `old[o0..o1]` becomes `new[n0..n1]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    o0: usize,
    o1: usize,
    n0: usize,
    n1: usize,
}

/// Remaining work units.
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

/// The texts, the trimmed prefix and the interned lines of the middle.
struct Ctx<'a> {
    old: &'a str,
    new: &'a str,
    prefix: usize,
    lines: Lines,
}

impl Ctx<'_> {
    /// Absolute byte offset of old line `i` (or the end).
    fn old_at(&self, i: usize) -> usize {
        self.prefix + self.lines.old_starts.get(i).copied().unwrap_or(0)
    }

    /// Absolute byte offset of new line `i` (or the end).
    fn new_at(&self, i: usize) -> usize {
        self.prefix + self.lines.new_starts.get(i).copied().unwrap_or(0)
    }
}

/// Compute the edit script from `old` to `new`.
///
/// # Errors
///
/// [`TooLargeToMergeSafely`] when a hunk can be neither diffed by character
/// nor aligned by line within the budgets.
pub fn edit_script(
    old: &str,
    new: &str,
    budgets: Budgets,
) -> Result<EditScript, TooLargeToMergeSafely> {
    let mut exact = Budget {
        left: budgets.exact,
    };
    let mut line = Budget { left: budgets.line };
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
        return Ok(script);
    }
    let ctx = Ctx {
        old,
        new,
        prefix,
        lines: intern_lines(&old[prefix..old_end], &new[prefix..new_end]),
    };

    // 2. Hunks between matched anchors.
    let (n_old, n_new) = (ctx.lines.old_ids.len(), ctx.lines.new_ids.len());
    let mut hunks = Vec::new();
    let (mut o0, mut n0) = (0, 0);
    for (i, j) in matched_anchors(&ctx.lines)
        .into_iter()
        .chain(std::iter::once((n_old, n_new)))
    {
        let differs =
            old.get(ctx.old_at(o0)..ctx.old_at(i)) != new.get(ctx.new_at(n0)..ctx.new_at(j));
        if differs {
            hunks.push(Span {
                o0,
                o1: i,
                n0,
                n1: j,
            });
        }
        (o0, n0) = (i + 1, j + 1);
    }

    // 3. The ladder, hunk by hunk.
    for hunk in hunks {
        // RED PROOF: c85eb5e's fallback, the whole unresolved hunk replaced.
        if !exact_hunk(&ctx, hunk, &mut exact, &mut script) {
            let _ = (&mut line, line_paired_hunk as fn(_, _, _, _) -> _);
            let (o0, o1) = (ctx.old_at(hunk.o0), ctx.old_at(hunk.o1));
            let (n0, n1) = (ctx.new_at(hunk.n0), ctx.new_at(hunk.n1));
            script.edits.push(Replace {
                old_start: o0,
                old_end: o1,
                new_start: n0,
                new_end: n1,
            });
        }
    }
    script.work = (budgets.exact - exact.left) + (budgets.line - line.left);
    Ok(script)
}

/// Push the edits turning old bytes `ob0..ob1` into new bytes `nb0..nb1`,
/// diffed by character. Returns `false`, pushing nothing, if the budget
/// runs out.
fn diff_chars(
    ctx: &Ctx<'_>,
    (ob0, ob1): (usize, usize),
    (nb0, nb1): (usize, usize),
    budget: &mut Budget,
    script: &mut EditScript,
) -> bool {
    let (Some(old), Some(new)) = (ctx.old.get(ob0..ob1), ctx.new.get(nb0..nb1)) else {
        return false;
    };
    let old_chars: Vec<char> = old.chars().collect();
    let new_chars: Vec<char> = new.chars().collect();
    let mut spans = Vec::new();
    if myers(&old_chars, &new_chars, budget, &mut spans) > 0 {
        return false;
    }
    let mut old_cursor = CharCursor::default();
    let mut new_cursor = CharCursor::default();
    for s in spans {
        script.edits.push(Replace {
            old_start: ob0 + old_cursor.byte_at(old, s.o0),
            old_end: ob0 + old_cursor.byte_at(old, s.o1),
            new_start: nb0 + new_cursor.byte_at(new, s.n0),
            new_end: nb0 + new_cursor.byte_at(new, s.n1),
        });
    }
    true
}

/// The exact rung. The hunk also takes the `\n` that ends the line before
/// it (an anchor, or the prefix): only an anchor's other characters are
/// fixed, so the diff may pair that newline differently.
fn exact_hunk(ctx: &Ctx<'_>, hunk: Span, budget: &mut Budget, script: &mut EditScript) -> bool {
    let (mut ob0, mut nb0) = (ctx.old_at(hunk.o0), ctx.new_at(hunk.n0));
    if ob0 > 0 && nb0 > 0 {
        ob0 -= 1;
        nb0 -= 1;
    }
    let old = (ob0, ctx.old_at(hunk.o1));
    let new = (nb0, ctx.new_at(hunk.n1));
    diff_chars(ctx, old, new, budget, script)
}

/// The line-paired rung (see the module docs).
fn line_paired_hunk(
    ctx: &Ctx<'_>,
    hunk: Span,
    budget: &mut Budget,
    script: &mut EditScript,
) -> Result<(), TooLargeToMergeSafely> {
    let old_ids = ctx.lines.old_ids.get(hunk.o0..hunk.o1).unwrap_or(&[]);
    let new_ids = ctx.lines.new_ids.get(hunk.n0..hunk.n1).unwrap_or(&[]);
    let mut align = Budget {
        left: budget.left.min(LINE_ALIGN_WORK),
    };
    let before = align.left;
    let mut spans = Vec::new();
    let unaligned = myers(old_ids, new_ids, &mut align, &mut spans);
    budget.left -= before - align.left;
    if unaligned > 0 {
        if old_ids.len() != new_ids.len() {
            return Err(TooLargeToMergeSafely {
                old_lines: old_ids.len(),
                new_lines: new_ids.len(),
            });
        }
        // Same line count: pair by position.
        spans = vec![Span {
            o0: 0,
            o1: old_ids.len(),
            n0: 0,
            n1: new_ids.len(),
        }];
    }
    for s in spans {
        let (o0, o1) = (hunk.o0 + s.o0, hunk.o0 + s.o1);
        let (n0, n1) = (hunk.n0 + s.n0, hunk.n0 + s.n1);
        if o1 - o0 == n1 - n0 {
            for k in 0..o1 - o0 {
                replace_lines(
                    ctx,
                    (o0 + k, o0 + k + 1),
                    (n0 + k, n0 + k + 1),
                    budget,
                    script,
                );
            }
        } else {
            replace_lines(ctx, (o0, o1), (n0, n1), budget, script);
        }
    }
    Ok(())
}

/// Diff old lines `o0..o1` into new lines `n0..n1` by character, or replace
/// them whole (counted) if the budget runs out.
fn replace_lines(
    ctx: &Ctx<'_>,
    (o0, o1): (usize, usize),
    (n0, n1): (usize, usize),
    budget: &mut Budget,
    script: &mut EditScript,
) {
    let old = (ctx.old_at(o0), ctx.old_at(o1));
    let new = (ctx.new_at(n0), ctx.new_at(n1));
    if diff_chars(ctx, old, new, budget, script) {
        return;
    }
    script.replaced_lines += o1 - o0;
    script.replaced_chars += ctx.old.get(old.0..old.1).map_or(0, |s| s.chars().count());
    script.edits.push(Replace {
        old_start: old.0,
        old_end: old.1,
        new_start: new.0,
        new_end: new.1,
    });
}

/// Save `new` into `text` by applying the edit script from its current
/// value as explicit ops.
///
/// # Errors
///
/// [`ApplyError::TooLarge`] before any op is applied; otherwise
/// [`ApplyError::Loro`] or [`ApplyError::Mismatch`] (the caller discards
/// the fork).
pub fn apply_edit_script(
    text: &LoroText,
    new: &str,
    budgets: Budgets,
) -> Result<EditScript, ApplyError> {
    let old = text.to_string();
    let script = edit_script(&old, new, budgets).map_err(ApplyError::TooLarge)?;
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
            text.insert(pos, inserted).map_err(|_| ApplyError::Loro)?;
        }
        if end > at {
            text.delete(pos + inserted_chars, end - at)
                .map_err(|_| ApplyError::Loro)?;
        }
        shift = pos + inserted_chars;
        consumed = end;
    }
    if text.to_string() != new {
        return Err(ApplyError::Mismatch);
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

/// The anchors matched between the texts, as `(old line, new line)` in
/// ascending order: the longest run of anchors whose order agrees in both
/// texts (patience diff; `O(n log n)`, no budget).
fn matched_anchors(lines: &Lines) -> Vec<(usize, usize)> {
    let new_pos: HashMap<u32, usize> = lines
        .new_ids
        .iter()
        .enumerate()
        .filter(|(_, &id)| lines.is_anchor(id))
        .map(|(j, &id)| (id, j))
        .collect();
    let pairs: Vec<(usize, usize)> = lines
        .old_ids
        .iter()
        .enumerate()
        .filter_map(|(i, id)| new_pos.get(id).map(|&j| (i, j)))
        .collect();
    // Longest increasing subsequence of the new positions.
    let mut tails: Vec<usize> = Vec::new();
    let mut prev: Vec<Option<usize>> = vec![None; pairs.len()];
    for (k, &(_, j)) in pairs.iter().enumerate() {
        let at = tails.partition_point(|&t| pairs.get(t).is_some_and(|p| p.1 < j));
        if let Some(slot) = prev.get_mut(k) {
            *slot = at.checked_sub(1).and_then(|p| tails.get(p)).copied();
        }
        if at == tails.len() {
            tails.push(k);
        } else if let Some(t) = tails.get_mut(at) {
            *t = k;
        }
    }
    let mut out = Vec::new();
    let mut cur = tails.last().copied();
    while let Some(k) = cur {
        if let Some(&p) = pairs.get(k) {
            out.push(p);
        }
        cur = prev.get(k).copied().flatten();
    }
    out.reverse();
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
/// spans merged). Returns how many old elements the budget could not
/// resolve; their spans are whole replacements, so every caller discards a
/// result with a nonzero count.
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
/// resolve becomes one span and is counted in `unresolved`.
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

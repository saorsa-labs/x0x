//! Local history recording and retention policy (ADR 0116 §1).
//!
//! The `[history]` keys `dm_recording`, `class_limits` and `topic_rules`
//! (TOML or [`super::HistoryConfig`] in the library) compile here, once,
//! into a [`HistoryPolicy`]. Compilation is also validation: every check
//! ADR 0116 §1 lists runs before history opens, and the library and the
//! daemon share it.
//!
//! The policy is local. It never changes what this node sends, and a
//! sender cannot set it on a receiver (ADR 0116 §3).
//!
//! With every new key unset the compiled policy is
//! [`HistoryPolicy::is_unset`], and history records and retains exactly
//! as it did before ADR 0116.

use serde::{Deserialize, Serialize};

use crate::error::{HistoryError, HistoryResult};

/// Upper bound on `class_limits` plus `topic_rules` entries combined
/// (ADR 0116 §1).
pub const MAX_POLICY_RULES: usize = 256;

/// Upper bound on one topic-rule prefix, in UTF-8 bytes (ADR 0116 §1).
pub const MAX_TOPIC_PREFIX_BYTES: usize = 256;

/// One day in milliseconds. Positive ages are measured from local
/// `seen_at_ms` in 24-hour days (ADR 0116 §1).
const MS_PER_DAY: i64 = 86_400_000;

/// How this node records ordinary inbound and outbound DMs
/// (`[history] dm_recording`, ADR 0116 §1).
///
/// It never reclassifies a registered protocol handler or its own durable
/// store, and it does not apply to group history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DmRecording {
    /// Record ordinary DMs as ADR 0023 classifies them (the default).
    #[default]
    Inherit,
    /// Write no history row for an ordinary DM on this node.
    Ephemeral,
}

impl DmRecording {
    /// Whether this is the default, `inherit`. Lets a serialized default
    /// `HistoryConfig` omit the key and keep its bytes unchanged.
    #[must_use]
    pub fn is_inherit(&self) -> bool {
        *self == Self::Inherit
    }
}

/// How a topic rule records the topics it selects (ADR 0116 §1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TopicRecording {
    /// Record as `record_topics` selects (the default).
    #[default]
    Inherit,
    /// Write no history row for a topic this rule wins.
    Ephemeral,
}

/// A retained message class a `class_limits` entry may name.
///
/// `ephemeral` is not a retained class, so it cannot carry a retention
/// budget and has no variant here (ADR 0116 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RetainedClass {
    /// Append-only history rows (`replace_key` unset).
    Durable,
    /// Current-state rows (`replace_key` set).
    Replaceable,
}

/// One `[[history.class_limits]]` entry (ADR 0116 §1).
///
/// An entry must set `max_bytes` or a positive `max_age_days`. `max_bytes =
/// 0` retains no eligible row of the class; an omitted or zero age adds no
/// age bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassLimit {
    /// The class this entry bounds.
    pub class: RetainedClass,
    /// Aggregate byte budget for the class (payload plus signed artifact).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Age bound in days from local `seen_at_ms`; 0 or omitted adds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_days: Option<u64>,
}

/// One `[[history.topic_rules]]` entry (ADR 0116 §1).
///
/// `prefix` is a non-empty, case-sensitive literal UTF-8 prefix: no glob,
/// regex or SQL wildcard. The longest matching prefix wins the whole rule;
/// fields it omits do not inherit from a shorter prefix. A rule that sets
/// only `prefix` is valid: it carves its topics out of a shorter rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicRule {
    /// Literal topic-name prefix.
    pub prefix: String,
    /// Recording mode for topics this rule wins.
    #[serde(default, skip_serializing_if = "is_inherit")]
    pub recording: TopicRecording,
    /// Aggregate byte budget over every topic this rule wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Age bound in days from local `seen_at_ms`; 0 or omitted adds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_days: Option<u64>,
}

fn is_inherit(recording: &TopicRecording) -> bool {
    *recording == TopicRecording::Inherit
}

/// The bounds one class or topic rule imposes, after validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompiledBounds {
    /// Aggregate byte budget; `None` = no extra byte bound.
    pub max_bytes: Option<u64>,
    /// Positive age bound in milliseconds; `None` = no age bound.
    pub max_age_ms: Option<i64>,
}

impl CompiledBounds {
    /// Whether this sets no bound at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.max_bytes.is_none() && self.max_age_ms.is_none()
    }
}

/// A validated topic rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledTopicRule {
    /// Literal topic-name prefix.
    pub prefix: String,
    /// Recording mode for topics this rule wins.
    pub recording: TopicRecording,
    /// Retention bounds for every topic this rule wins.
    pub bounds: CompiledBounds,
}

/// The validated, compiled local history policy (ADR 0116 §1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryPolicy {
    dm_recording: DmRecording,
    durable: Option<CompiledBounds>,
    replaceable: Option<CompiledBounds>,
    /// Sorted by prefix bytes, ascending: the order ADR 0116 §2 processes
    /// topic budgets in.
    topic_rules: Vec<CompiledTopicRule>,
}

impl HistoryPolicy {
    /// Validate and compile the new `[history]` keys.
    ///
    /// # Errors
    /// [`HistoryError::InvalidConfig`] names the first rule ADR 0116 §1
    /// rejects: a duplicate class or prefix, an empty class entry, an empty
    /// or over-long prefix, too many rules, or a bound that overflows.
    pub fn compile(
        dm_recording: DmRecording,
        class_limits: &[ClassLimit],
        topic_rules: &[TopicRule],
    ) -> HistoryResult<Self> {
        let total = class_limits.len().saturating_add(topic_rules.len());
        if total > MAX_POLICY_RULES {
            return Err(invalid(format!(
                "[history] class_limits and topic_rules hold {total} entries; at most \
                 {MAX_POLICY_RULES} are allowed"
            )));
        }

        let mut durable = None;
        let mut replaceable = None;
        for limit in class_limits {
            let name = class_name(limit.class);
            let bounds = compile_bounds(limit.max_bytes, limit.max_age_days, || {
                format!("[[history.class_limits]] class = \"{name}\"")
            })?;
            if bounds.is_empty() {
                return Err(invalid(format!(
                    "[[history.class_limits]] class = \"{name}\" sets neither max_bytes nor \
                     a positive max_age_days"
                )));
            }
            let slot = match limit.class {
                RetainedClass::Durable => &mut durable,
                RetainedClass::Replaceable => &mut replaceable,
            };
            if slot.replace(bounds).is_some() {
                return Err(invalid(format!(
                    "[[history.class_limits]] has more than one entry for class \"{name}\""
                )));
            }
        }

        let mut compiled = Vec::with_capacity(topic_rules.len());
        for rule in topic_rules {
            if rule.prefix.is_empty() {
                return Err(invalid(
                    "[[history.topic_rules]] prefix must not be empty".to_string(),
                ));
            }
            if rule.prefix.len() > MAX_TOPIC_PREFIX_BYTES {
                return Err(invalid(format!(
                    "[[history.topic_rules]] prefix is {} bytes; at most \
                     {MAX_TOPIC_PREFIX_BYTES} UTF-8 bytes are allowed",
                    rule.prefix.len()
                )));
            }
            let bounds = compile_bounds(rule.max_bytes, rule.max_age_days, || {
                format!("[[history.topic_rules]] prefix = {:?}", rule.prefix)
            })?;
            compiled.push(CompiledTopicRule {
                prefix: rule.prefix.clone(),
                recording: rule.recording,
                bounds,
            });
        }
        compiled.sort_by(|a, b| a.prefix.as_bytes().cmp(b.prefix.as_bytes()));
        if let Some(pair) = compiled.windows(2).find(|w| w[0].prefix == w[1].prefix) {
            return Err(invalid(format!(
                "[[history.topic_rules]] has more than one rule for prefix {:?}",
                pair[0].prefix
            )));
        }

        Ok(Self {
            dm_recording,
            durable,
            replaceable,
            topic_rules: compiled,
        })
    }

    /// True when every new key is unset: recording and retention are
    /// exactly what they were before ADR 0116.
    #[must_use]
    pub fn is_unset(&self) -> bool {
        self.dm_recording == DmRecording::Inherit
            && self.durable.is_none()
            && self.replaceable.is_none()
            && self.topic_rules.is_empty()
    }

    /// Whether any class or topic rule sets a retention bound. When false
    /// the reaper runs main's retention unchanged (ADR 0116 Validation
    /// row 1): a prefix-only topic rule bounds nothing.
    #[must_use]
    pub fn has_retention_bounds(&self) -> bool {
        self.durable.is_some()
            || self.replaceable.is_some()
            || self.topic_rules.iter().any(|rule| !rule.bounds.is_empty())
    }

    /// How many topic rules set a retention bound. These are the rules
    /// the reaper matches against topic names in SQL, which needs a UTF-8
    /// database.
    #[must_use]
    pub fn bounded_topic_rule_count(&self) -> usize {
        self.topic_rules
            .iter()
            .filter(|rule| !rule.bounds.is_empty())
            .count()
    }

    /// Ordinary-DM recording mode.
    #[must_use]
    pub fn dm_recording(&self) -> DmRecording {
        self.dm_recording
    }

    /// The bounds a `class_limits` entry sets for `class`, if any.
    #[must_use]
    pub fn class_bounds(&self, class: RetainedClass) -> Option<CompiledBounds> {
        match class {
            RetainedClass::Durable => self.durable,
            RetainedClass::Replaceable => self.replaceable,
        }
    }

    /// Topic rules in prefix byte order.
    #[must_use]
    pub fn topic_rules(&self) -> &[CompiledTopicRule] {
        &self.topic_rules
    }

    /// The rule a topic name selects: the longest prefix it starts with,
    /// compared as literal bytes. `None` when no rule matches.
    #[must_use]
    pub fn winning_topic_rule(&self, topic: &str) -> Option<&CompiledTopicRule> {
        self.topic_rules
            .iter()
            .filter(|rule| topic.as_bytes().starts_with(rule.prefix.as_bytes()))
            .max_by_key(|rule| rule.prefix.len())
    }
}

fn class_name(class: RetainedClass) -> &'static str {
    match class {
        RetainedClass::Durable => "durable",
        RetainedClass::Replaceable => "replaceable",
    }
}

/// Validate one entry's bounds. A byte budget must fit SQLite's signed
/// 64-bit integer; a positive age must fit `i64` milliseconds.
fn compile_bounds(
    max_bytes: Option<u64>,
    max_age_days: Option<u64>,
    what: impl Fn() -> String,
) -> HistoryResult<CompiledBounds> {
    if let Some(bytes) = max_bytes {
        if i64::try_from(bytes).is_err() {
            return Err(invalid(format!(
                "{}: max_bytes {bytes} exceeds {}",
                what(),
                i64::MAX
            )));
        }
    }
    let max_age_ms = match max_age_days {
        None | Some(0) => None,
        Some(days) => Some(
            i64::try_from(days)
                .ok()
                .and_then(|days| days.checked_mul(MS_PER_DAY))
                .ok_or_else(|| {
                    invalid(format!(
                        "{}: max_age_days {days} overflows a millisecond age",
                        what()
                    ))
                })?,
        ),
    };
    Ok(CompiledBounds {
        max_bytes,
        max_age_ms,
    })
}

fn invalid(message: String) -> HistoryError {
    HistoryError::InvalidConfig(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(
        class: RetainedClass,
        max_bytes: Option<u64>,
        max_age_days: Option<u64>,
    ) -> ClassLimit {
        ClassLimit {
            class,
            max_bytes,
            max_age_days,
        }
    }

    fn rule(prefix: &str) -> TopicRule {
        TopicRule {
            prefix: prefix.to_string(),
            recording: TopicRecording::Inherit,
            max_bytes: None,
            max_age_days: None,
        }
    }

    #[test]
    fn nothing_set_compiles_to_an_unset_policy() {
        let policy = HistoryPolicy::compile(DmRecording::Inherit, &[], &[]).unwrap();
        assert!(policy.is_unset());
        assert_eq!(policy, HistoryPolicy::default());
    }

    /// `max_bytes = 0` is a bound; a zero age is the same as no age.
    #[test]
    fn zero_and_omitted_bounds_compile_distinctly() {
        let policy = HistoryPolicy::compile(
            DmRecording::Inherit,
            &[
                class(RetainedClass::Durable, Some(0), None),
                class(RetainedClass::Replaceable, Some(5), Some(0)),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            policy.class_bounds(RetainedClass::Durable),
            Some(CompiledBounds {
                max_bytes: Some(0),
                max_age_ms: None,
            })
        );
        assert_eq!(
            policy.class_bounds(RetainedClass::Replaceable),
            Some(CompiledBounds {
                max_bytes: Some(5),
                max_age_ms: None,
            })
        );
        let aged = HistoryPolicy::compile(
            DmRecording::Inherit,
            &[class(RetainedClass::Durable, None, Some(7))],
            &[],
        )
        .unwrap();
        assert_eq!(
            aged.class_bounds(RetainedClass::Durable),
            Some(CompiledBounds {
                max_bytes: None,
                max_age_ms: Some(7 * 86_400_000),
            })
        );
    }

    /// A byte budget must fit SQLite's signed integer. TOML cannot express
    /// a larger value, but the library's `HistoryConfig` can.
    #[test]
    fn a_byte_budget_above_i64_max_is_rejected() {
        let over = u64::try_from(i64::MAX).unwrap() + 1;
        let error = HistoryPolicy::compile(
            DmRecording::Inherit,
            &[class(RetainedClass::Durable, Some(over), None)],
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
        let mut topic = rule("app.");
        topic.max_bytes = Some(u64::MAX);
        assert!(HistoryPolicy::compile(DmRecording::Inherit, &[], &[topic]).is_err());
        assert!(HistoryPolicy::compile(
            DmRecording::Inherit,
            &[class(
                RetainedClass::Durable,
                Some(u64::try_from(i64::MAX).unwrap()),
                None
            )],
            &[],
        )
        .is_ok());
    }

    /// The longest matching prefix selects the WHOLE rule: fields it omits
    /// do not come from a shorter prefix.
    #[test]
    fn the_longest_prefix_wins_the_whole_rule() {
        let mut short = rule("app.");
        short.recording = TopicRecording::Ephemeral;
        short.max_age_days = Some(3);
        let mut long = rule("app.chat");
        long.max_bytes = Some(1024);
        let policy = HistoryPolicy::compile(DmRecording::Inherit, &[], &[long, short]).unwrap();

        let chat = policy.winning_topic_rule("app.chat.room1").unwrap();
        assert_eq!(chat.prefix, "app.chat");
        assert_eq!(chat.recording, TopicRecording::Inherit);
        assert_eq!(
            chat.bounds,
            CompiledBounds {
                max_bytes: Some(1024),
                max_age_ms: None,
            },
            "no age is inherited from the shorter \"app.\" rule"
        );
        assert_eq!(
            policy.winning_topic_rule("app.sync").unwrap().prefix,
            "app."
        );
        assert_eq!(
            policy.winning_topic_rule("app.chat").unwrap().prefix,
            "app.chat"
        );
        assert!(policy.winning_topic_rule("ap").is_none());
        assert!(policy.winning_topic_rule("other.app.chat").is_none());
    }

    /// Prefixes are literal, case-sensitive bytes: no glob, regex or SQL
    /// wildcard meaning.
    #[test]
    fn prefixes_are_literal_case_sensitive_bytes() {
        let policy = HistoryPolicy::compile(
            DmRecording::Inherit,
            &[],
            &[rule("app.%"), rule("app._"), rule("app.*"), rule("App.")],
        )
        .unwrap();
        assert!(policy.winning_topic_rule("app.x").is_none());
        assert!(policy.winning_topic_rule("app.chat").is_none());
        assert_eq!(policy.winning_topic_rule("app.%y").unwrap().prefix, "app.%");
        assert_eq!(policy.winning_topic_rule("app._").unwrap().prefix, "app._");
        assert_eq!(policy.winning_topic_rule("app.*z").unwrap().prefix, "app.*");
        assert!(policy.winning_topic_rule("APP.chat").is_none());
        assert_eq!(
            policy.winning_topic_rule("App.chat").unwrap().prefix,
            "App."
        );
    }

    /// Topic budgets are processed in prefix byte order (ADR 0116 §2).
    #[test]
    fn topic_rules_are_kept_in_prefix_byte_order() {
        let policy = HistoryPolicy::compile(
            DmRecording::Inherit,
            &[],
            &[rule("é."), rule("b"), rule("a."), rule("a"), rule("Z")],
        )
        .unwrap();
        let order: Vec<&str> = policy
            .topic_rules()
            .iter()
            .map(|rule| rule.prefix.as_str())
            .collect();
        // Bytes: 'Z' 0x5A < 'a' 0x61 < "a." < 'b' 0x62 < 'é' 0xC3 0xA9.
        assert_eq!(order, ["Z", "a", "a.", "b", "é."]);
    }

    /// Slice C enforces the `ephemeral` recording modes, so every valid rule
    /// compiles and nothing is refused for being unenforced.
    #[test]
    fn every_valid_rule_compiles_including_the_ephemeral_modes() {
        let carve_out =
            HistoryPolicy::compile(DmRecording::Inherit, &[], &[rule("app.chat")]).unwrap();
        assert!(!carve_out.is_unset(), "a configured rule is not \"unset\"");
        assert!(
            !carve_out.has_retention_bounds(),
            "a prefix-only rule bounds nothing"
        );

        let dm = HistoryPolicy::compile(DmRecording::Ephemeral, &[], &[]).unwrap();
        assert_eq!(dm.dm_recording(), DmRecording::Ephemeral);
        assert!(!dm.has_retention_bounds());

        let mut ephemeral = rule("app.sync.");
        ephemeral.recording = TopicRecording::Ephemeral;
        let topics = HistoryPolicy::compile(DmRecording::Inherit, &[], &[ephemeral]).unwrap();
        assert_eq!(
            topics
                .winning_topic_rule("app.sync.state")
                .map(|r| r.recording),
            Some(TopicRecording::Ephemeral)
        );
    }
}

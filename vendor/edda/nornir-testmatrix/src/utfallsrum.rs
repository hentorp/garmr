//! # utfallsrum — first-class outcome-space coverage (boundary-value + equivalence-partition analysis)
//!
//! `utfallsrum` (Swedish: *outcome space* / sample space) makes a function's
//! **whole outcome space** a measurable, recordable thing — not just "did one
//! call pass?". A test declares the function's CONTRACT as a set of
//! **outcome classes** (the equivalence partitions + boundary values its output
//! must cover), records which classes a run actually exercised (with the exact
//! asserted output per class), and the framework computes a single
//! **`covered ∈ [0,1]`** score = exercised-classes / declared-classes.
//!
//! This is classic **equivalence-partition + boundary-value analysis** made
//! first-class and persistable: a single-value test scores low even when green,
//! and the matrix carries per-function outcome-space coverage alongside the
//! pass/fail [`functional_status`](crate::functional) verdict.
//!
//! ```text
//!  declare:  Outcome::for_fn("clamp01")
//!              .class("below-0", "input < 0  ⇒  output == 0.0")     // a partition / boundary
//!              .class("in-range", "0 ≤ input ≤ 1  ⇒  output == input")
//!              .class("above-1", "input > 1  ⇒  output == 1.0")
//!  record:   o.hit("below-0", "clamp01(-0.5) == 0.0");             // exercised, with the exact output
//!            o.hit("in-range", "clamp01(0.3) == 0.3");
//!  score:    o.covered()  ==  2/3  ≈ 0.667    (above-1 not yet swept → not done)
//! ```
//!
//! ## Why a class, not a value
//! A correct function maps a *partition* of its inputs to a known region of its
//! output space. Sweeping ten values inside one partition proves nothing the
//! first value didn't; sweeping one value in EACH partition + the boundaries
//! between them is what proves the contract. `utfallsrum` records coverage at
//! that granularity — the unit that actually moves the needle.
//!
//! ## Relation to the rest of the crate
//! - [`functional_status`](crate::functional) records ONE pass/fail per check.
//!   `utfallsrum` records the **shape** of the check: how much of the declared
//!   outcome space the test swept. They compose — an [`Outcome`] emits its
//!   per-class results as `functional_status` rows AND a roll-up
//!   `<fn>/utfallsrum` row carrying the score as its `metric`, so the warehouse
//!   carries both pass/fail and outcome-space coverage on the existing path.
//! - The completeness gate ([`crate::coverage`]) consumes the score: a surface
//!   only counts as **covered** when its functions meet an utfallsrum threshold
//!   (≥K classes swept), so a one-value smoke test does NOT flip a surface green.
//!
//! Pure `std` + `serde` (toolkit-neutral); every type round-trips so the score
//! persists to the warehouse like any other fact.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{TestResultRow, status};

/// One declared **outcome class** — an equivalence partition or a boundary value
/// of a function's output space, with the contract it must satisfy.
///
/// `name` is the stable id within the function (`"below-0"`, `"empty-input"`,
/// `"denominator→0"`). `contract` is the human/spec statement of what a correct
/// output is for this class (`"input < 0 ⇒ output == 0.0"`). Once a test `hit`s
/// the class it also carries the **exact asserted output** (`evidence`) so the
/// record proves *what* came out, not merely *that* something did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeClass {
    /// Stable id within the function (the partition / boundary name).
    pub name: String,
    /// The contract a correct output must satisfy for this class (spec text).
    pub contract: String,
    /// Whether a test actually exercised this class this run.
    #[serde(default)]
    pub exercised: bool,
    /// The exact asserted output that exercised the class (`""` until hit) —
    /// e.g. `"clamp01(-0.5) == 0.0"`. Proves the output, not just "ran".
    #[serde(default)]
    pub evidence: String,
}

impl OutcomeClass {
    /// A freshly-declared, not-yet-exercised class.
    pub fn declared(name: impl Into<String>, contract: impl Into<String>) -> Self {
        OutcomeClass {
            name: name.into(),
            contract: contract.into(),
            exercised: false,
            evidence: String::new(),
        }
    }
}

/// A function's declared **outcome space** + the per-class exercise record.
///
/// Build it with [`Outcome::for_fn`] + [`Outcome::class`] (declare the
/// partitions/boundaries), then [`Outcome::hit`] each class as a test exercises
/// it with the exact output. [`Outcome::covered`] is the score in `[0,1]`.
///
/// The class set is a `BTreeMap` keyed by name so the same class declared twice
/// is one class (idempotent declaration) and the output is deterministically
/// ordered — the persisted rows are stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// The function whose outcome space this is (the stable id for rows).
    pub function: String,
    /// The declared classes, keyed by name (declaration is idempotent).
    pub classes: BTreeMap<String, OutcomeClass>,
}

impl Outcome {
    /// Begin declaring the outcome space of `function`.
    pub fn for_fn(function: impl Into<String>) -> Self {
        Outcome {
            function: function.into(),
            classes: BTreeMap::new(),
        }
    }

    /// Declare one outcome class (an equivalence partition / boundary value) with
    /// its contract. Idempotent: re-declaring a name keeps the first contract and
    /// preserves any `hit` already recorded (so declare-order is irrelevant).
    pub fn class(mut self, name: impl Into<String>, contract: impl Into<String>) -> Self {
        let name = name.into();
        self.classes
            .entry(name.clone())
            .or_insert_with(|| OutcomeClass::declared(name, contract));
        self
    }

    /// Declare many classes at once from `(name, contract)` pairs.
    pub fn classes<I, N, C>(mut self, classes: I) -> Self
    where
        I: IntoIterator<Item = (N, C)>,
        N: Into<String>,
        C: Into<String>,
    {
        for (n, c) in classes {
            self = self.class(n, c);
        }
        self
    }

    /// Record that a test **exercised** `class` with the exact asserted output as
    /// `evidence` (`"clamp01(-0.5) == 0.0"`). Marks the class exercised. A `hit`
    /// on an undeclared class is RECORDED as an undeclared exercised class (it
    /// counts, but it's flagged — see [`Outcome::undeclared_hits`] — so an
    /// outcome the test found but the contract never declared is visible, never
    /// silently dropped or silently inflating the score's denominator).
    pub fn hit(&mut self, class: &str, evidence: impl Into<String>) -> &mut Self {
        let evidence = evidence.into();
        self.classes
            .entry(class.to_string())
            .and_modify(|c| {
                c.exercised = true;
                if c.evidence.is_empty() {
                    c.evidence = evidence.clone();
                }
            })
            .or_insert_with(|| OutcomeClass {
                name: class.to_string(),
                contract: String::new(), // undeclared — flagged by undeclared_hits
                exercised: true,
                evidence,
            });
        self
    }

    /// Total declared (and discovered) classes — the score denominator.
    pub fn declared_count(&self) -> usize {
        self.classes.len()
    }

    /// How many classes a test actually exercised — the score numerator.
    pub fn exercised_count(&self) -> usize {
        self.classes.values().filter(|c| c.exercised).count()
    }

    /// `utfallsrum_covered ∈ [0,1]` = exercised-classes / declared-classes. An
    /// empty outcome space (no class declared) scores `0.0` — declaring nothing
    /// is never "fully covered" (a function with no declared outcome space is a
    /// gap, not a pass).
    pub fn covered(&self) -> f64 {
        let d = self.declared_count();
        if d == 0 {
            return 0.0;
        }
        self.exercised_count() as f64 / d as f64
    }

    /// The names of declared-but-not-yet-exercised classes (the burn-down list —
    /// the part of the outcome space still unswept), sorted.
    pub fn unexercised(&self) -> Vec<String> {
        self.classes
            .values()
            .filter(|c| !c.exercised && !c.contract.is_empty())
            .map(|c| c.name.clone())
            .collect()
    }

    /// Classes that were `hit` but never `class`-declared (contract empty) — an
    /// outcome the test found that the declared space didn't anticipate. Sorted.
    /// Worth surfacing: it means the contract under-described the function.
    pub fn undeclared_hits(&self) -> Vec<String> {
        self.classes
            .values()
            .filter(|c| c.exercised && c.contract.is_empty())
            .map(|c| c.name.clone())
            .collect()
    }

    /// Is the whole declared outcome space covered (`covered() == 1.0`)? True iff
    /// at least one class is declared and every declared class is exercised.
    pub fn is_complete(&self) -> bool {
        self.declared_count() > 0 && self.unexercised().is_empty()
    }

    /// Emit this outcome space as matrix [`TestResultRow`]s: ONE per declared
    /// class (`suite = function`, `test_name = "<class>"`, aspect
    /// [`UTFALLSRUM_ASPECT`], `pass` iff exercised, `message = contract +
    /// evidence`) PLUS a roll-up row (`test_name = "utfallsrum"`) whose `metric`
    /// is the `covered()` score in `[0,1]` and whose status is `pass` iff
    /// [`Outcome::is_complete`]. The roll-up row is how the warehouse carries the
    /// per-function outcome-space coverage alongside the functional verdict.
    pub fn to_rows(&self) -> Vec<TestResultRow> {
        let mut rows = Vec::with_capacity(self.classes.len() + 1);
        for c in self.classes.values() {
            let message = if c.evidence.is_empty() {
                c.contract.clone()
            } else {
                format!("{} | {}", c.contract, c.evidence)
            };
            rows.push(TestResultRow {
                run_id: String::new(),
                repo: String::new(),
                suite: self.function.clone(),
                test_name: c.name.clone(),
                status: if c.exercised {
                    status::PASS
                } else {
                    status::LISTED
                }
                .to_string(),
                duration_ms: 0.0,
                ts_micros: 0,
                message,
                aspect: UTFALLSRUM_ASPECT.to_string(),
                metric: if c.exercised { 1.0 } else { 0.0 },
            });
        }
        // Roll-up: the score is the metric; complete ⇒ pass, else fail (a partial
        // outcome space is a RED roll-up even when each exercised class is green).
        rows.push(TestResultRow {
            run_id: String::new(),
            repo: String::new(),
            suite: self.function.clone(),
            test_name: "utfallsrum".to_string(),
            status: if self.is_complete() {
                status::PASS
            } else {
                status::FAIL
            }
            .to_string(),
            duration_ms: 0.0,
            ts_micros: 0,
            message: format!(
                "{}/{} outcome classes swept ({:.0}%); unswept: [{}]",
                self.exercised_count(),
                self.declared_count(),
                self.covered() * 100.0,
                self.unexercised().join(", "),
            ),
            aspect: UTFALLSRUM_ASPECT.to_string(),
            metric: self.covered(),
        });
        rows
    }

    /// Emit this outcome space to the process-global functional buffer (feature
    /// `testmatrix` ON) so `nornir test` / the matrix drains it like any other
    /// functional row. One [`functional_status`](crate::functional) emit per
    /// declared class + the roll-up. A no-op in release (feature OFF). The
    /// `component` prefixes the function id so rows scope to their surface
    /// (e.g. `"viz/Bench"` + fn `"bench_history"` → suite `"viz/Bench::bench_history"`).
    #[cfg(feature = "testmatrix")]
    pub fn emit(&self, component: &str) {
        let suite = if component.is_empty() {
            self.function.clone()
        } else {
            format!("{component}::{}", self.function)
        };
        for c in self.classes.values() {
            let detail = if c.evidence.is_empty() {
                c.contract.clone()
            } else {
                format!("{} | {}", c.contract, c.evidence)
            };
            crate::functional::functional_status(&suite, &c.name, c.exercised, &detail);
        }
        let roll = format!(
            "{}/{} classes swept ({:.0}%); unswept: [{}]",
            self.exercised_count(),
            self.declared_count(),
            self.covered() * 100.0,
            self.unexercised().join(", "),
        );
        crate::functional::functional_status(&suite, "utfallsrum", self.is_complete(), &roll);
    }

    /// No-op emit in release (feature OFF) — mirrors
    /// [`functional_status`](crate::functional)'s release stub so a consumer can
    /// call `o.emit(..)` unconditionally and pay zero release cost.
    #[cfg(not(feature = "testmatrix"))]
    #[inline]
    pub fn emit(&self, _component: &str) {}

    /// A compact persisted summary of this outcome space — the warehouse-facing
    /// shape (function + score + counts + the unswept list). Round-trips through
    /// serde so the score lands as a fact next to `functional_status`.
    pub fn summary(&self) -> UtfallsrumSummary {
        UtfallsrumSummary {
            function: self.function.clone(),
            declared: self.declared_count(),
            exercised: self.exercised_count(),
            covered: self.covered(),
            complete: self.is_complete(),
            unexercised: self.unexercised(),
            undeclared_hits: self.undeclared_hits(),
        }
    }
}

/// The aspect tag carried by utfallsrum [`TestResultRow`]s — distinct from
/// `"functional"` so the matrix can group / filter outcome-space rows.
pub const UTFALLSRUM_ASPECT: &str = "utfallsrum";

/// A compact, persistable roll-up of one function's outcome-space coverage — the
/// warehouse-facing fact ([`Outcome::summary`]). Carries the score + the
/// burn-down (unswept) list so the gate / viz can show outcome-space coverage
/// without re-deriving it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UtfallsrumSummary {
    pub function: String,
    /// Declared outcome classes (the denominator).
    pub declared: usize,
    /// Exercised classes (the numerator).
    pub exercised: usize,
    /// `covered ∈ [0,1]` = exercised / declared.
    pub covered: f64,
    /// `covered == 1.0` (every declared class swept).
    pub complete: bool,
    /// Declared-but-unswept class names (the burn-down list).
    pub unexercised: Vec<String>,
    /// Exercised-but-undeclared class names (contract under-described the fn).
    #[serde(default)]
    pub undeclared_hits: Vec<String>,
}

impl UtfallsrumSummary {
    /// Does this function meet an outcome-space threshold of `min_classes`
    /// exercised? The gate's "≥K classes swept" rule: a function below the
    /// threshold did NOT sweep enough of its outcome space to count as covered,
    /// even if every case it ran was green. `min_classes == 0` accepts anything
    /// (the threshold is off); `min_classes >= 1` requires real multi-value sweep.
    pub fn meets_threshold(&self, min_classes: usize) -> bool {
        self.exercised >= min_classes && self.exercised > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::status;

    /// A canonical outcome space: `clamp01` partitions inputs into below-0 /
    /// in-range / above-1 with exact output contracts.
    fn clamp01_space() -> Outcome {
        Outcome::for_fn("clamp01")
            .class("below-0", "input < 0  ⇒  output == 0.0")
            .class("in-range", "0 ≤ input ≤ 1  ⇒  output == input")
            .class("above-1", "input > 1  ⇒  output == 1.0")
    }

    #[test]
    fn covered_is_exercised_over_declared_multi_value() {
        // Inject MULTIPLE real outcomes across partitions; assert the exact score.
        let mut o = clamp01_space();
        assert_eq!(o.declared_count(), 3, "three declared partitions");
        assert_eq!(o.covered(), 0.0, "nothing swept yet → 0.0");

        // Sweep two of the three partitions with their EXACT asserted outputs.
        o.hit("below-0", "clamp01(-0.5) == 0.0");
        o.hit("in-range", "clamp01(0.3) == 0.3");
        assert_eq!(o.exercised_count(), 2);
        assert!(
            (o.covered() - 2.0 / 3.0).abs() < 1e-9,
            "2/3 of the space swept"
        );
        assert!(!o.is_complete(), "above-1 unswept → not complete");
        assert_eq!(
            o.unexercised(),
            vec!["above-1".to_string()],
            "the unswept boundary is named"
        );

        // Sweep the last partition → full coverage.
        o.hit("above-1", "clamp01(1.7) == 1.0");
        assert_eq!(o.covered(), 1.0, "all three partitions swept → 1.0");
        assert!(o.is_complete());
        assert!(o.unexercised().is_empty());
    }

    #[test]
    fn single_value_scores_low_even_when_green() {
        // The core differentiator: ONE value (one partition) is a low score even
        // though that one assertion passed — a single-value test is not "covered".
        let mut o = clamp01_space();
        o.hit("in-range", "clamp01(0.5) == 0.5"); // green, but only one partition
        assert!(
            (o.covered() - 1.0 / 3.0).abs() < 1e-9,
            "one of three → 0.333"
        );
        assert!(
            !o.is_complete(),
            "a single-value sweep never completes the space"
        );
        // And it fails a ≥2-class threshold.
        assert!(
            !o.summary().meets_threshold(2),
            "one class < threshold of 2"
        );
        assert!(o.summary().meets_threshold(1), "but meets a threshold of 1");
    }

    #[test]
    fn empty_outcome_space_scores_zero_not_one() {
        // Declaring nothing is a GAP, never "fully covered" — guards the obvious
        // gaming (0/0 = 1.0 would let a no-declaration test claim full coverage).
        let o = Outcome::for_fn("undeclared");
        assert_eq!(o.declared_count(), 0);
        assert_eq!(o.covered(), 0.0, "no declared space → 0.0, not 1.0");
        assert!(!o.is_complete());
        assert!(!o.summary().meets_threshold(1));
    }

    #[test]
    fn declaration_is_idempotent_and_order_free() {
        // Re-declaring a class keeps the first contract + any recorded hit.
        let mut o = Outcome::for_fn("f").class("a", "first contract");
        o.hit("a", "a-evidence");
        let o = o
            .class("a", "SECOND contract (ignored)")
            .class("b", "b contract");
        assert_eq!(o.declared_count(), 2, "re-declared `a` is still one class");
        let a = o.classes.get("a").unwrap();
        assert_eq!(a.contract, "first contract", "first contract wins");
        assert!(a.exercised, "the hit survived re-declaration");
        assert_eq!(a.evidence, "a-evidence");
    }

    #[test]
    fn undeclared_hit_counts_but_is_flagged() {
        // A hit on a class the contract never declared still counts (the outcome
        // happened) but is surfaced — the contract under-described the function.
        let mut o = Outcome::for_fn("f").class("declared", "the declared partition");
        o.hit("declared", "ok");
        o.hit("surprise", "an unanticipated outcome");
        assert_eq!(
            o.declared_count(),
            2,
            "the surprise class is now part of the space"
        );
        assert_eq!(o.exercised_count(), 2);
        assert_eq!(
            o.undeclared_hits(),
            vec!["surprise".to_string()],
            "flagged, not silent"
        );
        // The declared-but-unswept list excludes the undeclared (it has no contract).
        assert!(o.unexercised().is_empty(), "every declared class was swept");
    }

    #[test]
    fn to_rows_emits_per_class_plus_scored_rollup() {
        let mut o = clamp01_space();
        o.hit("below-0", "clamp01(-1.0) == 0.0");
        o.hit("in-range", "clamp01(0.5) == 0.5");
        // above-1 left unswept → the roll-up must be RED with metric 2/3.
        let rows = o.to_rows();
        assert_eq!(rows.len(), 4, "3 class rows + 1 roll-up");

        let below = rows.iter().find(|r| r.test_name == "below-0").unwrap();
        assert_eq!(below.status, status::PASS, "swept class is green");
        assert_eq!(below.aspect, UTFALLSRUM_ASPECT);
        assert!(
            below.message.contains("clamp01(-1.0) == 0.0"),
            "evidence carried in the message"
        );

        let above = rows.iter().find(|r| r.test_name == "above-1").unwrap();
        assert_eq!(
            above.status,
            status::LISTED,
            "unswept class is a listed (NotRun) gap"
        );
        assert_eq!(above.metric, 0.0);

        let roll = rows.iter().find(|r| r.test_name == "utfallsrum").unwrap();
        assert_eq!(
            roll.status,
            status::FAIL,
            "partial outcome space → RED roll-up"
        );
        assert!(
            (roll.metric - 2.0 / 3.0).abs() < 1e-9,
            "roll-up metric IS the score"
        );
        assert!(
            roll.message.contains("above-1"),
            "roll-up names the unswept class"
        );

        // Complete the space → the roll-up flips green with metric 1.0.
        o.hit("above-1", "clamp01(2.0) == 1.0");
        let roll2 = o
            .to_rows()
            .into_iter()
            .find(|r| r.test_name == "utfallsrum")
            .unwrap();
        assert_eq!(roll2.status, status::PASS, "full space → green roll-up");
        assert_eq!(roll2.metric, 1.0);
    }

    #[test]
    fn summary_round_trips_through_serde_with_the_score() {
        let mut o = clamp01_space();
        o.hit("below-0", "e1");
        o.hit("above-1", "e2");
        let s = o.summary();
        assert_eq!(s.function, "clamp01");
        assert_eq!(s.declared, 3);
        assert_eq!(s.exercised, 2);
        assert!((s.covered - 2.0 / 3.0).abs() < 1e-9);
        assert!(!s.complete);
        assert_eq!(s.unexercised, vec!["in-range".to_string()]);

        let json = serde_json::to_string(&s).unwrap();
        let back: UtfallsrumSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s, "the score persists as a fact");
    }

    #[test]
    fn meets_threshold_enforces_min_classes() {
        let mut o = Outcome::for_fn("f")
            .class("a", "ca")
            .class("b", "cb")
            .class("c", "cc");
        o.hit("a", "ea");
        let s1 = o.summary();
        assert!(s1.meets_threshold(1), "1 swept ≥ 1");
        assert!(
            !s1.meets_threshold(2),
            "1 swept < 2 — a one-value smoke fails the gate"
        );

        o.hit("b", "eb");
        let s2 = o.summary();
        assert!(s2.meets_threshold(2), "2 swept ≥ 2 → meets the gate");
        // threshold 0 accepts anything that ran at all (still needs ≥1 exercised).
        assert!(s2.meets_threshold(0));
        let none = Outcome::for_fn("g").class("x", "cx").summary();
        assert!(
            !none.meets_threshold(0),
            "zero swept never meets the gate, even at threshold 0"
        );
    }

    // ── feature ON: the emit path drains as functional rows ──────────────────
    #[cfg(feature = "testmatrix")]
    #[test]
    fn emit_drains_per_class_plus_rollup_into_functional_rows() {
        let _guard = crate::functional::test_lock();
        let _ = crate::functional::drain_functional_rows();

        let mut o = Outcome::for_fn("emit_fn")
            .class("emit-class-x", "cx")
            .class("emit-class-y", "cy");
        o.hit("emit-class-x", "x-out");
        // y left unswept.
        o.emit("viz/Emit");

        let rows = crate::functional::drain_functional_rows();
        let mine: Vec<_> = rows
            .iter()
            .filter(|r| r.suite == "viz/Emit::emit_fn")
            .collect();
        assert_eq!(
            mine.len(),
            3,
            "2 class rows + 1 roll-up, prefixed by component"
        );

        let x = mine.iter().find(|r| r.test_name == "emit-class-x").unwrap();
        assert_eq!(x.status, status::PASS);
        assert!(x.message.contains("x-out"), "exact output evidence emitted");
        let y = mine.iter().find(|r| r.test_name == "emit-class-y").unwrap();
        assert_eq!(
            y.status,
            status::FAIL,
            "unswept class is a fail on the functional wire"
        );
        let roll = mine.iter().find(|r| r.test_name == "utfallsrum").unwrap();
        assert_eq!(
            roll.status,
            status::FAIL,
            "1/2 swept → incomplete → red roll-up"
        );
        assert!(roll.message.contains("50%"));
    }
}

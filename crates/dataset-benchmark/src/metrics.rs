use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Confusion {
    pub true_positive: u64,
    pub false_positive: u64,
    pub true_negative: u64,
    pub false_negative: u64,
}

fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 / denominator as f64)
}

impl Confusion {
    pub fn record(&mut self, actual: bool, predicted: bool) {
        match (actual, predicted) {
            (true, true) => self.true_positive += 1,
            (false, true) => self.false_positive += 1,
            (false, false) => self.true_negative += 1,
            (true, false) => self.false_negative += 1,
        }
    }

    pub fn total(&self) -> u64 {
        self.true_positive + self.false_positive + self.true_negative + self.false_negative
    }

    pub fn scores(&self) -> Scores {
        let precision = ratio(self.true_positive, self.true_positive + self.false_positive);
        let recall = ratio(self.true_positive, self.true_positive + self.false_negative);
        let f1 = match (precision, recall) {
            (Some(p), Some(r)) if p + r > 0.0 => Some(2.0 * p * r / (p + r)),
            (Some(_), Some(_)) => Some(0.0),
            _ => None,
        };
        let positives = self.true_positive + self.false_negative;
        let base_rate = ratio(positives, self.total());
        Scores {
            precision,
            recall,
            f1,
            accuracy: ratio(self.true_positive + self.true_negative, self.total()),
            specificity: ratio(self.true_negative, self.true_negative + self.false_positive),
            flag_rate: ratio(self.true_positive + self.false_positive, self.total()),
            base_rate,
            // A detector that flags everything: precision = base rate, recall = 1.
            always_flag_f1: base_rate.map(|rate| {
                if rate > 0.0 {
                    2.0 * rate / (1.0 + rate)
                } else {
                    0.0
                }
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Scores {
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
    pub accuracy: Option<f64>,
    pub specificity: Option<f64>,
    /// Share of samples the analyzer flagged at all.
    pub flag_rate: Option<f64>,
    /// Share of samples labeled vulnerable.
    pub base_rate: Option<f64>,
    /// F1 of the trivial "flag everything" baseline, for comparison.
    pub always_flag_f1: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RuleStats {
    pub fired_on_vulnerable: u64,
    pub fired_on_safe: u64,
    pub precision: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CweStats {
    pub vulnerable_samples: u64,
    /// Samples where the analyzer reported anything.
    pub flagged: u64,
    /// Samples where the analyzer reported this same CWE.
    pub matched_cwe: u64,
    pub recall_any: Option<f64>,
    pub recall_same_cwe: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LanguageStats {
    pub confusion: Confusion,
    pub scores: Scores,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityMetrics {
    pub rows_read: u64,
    pub evaluated: u64,
    pub skipped_unlabeled: u64,
    pub skipped_empty: u64,
    pub skipped_oversize: u64,
    pub skipped_unsupported_language: BTreeMap<String, u64>,
    pub analyzer_errors: u64,
    /// Evaluated samples whose syntax tree contained errors (fragments, macros, …).
    pub parsed_with_errors: u64,
    pub confusion: Confusion,
    pub scores: Scores,
    pub by_language: BTreeMap<String, LanguageStats>,
    pub by_cwe: BTreeMap<String, CweStats>,
    pub by_rule: BTreeMap<String, RuleStats>,
}

impl VulnerabilityMetrics {
    pub fn record(
        &mut self,
        language: &str,
        vulnerable: bool,
        labeled_cwes: &BTreeSet<String>,
        observed_rules: &BTreeSet<String>,
        observed_cwes: &BTreeSet<String>,
    ) {
        let predicted = !observed_rules.is_empty();
        self.evaluated += 1;
        self.confusion.record(vulnerable, predicted);
        self.by_language
            .entry(language.to_string())
            .or_default()
            .confusion
            .record(vulnerable, predicted);
        for rule in observed_rules {
            let stats = self.by_rule.entry(rule.clone()).or_default();
            if vulnerable {
                stats.fired_on_vulnerable += 1;
            } else {
                stats.fired_on_safe += 1;
            }
        }
        if vulnerable {
            for cwe in labeled_cwes {
                let stats = self.by_cwe.entry(cwe.clone()).or_default();
                stats.vulnerable_samples += 1;
                stats.flagged += u64::from(predicted);
                stats.matched_cwe += u64::from(observed_cwes.contains(cwe));
            }
        }
    }

    pub fn finish(&mut self) {
        self.scores = self.confusion.scores();
        for stats in self.by_language.values_mut() {
            stats.scores = stats.confusion.scores();
        }
        for stats in self.by_rule.values_mut() {
            stats.precision = ratio(
                stats.fired_on_vulnerable,
                stats.fired_on_vulnerable + stats.fired_on_safe,
            );
        }
        for stats in self.by_cwe.values_mut() {
            stats.recall_any = ratio(stats.flagged, stats.vulnerable_samples);
            stats.recall_same_cwe = ratio(stats.matched_cwe, stats.vulnerable_samples);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RepairPairMetrics {
    pub rows_read: u64,
    pub pairs_evaluated: u64,
    pub skipped_empty: u64,
    pub skipped_oversize: u64,
    pub skipped_unsupported_language: BTreeMap<String, u64>,
    pub analyzer_errors: u64,
    pub findings_before: u64,
    pub findings_after: u64,
    /// Pairs where the buggy side had findings.
    pub pairs_flagged_before: u64,
    /// Pairs where every finding on the buggy side is gone after the fix.
    pub pairs_cleared_by_fix: u64,
    /// Pairs where the fix introduced a rule that did not fire before.
    pub pairs_with_new_findings: u64,
    pub rules_removed_by_fix: BTreeMap<String, u64>,
    pub rules_introduced_by_fix: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SecretProbeMetrics {
    pub texts_scanned: u64,
    pub texts_with_hits: u64,
    pub hits: u64,
    pub hits_by_rule: BTreeMap<String, u64>,
    /// Texts with at least one hit per 1,000 scanned. On public benchmark code nearly all of
    /// these are placeholders or published test keys, so lower is better.
    pub hit_texts_per_thousand: Option<f64>,
}

impl SecretProbeMetrics {
    pub fn record(&mut self, rules: &[&str]) {
        self.texts_scanned += 1;
        if !rules.is_empty() {
            self.texts_with_hits += 1;
        }
        for rule in rules {
            self.hits += 1;
            *self.hits_by_rule.entry((*rule).to_string()).or_default() += 1;
        }
    }

    pub fn finish(&mut self) {
        self.hit_texts_per_thousand = ratio(self.texts_with_hits * 1000, self.texts_scanned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_match_hand_computation() {
        let mut confusion = Confusion::default();
        for _ in 0..3 {
            confusion.record(true, true);
        }
        confusion.record(false, true);
        confusion.record(true, false);
        for _ in 0..5 {
            confusion.record(false, false);
        }
        let scores = confusion.scores();
        assert_eq!(scores.precision, Some(0.75));
        assert_eq!(scores.recall, Some(0.75));
        assert_eq!(scores.f1, Some(0.75));
        assert_eq!(scores.accuracy, Some(0.8));
        assert_eq!(scores.base_rate, Some(0.4));
        let baseline = scores.always_flag_f1.unwrap();
        assert!((baseline - 0.8 / 1.4).abs() < 1e-12);
    }

    #[test]
    fn empty_confusion_has_no_scores() {
        let scores = Confusion::default().scores();
        assert_eq!(scores.precision, None);
        assert_eq!(scores.f1, None);
    }

    #[test]
    fn cwe_and_rule_breakdown() {
        let mut metrics = VulnerabilityMetrics::default();
        let cwe79: BTreeSet<String> = ["CWE-79".to_string()].into();
        let rule: BTreeSet<String> = ["web.xss".to_string()].into();
        metrics.record("PHP", true, &cwe79, &rule, &cwe79);
        metrics.record("PHP", true, &cwe79, &BTreeSet::new(), &BTreeSet::new());
        metrics.record("PHP", false, &BTreeSet::new(), &rule, &cwe79);
        metrics.finish();
        let cwe = &metrics.by_cwe["CWE-79"];
        assert_eq!((cwe.vulnerable_samples, cwe.matched_cwe), (2, 1));
        assert_eq!(cwe.recall_same_cwe, Some(0.5));
        assert_eq!(metrics.by_rule["web.xss"].precision, Some(0.5));
        assert_eq!(metrics.by_language["PHP"].confusion.total(), 3);
    }
}

//! High-performance pattern matching for OpenLabels.
//!
//! This module provides a Rust-based pattern matcher that uses RegexSet
//! for parallel pattern matching and Rayon for batch processing.

use pyo3::prelude::*;
use pyo3::types::PyList;
use regex::{Regex, RegexSet};
use rayon::prelude::*;
use std::collections::HashMap;

mod validators;
mod patterns;

use validators::*;
use patterns::BUILTIN_PATTERNS;

/// A single match result.
#[pyclass]
#[derive(Clone)]
pub struct RawMatch {
    #[pyo3(get)]
    pub pattern_name: String,
    #[pyo3(get)]
    pub start: usize,
    #[pyo3(get)]
    pub end: usize,
    #[pyo3(get)]
    pub matched_text: String,
    #[pyo3(get)]
    pub confidence: f64,
    #[pyo3(get)]
    pub validator: Option<String>,
}

#[pymethods]
impl RawMatch {
    fn __repr__(&self) -> String {
        format!(
            "RawMatch(pattern='{}', start={}, end={}, confidence={:.2})",
            self.pattern_name, self.start, self.end, self.confidence
        )
    }
}

/// Pattern definition for the matcher.
#[derive(Clone)]
struct PatternInfo {
    name: String,
    regex: Regex,
    validator: Option<String>,
    base_confidence: f64,
}

/// High-performance pattern matcher using RegexSet and Rayon.
#[pyclass]
pub struct PatternMatcher {
    regex_set: RegexSet,
    patterns: Vec<PatternInfo>,
}

#[pymethods]
impl PatternMatcher {
    /// Create a new PatternMatcher with the given patterns.
    ///
    /// Args:
    ///     patterns: List of (name, regex, validator, confidence) tuples
    #[new]
    fn new(patterns: Vec<(String, String, Option<String>, f64)>) -> PyResult<Self> {
        let mut regex_patterns = Vec::new();
        let mut pattern_infos = Vec::new();

        for (name, pattern, validator, confidence) in patterns {
            let regex = Regex::new(&pattern).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid regex for pattern '{}': {}",
                    name, e
                ))
            })?;
            regex_patterns.push(pattern.clone());
            pattern_infos.push(PatternInfo {
                name,
                regex,
                validator,
                base_confidence: confidence,
            });
        }

        let regex_set = RegexSet::new(&regex_patterns).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Failed to build RegexSet: {}", e))
        })?;

        Ok(PatternMatcher {
            regex_set,
            patterns: pattern_infos,
        })
    }

    /// Create a matcher with built-in patterns.
    #[staticmethod]
    fn with_builtin_patterns() -> PyResult<Self> {
        let patterns: Vec<(String, String, Option<String>, f64)> = BUILTIN_PATTERNS
            .iter()
            .map(|(name, pattern, validator, conf)| {
                (
                    name.to_string(),
                    pattern.to_string(),
                    validator.map(|s| s.to_string()),
                    *conf,
                )
            })
            .collect();
        PatternMatcher::new(patterns)
    }

    /// Find all matches in a single text.
    fn find_matches(&self, text: &str) -> Vec<RawMatch> {
        let matching_patterns: Vec<usize> = self.regex_set.matches(text).into_iter().collect();

        let mut results = Vec::new();

        for pattern_idx in matching_patterns {
            let pattern = &self.patterns[pattern_idx];

            for mat in pattern.regex.find_iter(text) {
                let matched_text = mat.as_str().to_string();

                // Run validator if specified
                let (is_valid, confidence_boost) = match &pattern.validator {
                    Some(v) => validate(&matched_text, v),
                    None => (true, 0.0),
                };

                if is_valid {
                    let confidence = (pattern.base_confidence + confidence_boost).min(1.0);
                    results.push(RawMatch {
                        pattern_name: pattern.name.clone(),
                        start: mat.start(),
                        end: mat.end(),
                        matched_text: matched_text.clone(),
                        confidence,
                        validator: pattern.validator.clone(),
                    });
                }
            }
        }

        results
    }

    /// Find all matches in multiple texts (parallel via Rayon).
    ///
    /// This is the main entry point for batch processing.
    fn find_matches_batch(&self, py: Python, texts: Vec<&str>) -> Vec<Vec<RawMatch>> {
        py.allow_threads(|| {
            texts
                .par_iter()
                .map(|text| self.find_matches_single(text))
                .collect()
        })
    }

    /// Internal method for single text matching (used by batch).
    fn find_matches_single(&self, text: &str) -> Vec<RawMatch> {
        self.find_matches(text)
    }

    /// Get the number of patterns loaded.
    fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Get the names of all loaded patterns.
    fn pattern_names(&self) -> Vec<String> {
        self.patterns.iter().map(|p| p.name.clone()).collect()
    }
}

/// Run a validator and return (is_valid, confidence_boost).
fn validate(text: &str, validator: &str) -> (bool, f64) {
    match validator {
        "luhn" => {
            if validate_luhn(text) {
                (true, 0.15) // Boost confidence for Luhn-valid numbers
            } else {
                (false, 0.0)
            }
        }
        "ssn" => {
            if validate_ssn(text) {
                (true, 0.10)
            } else {
                (false, 0.0)
            }
        }
        "phone" => {
            if validate_phone(text) {
                (true, 0.05)
            } else {
                (false, 0.0)
            }
        }
        "email" => {
            if validate_email(text) {
                (true, 0.05)
            } else {
                (false, 0.0)
            }
        }
        "ipv4" => {
            if validate_ipv4(text) {
                (true, 0.05)
            } else {
                (false, 0.0)
            }
        }
        "iban" => {
            if validate_iban(text) {
                (true, 0.15)
            } else {
                (false, 0.0)
            }
        }
        "npi" => {
            if validate_npi(text) {
                (true, 0.15)
            } else {
                (false, 0.0)
            }
        }
        "cusip" => {
            if validate_cusip(text) {
                (true, 0.15)
            } else {
                (false, 0.0)
            }
        }
        "isin" => {
            if validate_isin(text) {
                (true, 0.15)
            } else {
                (false, 0.0)
            }
        }
        _ => (true, 0.0), // Unknown validator - pass through
    }
}

/// Python module initialization.
#[pymodule]
fn openlabels_matcher(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RawMatch>()?;
    m.add_class::<PatternMatcher>()?;
    Ok(())
}

//! Pattern matching engine using Rust's regex crate
//!
//! Compiles all patterns once and reuses them across scans.
//! Uses RegexSet for efficient multi-pattern matching.
//! Supports batch processing with parallel execution via Rayon.

use aho_corasick::AhoCorasick;
use once_cell::sync::OnceCell;
use pyo3::prelude::*;
use rayon::prelude::*;
use regex::{Regex, RegexSet, RegexSetBuilder};
use std::collections::HashMap;

/// Global compiled patterns (initialized once, reused forever)
static COMPILED_PATTERNS: OnceCell<CompiledPatterns> = OnceCell::new();

/// Holds compiled regex patterns and metadata
struct CompiledPatterns {
    /// RegexSet for fast "which patterns match?" check
    regex_set: RegexSet,
    /// Individual compiled regexes for position extraction
    individual_regexes: Vec<Regex>,
    /// Pattern metadata (entity_type, confidence, group_idx)
    metadata: Vec<PatternMetadata>,
    /// Map from pattern index to metadata index (for failed compilations)
    index_map: HashMap<usize, usize>,
    /// Aho-Corasick automaton for fast literal pre-filtering
    /// Contains common literals like "@", ".", "-" that most patterns need
    prefilter: Option<AhoCorasick>,
}

#[derive(Clone)]
struct PatternMetadata {
    entity_type: String,
    confidence: f32,
    group_idx: usize,
}

/// A raw match from pattern matching (before Python-side validation)
#[pyclass]
#[derive(Clone)]
pub struct RawMatch {
    #[pyo3(get)]
    pub pattern_id: usize,
    #[pyo3(get)]
    pub start: usize,
    #[pyo3(get)]
    pub end: usize,
    #[pyo3(get)]
    pub text: String,
    #[pyo3(get)]
    pub entity_type: String,
    #[pyo3(get)]
    pub confidence: f32,
}

#[pymethods]
impl RawMatch {
    fn __repr__(&self) -> String {
        format!(
            "RawMatch(type={}, text='{}', pos={}:{})",
            self.entity_type, self.text, self.start, self.end
        )
    }
}

/// High-performance pattern matcher using Rust regex
#[pyclass]
pub struct PatternMatcher {
    /// Number of successfully compiled patterns
    pattern_count: usize,
    /// Number of patterns that failed to compile
    failed_count: usize,
}

#[pymethods]
impl PatternMatcher {
    /// Create a new matcher, compiling patterns if not already done
    ///
    /// Args:
    ///     patterns: List of (regex_str, entity_type, confidence, group_idx) tuples
    ///
    /// Returns:
    ///     PatternMatcher instance
    #[new]
    fn new(patterns: Vec<(String, String, f32, usize)>) -> PyResult<Self> {
        let compiled = COMPILED_PATTERNS.get_or_init(|| compile_patterns(&patterns));

        Ok(Self {
            pattern_count: compiled.individual_regexes.len(),
            failed_count: patterns.len() - compiled.individual_regexes.len(),
        })
    }

    /// Get number of successfully compiled patterns
    #[getter]
    fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Get number of patterns that failed to compile
    #[getter]
    fn failed_count(&self) -> usize {
        self.failed_count
    }

    /// Find all pattern matches in text
    ///
    /// This method releases the GIL during execution, allowing other
    /// Python threads to run concurrently.
    ///
    /// Args:
    ///     text: The text to scan
    ///
    /// Returns:
    ///     List of RawMatch objects
    fn find_matches(&self, py: Python<'_>, text: &str) -> PyResult<Vec<RawMatch>> {
        // Release the GIL during the heavy lifting
        py.allow_threads(|| {
            let compiled = COMPILED_PATTERNS.get().expect("Patterns not initialized");
            find_matches_impl(compiled, text)
        })
    }

    /// Check if a specific pattern index is available
    fn has_pattern(&self, index: usize) -> bool {
        COMPILED_PATTERNS
            .get()
            .map(|c| c.index_map.contains_key(&index))
            .unwrap_or(false)
    }

    /// Find matches in multiple texts in parallel (batch API)
    ///
    /// Processes texts concurrently using Rayon's parallel iterator.
    /// Significantly faster than calling find_matches() repeatedly.
    ///
    /// Args:
    ///     texts: List of texts to scan
    ///
    /// Returns:
    ///     List of lists of RawMatch objects (one per input text)
    fn find_matches_batch(&self, py: Python<'_>, texts: Vec<String>) -> PyResult<Vec<Vec<RawMatch>>> {
        Ok(py.allow_threads(|| {
            let compiled = COMPILED_PATTERNS.get().expect("Patterns not initialized");

            // Process texts in parallel
            texts
                .par_iter()
                .map(|text| find_matches_impl(compiled, text.as_str()).unwrap_or_default())
                .collect::<Vec<Vec<RawMatch>>>()
        }))
    }

    /// Quick check if text likely contains any patterns (pre-filter)
    ///
    /// Uses Aho-Corasick to quickly check for common pattern literals
    /// before running full regex matching. Can skip texts that definitely
    /// won't match any patterns.
    ///
    /// Args:
    ///     text: The text to check
    ///
    /// Returns:
    ///     True if text might contain patterns, False if definitely not
    fn might_contain_patterns(&self, py: Python<'_>, text: &str) -> bool {
        py.allow_threads(|| {
            let compiled = COMPILED_PATTERNS.get().expect("Patterns not initialized");
            match &compiled.prefilter {
                Some(ac) => ac.is_match(text),
                None => true, // No prefilter, assume might match
            }
        })
    }
}

/// Compile all patterns into RegexSet and individual Regexes
fn compile_patterns(patterns: &[(String, String, f32, usize)]) -> CompiledPatterns {
    let mut successful_patterns: Vec<String> = Vec::new();
    let mut individual_regexes: Vec<Regex> = Vec::new();
    let mut metadata: Vec<PatternMetadata> = Vec::new();
    let mut index_map: HashMap<usize, usize> = HashMap::new();

    for (original_idx, (pattern_str, entity_type, confidence, group_idx)) in patterns.iter().enumerate() {
        // Try to compile the pattern
        match Regex::new(pattern_str) {
            Ok(regex) => {
                let new_idx = successful_patterns.len();
                index_map.insert(original_idx, new_idx);
                successful_patterns.push(pattern_str.clone());
                individual_regexes.push(regex);
                metadata.push(PatternMetadata {
                    entity_type: entity_type.clone(),
                    confidence: *confidence,
                    group_idx: *group_idx,
                });
            }
            Err(_e) => {
                // Pattern failed to compile - will be handled by Python fallback
                // eprintln!("Pattern {} failed: {}", original_idx, e);
            }
        }
    }

    // Build RegexSet from successful patterns with increased size limit
    let regex_set = RegexSetBuilder::new(&successful_patterns)
        .size_limit(50 * 1024 * 1024)  // 50MB limit (default is 10MB)
        .build()
        .expect("Failed to build RegexSet");

    // Build Aho-Corasick prefilter for common pattern literals
    // These are characters/strings that must appear for patterns to match
    let prefilter_patterns = [
        "@",     // Emails
        "-",     // SSNs, phone numbers, dates
        ".",     // Emails, IPs
        "/",     // Dates, paths
        ":",     // Times, IPs
        " ",     // Names, addresses (whitespace between words)
    ];
    let prefilter = AhoCorasick::builder()
        .build(&prefilter_patterns)
        .ok();

    CompiledPatterns {
        regex_set,
        individual_regexes,
        metadata,
        index_map,
        prefilter,
    }
}

/// Find all matches in text using compiled patterns
fn find_matches_impl(compiled: &CompiledPatterns, text: &str) -> PyResult<Vec<RawMatch>> {
    let mut matches = Vec::new();

    // Fast check: which patterns match anywhere in text?
    let matching_indices: Vec<usize> = compiled.regex_set.matches(text).into_iter().collect();

    // For each matching pattern, find actual positions
    for set_idx in matching_indices {
        let regex = &compiled.individual_regexes[set_idx];
        let meta = &compiled.metadata[set_idx];

        // Use captures if we need a specific group, otherwise find_iter is faster
        if meta.group_idx > 0 {
            // Need to extract a specific capture group
            for caps in regex.captures_iter(text) {
                if let Some(group_match) = caps.get(meta.group_idx) {
                    let matched_text = group_match.as_str();
                    if !matched_text.is_empty() && !matched_text.trim().is_empty() {
                        matches.push(RawMatch {
                            pattern_id: set_idx,
                            start: group_match.start(),
                            end: group_match.end(),
                            text: matched_text.to_string(),
                            entity_type: meta.entity_type.clone(),
                            confidence: meta.confidence,
                        });
                    }
                }
            }
        } else {
            // Use faster find_iter when we want the entire match
            for m in regex.find_iter(text) {
                let matched_text = m.as_str();
                if !matched_text.is_empty() && !matched_text.trim().is_empty() {
                    matches.push(RawMatch {
                        pattern_id: set_idx,
                        start: m.start(),
                        end: m.end(),
                        text: matched_text.to_string(),
                        entity_type: meta.entity_type.clone(),
                        confidence: meta.confidence,
                    });
                }
            }
        }
    }

    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_compilation() {
        let patterns = vec![
            (r"\d{3}-\d{2}-\d{4}".to_string(), "SSN".to_string(), 0.95, 0),
            (r"\d{16}".to_string(), "CREDIT_CARD".to_string(), 0.90, 0),
            (r"[a-z]+@[a-z]+\.[a-z]+".to_string(), "EMAIL".to_string(), 0.95, 0),
        ];

        let compiled = compile_patterns(&patterns);
        assert_eq!(compiled.individual_regexes.len(), 3);
    }

    #[test]
    fn test_find_matches() {
        let patterns = vec![
            (r"\d{3}-\d{2}-\d{4}".to_string(), "SSN".to_string(), 0.95, 0),
            (r"\b[a-z]+@[a-z]+\.[a-z]+\b".to_string(), "EMAIL".to_string(), 0.95, 0),
        ];

        let compiled = compile_patterns(&patterns);
        let text = "SSN: 123-45-6789, email: test@example.com";
        let matches = find_matches_impl(&compiled, text).unwrap();

        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_capture_groups() {
        let patterns = vec![
            // Pattern with capture group 1 - extract just the SSN digits
            (r"SSN:\s*(\d{3}-\d{2}-\d{4})".to_string(), "SSN".to_string(), 0.95, 1),
        ];

        let compiled = compile_patterns(&patterns);
        let text = "SSN: 123-45-6789";
        let matches = find_matches_impl(&compiled, text).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].text, "123-45-6789");
        assert_eq!(matches[0].start, 5);  // Position of "123" after "SSN: "
    }
}

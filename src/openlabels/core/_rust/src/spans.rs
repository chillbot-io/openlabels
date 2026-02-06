//! Span overlap detection and deduplication.
//!
//! Replaces O(n²) nested loop in span_validation.py with O(n log n)
//! sort-and-sweep algorithm. Uses Rayon for batch processing.

use pyo3::prelude::*;
use rayon::prelude::*;

/// Check for overlapping spans using sort-and-sweep O(n log n).
///
/// Args:
///     spans: List of (start, end) tuples
///     allow_identical: If True, spans at exact same position are OK
///
/// Returns:
///     List of (index_i, index_j) pairs that overlap
#[pyfunction]
#[pyo3(signature = (spans, allow_identical = true))]
pub fn check_overlaps(spans: Vec<(usize, usize)>, allow_identical: bool) -> Vec<(usize, usize)> {
    if spans.len() < 2 {
        return vec![];
    }

    // Create index array and sort by (start, end)
    let mut indices: Vec<usize> = (0..spans.len()).collect();
    indices.sort_by(|&a, &b| {
        spans[a].0.cmp(&spans[b].0).then(spans[a].1.cmp(&spans[b].1))
    });

    let mut overlaps = Vec::new();

    for i in 0..indices.len() {
        let idx_i = indices[i];
        let (start_i, end_i) = spans[idx_i];

        for j in (i + 1)..indices.len() {
            let idx_j = indices[j];
            let (start_j, end_j) = spans[idx_j];

            // Since sorted by start, start_j >= start_i
            // No overlap if start_j >= end_i
            if start_j >= end_i {
                break;
            }

            // Found overlap
            if allow_identical && start_i == start_j && end_i == end_j {
                continue;
            }

            // Return original indices (smaller first)
            let pair = if idx_i < idx_j {
                (idx_i, idx_j)
            } else {
                (idx_j, idx_i)
            };
            overlaps.push(pair);
        }
    }

    overlaps
}

/// Deduplicate spans by selecting the highest-confidence span for each position.
///
/// For spans that overlap, keeps the one with higher confidence.
/// If confidence is equal, keeps the longer span.
///
/// Args:
///     spans: List of (start, end, entity_type, confidence) tuples
///
/// Returns:
///     List of indices to keep (into the original spans list)
#[pyfunction]
pub fn deduplicate_spans(spans: Vec<(usize, usize, String, f64)>) -> Vec<usize> {
    if spans.is_empty() {
        return vec![];
    }
    if spans.len() == 1 {
        return vec![0];
    }

    // Sort by (start, end) with index tracking
    let mut indices: Vec<usize> = (0..spans.len()).collect();
    indices.sort_by(|&a, &b| {
        spans[a].0.cmp(&spans[b].0).then(spans[a].1.cmp(&spans[b].1))
    });

    let mut keep = vec![true; spans.len()];

    for i in 0..indices.len() {
        if !keep[indices[i]] {
            continue;
        }
        let idx_i = indices[i];
        let (start_i, end_i, _, conf_i) = &spans[idx_i];

        for j in (i + 1)..indices.len() {
            let idx_j = indices[j];
            let (start_j, end_j, _, conf_j) = &spans[idx_j];

            // No overlap possible
            if *start_j >= *end_i {
                break;
            }

            if !keep[idx_j] {
                continue;
            }

            // Overlap detected - keep the better one
            if conf_j > conf_i || (conf_j == conf_i && (end_j - start_j) > (end_i - start_i)) {
                keep[idx_i] = false;
                break; // idx_i is removed, no need to check more
            } else {
                keep[idx_j] = false;
            }
        }
    }

    (0..spans.len()).filter(|&i| keep[i]).collect()
}

/// Batch overlap check: process multiple span groups in parallel.
///
/// Args:
///     span_groups: List of span lists, each being a list of (start, end) tuples
///     allow_identical: If True, identical-position spans are OK
///
/// Returns:
///     List of overlap lists, one per input group
#[pyfunction]
#[pyo3(signature = (span_groups, allow_identical = true))]
pub fn batch_overlap_check(
    py: Python,
    span_groups: Vec<Vec<(usize, usize)>>,
    allow_identical: bool,
) -> Vec<Vec<(usize, usize)>> {
    py.allow_threads(|| {
        span_groups
            .par_iter()
            .map(|group| check_overlaps(group.clone(), allow_identical))
            .collect()
    })
}

/// Batch deduplication: process multiple span groups in parallel.
///
/// Args:
///     span_groups: List of span lists, each being (start, end, entity_type, confidence)
///
/// Returns:
///     List of index lists (indices to keep), one per input group
#[pyfunction]
pub fn batch_deduplicate(
    py: Python,
    span_groups: Vec<Vec<(usize, usize, String, f64)>>,
) -> Vec<Vec<usize>> {
    py.allow_threads(|| {
        span_groups
            .par_iter()
            .map(|group| deduplicate_spans(group.clone()))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_overlaps() {
        let spans = vec![(0, 5), (5, 10), (10, 15)];
        let result = check_overlaps(spans, true);
        assert!(result.is_empty());
    }

    #[test]
    fn test_simple_overlap() {
        let spans = vec![(0, 10), (5, 15)];
        let result = check_overlaps(spans, true);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (0, 1));
    }

    #[test]
    fn test_identical_allowed() {
        let spans = vec![(0, 10), (0, 10)];
        let result = check_overlaps(spans, true);
        assert!(result.is_empty());
    }

    #[test]
    fn test_identical_not_allowed() {
        let spans = vec![(0, 10), (0, 10)];
        let result = check_overlaps(spans, false);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dedup_by_confidence() {
        let spans = vec![
            (0, 10, "SSN".to_string(), 0.85),
            (5, 15, "SSN".to_string(), 0.99),
        ];
        let keep = deduplicate_spans(spans);
        // Should keep index 1 (higher confidence)
        assert_eq!(keep, vec![1]);
    }

    #[test]
    fn test_dedup_no_overlap() {
        let spans = vec![
            (0, 5, "SSN".to_string(), 0.99),
            (5, 10, "EMAIL".to_string(), 0.95),
        ];
        let keep = deduplicate_spans(spans);
        assert_eq!(keep, vec![0, 1]);
    }

    #[test]
    fn test_dedup_equal_confidence_keep_longer() {
        let spans = vec![
            (0, 5, "SSN".to_string(), 0.99),
            (0, 10, "SSN".to_string(), 0.99),
        ];
        let keep = deduplicate_spans(spans);
        // Should keep index 1 (longer span)
        assert_eq!(keep, vec![1]);
    }
}

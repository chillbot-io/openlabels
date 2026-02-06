//! High-performance file filtering for enumeration.
//!
//! Replaces Python's per-file fnmatch loop with:
//! - HashSet for O(1) extension lookup
//! - Pre-compiled glob patterns
//! - Rayon for batch filtering
//!
//! With 100K files and 12 patterns, this eliminates ~2.4M fnmatch calls.

use pyo3::prelude::*;
use rayon::prelude::*;
use std::collections::HashSet;

/// A single compiled glob pattern stored as segments for matching.
/// We implement a simplified glob matcher that handles *, ?, and literal segments
/// which covers the patterns used by FilterConfig (e.g., ".git/*", "*.egg-info/*").
#[derive(Clone, Debug)]
struct GlobPattern {
    /// Lowercased pattern for case-insensitive matching
    lower: String,
}

impl GlobPattern {
    fn new(pattern: &str) -> Self {
        GlobPattern {
            lower: pattern.to_lowercase(),
        }
    }

    /// Simple glob match supporting * and ? wildcards.
    fn matches(&self, text: &str) -> bool {
        glob_match(&self.lower, &text.to_lowercase())
    }
}

/// Simple glob matching (supports * and ? only, no character classes).
/// Operates on byte slices for performance.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < txt.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == txt[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }

    pi == pat.len()
}

/// High-performance file filter with pre-compiled patterns.
#[pyclass]
#[derive(Clone)]
pub struct FileFilter {
    /// Extensions to exclude (lowercase, no dot), stored in HashSet for O(1) lookup
    exclude_extensions: HashSet<String>,
    /// Compiled glob patterns to exclude
    exclude_patterns: Vec<GlobPattern>,
    /// Accounts to exclude (lowercase)
    exclude_accounts: Vec<String>,
    /// Account patterns (with wildcards)
    exclude_account_patterns: Vec<GlobPattern>,
    /// Size limits
    min_size: Option<i64>,
    max_size: Option<i64>,
}

#[pymethods]
impl FileFilter {
    /// Create a new FileFilter.
    ///
    /// Args:
    ///     exclude_extensions: List of extensions to exclude (without dot, case-insensitive)
    ///     exclude_patterns: List of glob patterns to exclude
    ///     exclude_accounts: List of accounts to exclude (exact or glob)
    ///     min_size: Minimum file size in bytes (None = no limit)
    ///     max_size: Maximum file size in bytes (None = no limit)
    #[new]
    #[pyo3(signature = (exclude_extensions, exclude_patterns, exclude_accounts, min_size = None, max_size = None))]
    fn new(
        exclude_extensions: Vec<String>,
        exclude_patterns: Vec<String>,
        exclude_accounts: Vec<String>,
        min_size: Option<i64>,
        max_size: Option<i64>,
    ) -> Self {
        let ext_set: HashSet<String> = exclude_extensions
            .into_iter()
            .map(|e| e.to_lowercase().trim_start_matches('.').to_string())
            .collect();

        let patterns: Vec<GlobPattern> = exclude_patterns
            .iter()
            .map(|p| GlobPattern::new(p))
            .collect();

        let mut exact_accounts = Vec::new();
        let mut account_patterns = Vec::new();
        for acct in exclude_accounts {
            if acct.contains('*') || acct.contains('?') {
                account_patterns.push(GlobPattern::new(&acct));
            } else {
                exact_accounts.push(acct.to_lowercase());
            }
        }

        FileFilter {
            exclude_extensions: ext_set,
            exclude_patterns: patterns,
            exclude_accounts: exact_accounts,
            exclude_account_patterns: account_patterns,
            min_size,
            max_size,
        }
    }

    /// Check if a single file should be included.
    ///
    /// Args:
    ///     name: File name (e.g., "report.pdf")
    ///     path: Full file path
    ///     owner: Optional file owner/account
    ///     size: File size in bytes
    ///
    /// Returns:
    ///     True if file passes all filters
    #[pyo3(signature = (name, path, owner = None, size = 0))]
    fn should_include(&self, name: &str, path: &str, owner: Option<&str>, size: i64) -> bool {
        self.check_include(name, path, owner, size)
    }

    /// Filter a batch of files in parallel using Rayon.
    ///
    /// Args:
    ///     files: List of (name, path, owner_or_empty, size) tuples
    ///
    /// Returns:
    ///     List of booleans, True if file should be included
    fn filter_batch(&self, py: Python, files: Vec<(String, String, String, i64)>) -> Vec<bool> {
        let filter = self.clone();
        py.allow_threads(move || {
            files
                .par_iter()
                .map(|(name, path, owner, size)| {
                    let owner_opt = if owner.is_empty() { None } else { Some(owner.as_str()) };
                    filter.check_include(name, path, owner_opt, *size)
                })
                .collect()
        })
    }

    /// Get the number of excluded extensions.
    fn extension_count(&self) -> usize {
        self.exclude_extensions.len()
    }

    /// Get the number of exclude patterns.
    fn pattern_count(&self) -> usize {
        self.exclude_patterns.len()
    }
}

impl FileFilter {
    /// Internal include check (not exposed to Python, used by both single and batch).
    fn check_include(&self, name: &str, path: &str, owner: Option<&str>, size: i64) -> bool {
        // Check extension (O(1) HashSet lookup)
        if !self.exclude_extensions.is_empty() {
            if let Some(dot_pos) = name.rfind('.') {
                let ext = name[dot_pos + 1..].to_lowercase();
                if self.exclude_extensions.contains(&ext) {
                    return false;
                }
            }
        }

        // Check path patterns
        let path_lower = path.to_lowercase();
        for pattern in &self.exclude_patterns {
            // Direct match
            if pattern.matches(&path_lower) {
                return false;
            }
            // Also check with */ prefix (matches any parent path component)
            let prefixed = format!("*/{}", pattern.lower);
            if glob_match(&prefixed, &path_lower) {
                return false;
            }
        }

        // Check account exclusion
        if let Some(owner_str) = owner {
            let owner_lower = owner_str.to_lowercase();
            // Exact match
            if self.exclude_accounts.contains(&owner_lower) {
                return false;
            }
            // Pattern match
            for pattern in &self.exclude_account_patterns {
                if pattern.matches(&owner_lower) {
                    return false;
                }
            }
        }

        // Check size limits
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*.txt", "hello.txt"));
        assert!(glob_match(".git/*", ".git/config"));
        assert!(glob_match("*/.git/*", "repo/.git/config"));
        assert!(!glob_match("*.txt", "hello.pdf"));
        assert!(glob_match("node_modules/*", "node_modules/express/index.js"));
    }

    #[test]
    fn test_extension_filter() {
        let filter = FileFilter::new(
            vec!["tmp".to_string(), "pyc".to_string()],
            vec![],
            vec![],
            None,
            None,
        );
        assert!(!filter.check_include("test.tmp", "/data/test.tmp", None, 100));
        assert!(!filter.check_include("mod.pyc", "/data/mod.pyc", None, 100));
        assert!(filter.check_include("doc.pdf", "/data/doc.pdf", None, 100));
    }

    #[test]
    fn test_pattern_filter() {
        let filter = FileFilter::new(
            vec![],
            vec![".git/*".to_string(), "node_modules/*".to_string()],
            vec![],
            None,
            None,
        );
        assert!(!filter.check_include("config", "repo/.git/config", None, 100));
        assert!(!filter.check_include("index.js", "project/node_modules/express/index.js", None, 100));
        assert!(filter.check_include("main.py", "project/src/main.py", None, 100));
    }

    #[test]
    fn test_size_filter() {
        let filter = FileFilter::new(
            vec![],
            vec![],
            vec![],
            Some(100),
            Some(10_000_000),
        );
        assert!(!filter.check_include("tiny.txt", "/data/tiny.txt", None, 50));
        assert!(filter.check_include("normal.txt", "/data/normal.txt", None, 1000));
        assert!(!filter.check_include("huge.bin", "/data/huge.bin", None, 20_000_000));
    }
}

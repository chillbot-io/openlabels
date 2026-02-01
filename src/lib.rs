//! OpenLabels Native Rust Extension
//!
//! Provides high-performance pattern matching using Rust's regex crate.
//! Releases the GIL during scanning, enabling true parallelism with Python threads.
//! Includes validation functions that run at native speed.

use pyo3::prelude::*;

mod matcher;
mod validators;

use matcher::{PatternMatcher, RawMatch};

/// OpenLabels native extension module
#[pymodule]
fn _rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PatternMatcher>()?;
    m.add_class::<RawMatch>()?;

    // Validation functions
    m.add_function(wrap_pyfunction!(validate_luhn, m)?)?;
    m.add_function(wrap_pyfunction!(validate_ssn_format, m)?)?;
    m.add_function(wrap_pyfunction!(validate_phone_format, m)?)?;
    m.add_function(wrap_pyfunction!(validate_ipv4_format, m)?)?;
    m.add_function(wrap_pyfunction!(is_private_ip, m)?)?;

    // Utility
    m.add_function(wrap_pyfunction!(is_native_available, m)?)?;
    Ok(())
}

/// Validate credit card number using Luhn algorithm
#[pyfunction]
fn validate_luhn(number: &str) -> bool {
    validators::luhn(number)
}

/// Validate SSN format (not context)
#[pyfunction]
fn validate_ssn_format(ssn: &str) -> bool {
    validators::ssn_format(ssn)
}

/// Validate US phone number format
#[pyfunction]
fn validate_phone_format(phone: &str) -> bool {
    validators::phone_format(phone)
}

/// Validate IPv4 address format
#[pyfunction]
fn validate_ipv4_format(ip: &str) -> bool {
    validators::ipv4_format(ip)
}

/// Check if IP is private/reserved (likely false positive)
#[pyfunction]
fn is_private_ip(ip: &str) -> bool {
    validators::is_private_ip(ip)
}

/// Check if native extension is working
#[pyfunction]
fn is_native_available() -> bool {
    true
}

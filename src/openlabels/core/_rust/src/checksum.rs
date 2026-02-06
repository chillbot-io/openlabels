//! Checksum validators returning (valid, confidence) tuples.
//!
//! These mirror the Python checksum.py validators but return graduated
//! confidence scores matching the Python API contract.

use pyo3::prelude::*;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref DIGITS_ONLY: Regex = Regex::new(r"[^0-9]").unwrap();
    static ref ASCII_DIGITS_SEPS: Regex = Regex::new(r"^[0-9\- ]+$").unwrap();
}

/// Strip non-digit characters from a string.
fn extract_digits(text: &str) -> String {
    text.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Luhn algorithm check (used internally by multiple validators).
fn luhn_check(digits: &[u32]) -> bool {
    if digits.len() < 2 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

/// Luhn check on a string of digits.
fn luhn_check_str(text: &str) -> bool {
    let digits: Vec<u32> = text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    luhn_check(&digits)
}

// =============================================================================
// PyO3-exported checksum validators
// =============================================================================

/// Validate SSN with graduated confidence.
/// Returns (is_valid, confidence).
///   0.99: Fully valid SSN
///   0.85: Invalid area code but valid structure
///   0.80: Invalid group/serial but valid format
#[pyfunction]
pub fn checksum_ssn(ssn: &str) -> (bool, f64) {
    let trimmed = ssn.trim();

    // Only accept ASCII digits and standard separators
    if !ASCII_DIGITS_SEPS.is_match(trimmed) {
        return (false, 0.0);
    }

    let digits = extract_digits(trimmed);
    if digits.len() != 9 {
        return (false, 0.0);
    }

    let area = &digits[..3];
    let group = &digits[3..5];
    let serial = &digits[5..];
    let mut confidence: f64 = 0.99;

    // Invalid area numbers (000, 666, 900-999)
    if area == "000" || area == "666" || area.starts_with('9') {
        confidence = 0.85;
    }

    // Invalid group (00)
    if group == "00" {
        confidence = confidence.min(0.80);
    }

    // Invalid serial (0000)
    if serial == "0000" {
        confidence = confidence.min(0.80);
    }

    (true, confidence)
}

/// Validate credit card using Luhn + prefix check.
/// Returns (is_valid, confidence).
///   0.99: Valid prefix AND valid Luhn
///   0.87: Valid prefix but invalid Luhn
#[pyfunction]
pub fn checksum_credit_card(cc: &str) -> (bool, f64) {
    let digits = extract_digits(cc);

    if digits.len() < 13 || digits.len() > 19 {
        return (false, 0.0);
    }

    let prefix2: u32 = digits[..2].parse().unwrap_or(0);
    let prefix3: u32 = if digits.len() >= 3 {
        digits[..3].parse().unwrap_or(0)
    } else {
        0
    };
    let prefix4: u32 = if digits.len() >= 4 {
        digits[..4].parse().unwrap_or(0)
    } else {
        0
    };

    let valid_prefix = digits.starts_with('4')                          // Visa
        || (51..=55).contains(&prefix2)                                  // Mastercard
        || (2221..=2720).contains(&prefix4)                              // Mastercard (new)
        || digits.starts_with("34") || digits.starts_with("37")         // Amex
        || digits.starts_with("6011")                                    // Discover
        || digits.starts_with("65")                                      // Discover
        || (644..=649).contains(&prefix3)                                // Discover
        || digits.starts_with("35")                                      // JCB
        || digits.starts_with("36")                                      // Diners Club
        || (300..=305).contains(&prefix3)                                // Diners Club
        || digits.starts_with("38") || digits.starts_with("39");         // Diners Club

    if !valid_prefix {
        return (false, 0.0);
    }

    if !luhn_check_str(&digits) {
        return (true, 0.87); // Still detect for safety
    }

    (true, 0.99)
}

/// Validate NPI using Luhn with 80840 prefix.
#[pyfunction]
pub fn checksum_npi(npi: &str) -> (bool, f64) {
    let digits = extract_digits(npi);

    if digits.len() != 10 {
        return (false, 0.0);
    }

    let first = digits.chars().next().unwrap_or('0');
    if first != '1' && first != '2' {
        return (false, 0.0);
    }

    let check_str = format!("80840{}", digits);
    if !luhn_check_str(&check_str) {
        return (false, 0.0);
    }

    (true, 0.99)
}

/// Validate DEA number using DEA checksum formula.
/// Format: 2 letters + 7 digits
#[pyfunction]
pub fn checksum_dea(dea: &str) -> (bool, f64) {
    let cleaned: String = dea.to_uppercase().replace(' ', "");

    if cleaned.len() != 9 {
        return (false, 0.0);
    }

    let chars: Vec<char> = cleaned.chars().collect();
    if !chars[0].is_ascii_alphabetic() || !chars[1].is_ascii_alphabetic() {
        return (false, 0.0);
    }

    let digit_str: String = chars[2..].iter().collect();
    if !digit_str.chars().all(|c| c.is_ascii_digit()) {
        return (false, 0.0);
    }

    let d: Vec<u32> = digit_str
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    let checksum = d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5]);
    if checksum % 10 != d[6] {
        return (false, 0.0);
    }

    (true, 0.99)
}

/// Validate IBAN using Mod-97 algorithm.
#[pyfunction]
pub fn checksum_iban(iban: &str) -> (bool, f64) {
    let cleaned: String = iban.to_uppercase().replace(' ', "");

    if cleaned.len() < 15 || cleaned.len() > 34 {
        return (false, 0.0);
    }

    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[..4]);

    let mut numeric = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_alphabetic() {
            numeric.push_str(&((c as u32 - 'A' as u32 + 10).to_string()));
        } else {
            return (false, 0.0);
        }
    }

    // Mod 97 on large number
    let mut remainder = 0u64;
    for c in numeric.chars() {
        if let Some(digit) = c.to_digit(10) {
            remainder = (remainder * 10 + digit as u64) % 97;
        }
    }

    if remainder != 1 {
        return (false, 0.0);
    }

    (true, 0.99)
}

/// Validate VIN using check digit (position 9).
#[pyfunction]
pub fn checksum_vin(vin: &str) -> (bool, f64) {
    let cleaned: String = vin.to_uppercase().replace(' ', "");

    if cleaned.len() != 17 {
        return (false, 0.0);
    }

    if cleaned.contains('I') || cleaned.contains('O') || cleaned.contains('Q') {
        return (false, 0.0);
    }

    let trans = |c: char| -> Option<u32> {
        match c {
            'A' => Some(1), 'B' => Some(2), 'C' => Some(3), 'D' => Some(4),
            'E' => Some(5), 'F' => Some(6), 'G' => Some(7), 'H' => Some(8),
            'J' => Some(1), 'K' => Some(2), 'L' => Some(3), 'M' => Some(4),
            'N' => Some(5), 'P' => Some(7), 'R' => Some(9),
            'S' => Some(2), 'T' => Some(3), 'U' => Some(4), 'V' => Some(5),
            'W' => Some(6), 'X' => Some(7), 'Y' => Some(8), 'Z' => Some(9),
            '0'..='9' => c.to_digit(10),
            _ => None,
        }
    };

    let weights: [u32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let chars: Vec<char> = cleaned.chars().collect();

    let mut total = 0u32;
    for (i, &c) in chars.iter().enumerate() {
        match trans(c) {
            Some(val) => total += val * weights[i],
            None => return (false, 0.0),
        }
    }

    let check = total % 11;
    let check_char = if check == 10 { 'X' } else { char::from_digit(check, 10).unwrap_or('0') };

    if chars[8] != check_char {
        return (false, 0.0);
    }

    (true, 0.99)
}

/// Validate ABA routing number using prefix and checksum.
#[pyfunction]
pub fn checksum_aba_routing(aba: &str) -> (bool, f64) {
    let digits = extract_digits(aba);

    if digits.len() != 9 {
        return (false, 0.0);
    }

    let prefix: u32 = digits[..2].parse().unwrap_or(999);
    let valid_prefix = (0..=12).contains(&prefix)
        || (21..=32).contains(&prefix)
        || (61..=72).contains(&prefix)
        || prefix == 80;

    if !valid_prefix {
        return (false, 0.0);
    }

    let d: Vec<u32> = digits
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    let checksum = 3 * (d[0] + d[3] + d[6])
        + 7 * (d[1] + d[4] + d[7])
        + d[2] + d[5] + d[8];

    if checksum % 10 != 0 {
        return (false, 0.0);
    }

    (true, 0.99)
}

/// Validate UPS tracking number (1Z + 16 alphanumeric).
#[pyfunction]
pub fn checksum_ups_tracking(tracking: &str) -> (bool, f64) {
    let cleaned: String = tracking.to_uppercase().replace(' ', "");

    if !cleaned.starts_with("1Z") || cleaned.len() != 18 {
        return (false, 0.0);
    }

    let letter_val = |c: char| -> Option<u32> {
        match c {
            'A' => Some(2), 'B' => Some(3), 'C' => Some(4), 'D' => Some(5),
            'E' => Some(6), 'F' => Some(7), 'G' => Some(8), 'H' => Some(9),
            'J' => Some(1), 'K' => Some(2), 'L' => Some(3), 'M' => Some(4),
            'N' => Some(5), 'P' => Some(7), 'Q' => Some(8), 'R' => Some(9),
            'S' => Some(1), 'T' => Some(2), 'U' => Some(3), 'V' => Some(4),
            'W' => Some(5), 'X' => Some(6), 'Y' => Some(7), 'Z' => Some(8),
            '0'..='9' => c.to_digit(10),
            _ => None,
        }
    };

    let data = &cleaned[2..];
    let mut values = Vec::new();
    for c in data.chars() {
        match letter_val(c) {
            Some(v) => values.push(v),
            None => return (false, 0.0),
        }
    }

    let mut total = 0u32;
    for (i, &v) in values[..values.len() - 1].iter().enumerate() {
        if i % 2 == 1 {
            total += v * 2;
        } else {
            total += v;
        }
    }

    let expected_check = (10 - (total % 10)) % 10;
    if expected_check != *values.last().unwrap_or(&999) {
        return (false, 0.0);
    }

    (true, 0.99)
}

/// Validate FedEx tracking number (12, 15, 20, or 22 digits).
#[pyfunction]
pub fn checksum_fedex_tracking(tracking: &str) -> (bool, f64) {
    let digits = extract_digits(tracking);

    match digits.len() {
        12 => {
            let weights = [1u32, 7, 3, 1, 7, 3, 1, 7, 3, 1, 7];
            let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
            let total: u32 = d[..11].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
            let check = (total % 11) % 10;
            if check != d[11] {
                return (false, 0.0);
            }
            (true, 0.99)
        }
        15 if digits.starts_with("96") => {
            let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
            let total: u32 = d[..14].iter().sum();
            let check = (10 - (total % 10)) % 10;
            if check != d[14] {
                return (false, 0.0);
            }
            (true, 0.99)
        }
        20 => {
            let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
            let weights: Vec<u32> = (0..19).map(|i| if i % 2 == 0 { 3 } else { 1 }).collect();
            let total: u32 = d[..19].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
            let check = (10 - (total % 10)) % 10;
            if check != d[19] {
                return (false, 0.0);
            }
            (true, 0.99)
        }
        22 if digits.starts_with("92") => {
            let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
            let weights: Vec<u32> = (0..21).map(|i| if i % 2 == 0 { 3 } else { 1 }).collect();
            let total: u32 = d[..21].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
            let check = (10 - (total % 10)) % 10;
            if check != d[21] {
                return (false, 0.0);
            }
            (true, 0.99)
        }
        _ => (false, 0.0),
    }
}

/// Validate USPS tracking number.
#[pyfunction]
pub fn checksum_usps_tracking(tracking: &str) -> (bool, f64) {
    let cleaned: String = tracking.to_uppercase().replace(' ', "");

    // International format: 2 letters + 9 digits + 2 letters
    if cleaned.len() == 13 {
        let chars: Vec<char> = cleaned.chars().collect();
        if chars[..2].iter().all(|c| c.is_ascii_alphabetic())
            && chars[11..].iter().all(|c| c.is_ascii_alphabetic())
        {
            let digit_part: String = chars[2..11].iter().collect();
            if !digit_part.chars().all(|c| c.is_ascii_digit()) {
                return (false, 0.0);
            }
            let d: Vec<u32> = digit_part.chars().filter_map(|c| c.to_digit(10)).collect();
            let weights = [8u32, 6, 4, 2, 3, 5, 9, 7];
            let total: u32 = d[..8].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
            let mut check = 11 - (total % 11);
            if check == 10 {
                check = 0;
            } else if check == 11 {
                check = 5;
            }
            if check != d[8] {
                return (false, 0.0);
            }
            return (true, 0.99);
        }
    }

    // Numeric formats
    let digits = extract_digits(&cleaned);
    if digits.len() == 20 || digits.len() == 22 {
        let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
        let len = d.len();
        let weights: Vec<u32> = (0..len - 1).map(|i| if i % 2 == 0 { 3 } else { 1 }).collect();
        let total: u32 = d[..len - 1].iter().zip(weights.iter()).map(|(a, b)| a * b).sum();
        let check = (10 - (total % 10)) % 10;
        if check != d[len - 1] {
            return (false, 0.0);
        }
        return (true, 0.99);
    }

    (false, 0.0)
}

/// Validate CUSIP (9-character security identifier).
#[pyfunction]
pub fn checksum_cusip(cusip: &str) -> (bool, f64) {
    let cleaned: String = cusip
        .to_uppercase()
        .replace(' ', "")
        .replace('-', "");

    if cleaned.len() != 9 {
        return (false, 0.0);
    }

    let chars: Vec<char> = cleaned.chars().collect();
    let mut total = 0u32;

    for (i, &c) in chars[..8].iter().enumerate() {
        let value = if c.is_ascii_digit() {
            c.to_digit(10).unwrap()
        } else if c.is_ascii_alphabetic() {
            c as u32 - 'A' as u32 + 10
        } else if c == '*' {
            36
        } else if c == '@' {
            37
        } else if c == '#' {
            38
        } else {
            return (false, 0.0);
        };

        let v = if i % 2 == 1 { value * 2 } else { value };
        total += v / 10 + v % 10;
    }

    let check = (10 - (total % 10)) % 10;
    match chars[8].to_digit(10) {
        Some(d) if d == check => (true, 0.99),
        _ => (false, 0.0),
    }
}

/// Validate ISIN (12-character international security identifier).
#[pyfunction]
pub fn checksum_isin(isin: &str) -> (bool, f64) {
    let cleaned: String = isin.to_uppercase().replace(' ', "");

    if cleaned.len() != 12 {
        return (false, 0.0);
    }

    let chars: Vec<char> = cleaned.chars().collect();
    if !chars[0].is_ascii_alphabetic() || !chars[1].is_ascii_alphabetic() {
        return (false, 0.0);
    }

    // Convert all chars except last to numeric string
    let mut numeric = String::new();
    for &c in &chars[..11] {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_alphabetic() {
            numeric.push_str(&(c as u32 - 'A' as u32 + 10).to_string());
        } else {
            return (false, 0.0);
        }
    }
    // Append last character
    numeric.push(chars[11]);

    if !luhn_check_str(&numeric) {
        return (false, 0.0);
    }

    (true, 0.99)
}

/// Batch validate: run a named checksum on multiple values.
/// Returns Vec<(bool, f64)>.
#[pyfunction]
pub fn checksum_batch(py: Python, validator_name: &str, values: Vec<String>) -> Vec<(bool, f64)> {
    py.allow_threads(|| {
        use rayon::prelude::*;
        values
            .par_iter()
            .map(|v| match validator_name {
                "ssn" => checksum_ssn(v),
                "credit_card" => checksum_credit_card(v),
                "npi" => checksum_npi(v),
                "dea" => checksum_dea(v),
                "iban" => checksum_iban(v),
                "vin" => checksum_vin(v),
                "aba_routing" => checksum_aba_routing(v),
                "ups_tracking" => checksum_ups_tracking(v),
                "fedex_tracking" => checksum_fedex_tracking(v),
                "usps_tracking" => checksum_usps_tracking(v),
                "cusip" => checksum_cusip(v),
                "isin" => checksum_isin(v),
                _ => (false, 0.0),
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_ssn() {
        // Valid SSN
        let (valid, conf) = checksum_ssn("123-45-6789");
        assert!(valid);
        assert!((conf - 0.99).abs() < 0.001);

        // Invalid area code - still valid but lower confidence
        let (valid, conf) = checksum_ssn("000-12-3456");
        assert!(valid);
        assert!((conf - 0.85).abs() < 0.001);

        // Invalid group
        let (valid, conf) = checksum_ssn("123-00-6789");
        assert!(valid);
        assert!((conf - 0.80).abs() < 0.001);
    }

    #[test]
    fn test_checksum_credit_card() {
        // Valid Visa with Luhn
        let (valid, conf) = checksum_credit_card("4532015112830366");
        assert!(valid);
        assert!((conf - 0.99).abs() < 0.001);

        // Valid Visa prefix but bad Luhn
        let (valid, conf) = checksum_credit_card("4532015112830367");
        assert!(valid);
        assert!((conf - 0.87).abs() < 0.001);

        // Not a valid prefix
        let (valid, _) = checksum_credit_card("1234567890123456");
        assert!(!valid);
    }

    #[test]
    fn test_checksum_iban() {
        let (valid, conf) = checksum_iban("GB82 WEST 1234 5698 7654 32");
        assert!(valid);
        assert!((conf - 0.99).abs() < 0.001);

        let (valid, conf) = checksum_iban("DE89370400440532013000");
        assert!(valid);
        assert!((conf - 0.99).abs() < 0.001);
    }

    #[test]
    fn test_checksum_cusip() {
        // Valid CUSIP: 037833100 (Apple Inc)
        let (valid, conf) = checksum_cusip("037833100");
        assert!(valid);
        assert!((conf - 0.99).abs() < 0.001);
    }
}

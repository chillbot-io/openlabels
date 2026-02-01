//! Validation functions for detected patterns.
//!
//! These validators provide checksum and format validation to reduce
//! false positives in pattern matching.

/// Validate a number using the Luhn algorithm (credit cards, etc.).
pub fn validate_luhn(text: &str) -> bool {
    let digits: Vec<u32> = text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 2 {
        return false;
    }

    let mut sum = 0;
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

/// Validate a US Social Security Number format.
pub fn validate_ssn(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return false;
    }

    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);

    // Invalid area numbers
    if area == 0 || area == 666 || (area >= 900 && area <= 999) {
        return false;
    }

    // Group and serial must be non-zero
    if group == 0 || serial == 0 {
        return false;
    }

    true
}

/// Validate a phone number has reasonable digit count.
pub fn validate_phone(text: &str) -> bool {
    let digits: Vec<char> = text.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.len() >= 10 && digits.len() <= 15
}

/// Validate an email address format.
pub fn validate_email(text: &str) -> bool {
    let parts: Vec<&str> = text.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Basic validation
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

/// Validate an IPv4 address.
pub fn validate_ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    for part in parts {
        match part.parse::<u32>() {
            Ok(n) if n <= 255 => continue,
            _ => return false,
        }
    }

    true
}

/// Validate an IBAN using mod-97 checksum.
pub fn validate_iban(text: &str) -> bool {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }

    // Move first 4 chars to end
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[0..4]);

    // Convert letters to numbers (A=10, B=11, etc.)
    let numeric: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                c.to_string()
            } else {
                ((c as u32) - ('A' as u32) + 10).to_string()
            }
        })
        .collect();

    // Mod 97 check
    mod97(&numeric) == 1
}

/// Calculate mod 97 for large numbers represented as strings.
fn mod97(s: &str) -> u32 {
    let mut remainder = 0u64;
    for c in s.chars() {
        if let Some(digit) = c.to_digit(10) {
            remainder = (remainder * 10 + digit as u64) % 97;
        }
    }
    remainder as u32
}

/// Validate a US National Provider Identifier (NPI).
pub fn validate_npi(text: &str) -> bool {
    let digits: Vec<u32> = text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 10 {
        return false;
    }

    // NPI uses Luhn with prefix 80840
    let prefixed: Vec<u32> = vec![8, 0, 8, 4, 0]
        .into_iter()
        .chain(digits.into_iter())
        .collect();

    let mut sum = 0;
    let mut double = false;

    for &digit in prefixed.iter().rev() {
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

/// Validate a CUSIP (Committee on Uniform Securities Identification Procedures).
pub fn validate_cusip(text: &str) -> bool {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    if cleaned.len() != 9 {
        return false;
    }

    let chars: Vec<char> = cleaned.chars().collect();
    let mut sum = 0;

    for (i, c) in chars[..8].iter().enumerate() {
        let mut val = if c.is_ascii_digit() {
            c.to_digit(10).unwrap()
        } else {
            (*c as u32) - ('A' as u32) + 10
        };

        if i % 2 == 1 {
            val *= 2;
        }

        sum += val / 10 + val % 10;
    }

    let check_digit = (10 - (sum % 10)) % 10;
    chars[8].to_digit(10) == Some(check_digit)
}

/// Validate an ISIN (International Securities Identification Number).
pub fn validate_isin(text: &str) -> bool {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    if cleaned.len() != 12 {
        return false;
    }

    // First two characters must be letters (country code)
    let chars: Vec<char> = cleaned.chars().collect();
    if !chars[0].is_ascii_alphabetic() || !chars[1].is_ascii_alphabetic() {
        return false;
    }

    // Convert to digits (A=10, B=11, etc.)
    let numeric: String = cleaned
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                c.to_string()
            } else {
                ((c as u32) - ('A' as u32) + 10).to_string()
            }
        })
        .collect();

    // Luhn check on the numeric string
    let digits: Vec<u32> = numeric
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();

    let mut sum = 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn() {
        assert!(validate_luhn("4532015112830366")); // Valid Visa
        assert!(!validate_luhn("4532015112830367")); // Invalid
    }

    #[test]
    fn test_ssn() {
        assert!(validate_ssn("123-45-6789"));
        assert!(!validate_ssn("000-12-3456")); // Invalid area
        assert!(!validate_ssn("666-12-3456")); // Invalid area
    }

    #[test]
    fn test_iban() {
        assert!(validate_iban("GB82 WEST 1234 5698 7654 32")); // UK
        assert!(validate_iban("DE89370400440532013000")); // Germany
    }

    #[test]
    fn test_ipv4() {
        assert!(validate_ipv4("192.168.1.1"));
        assert!(!validate_ipv4("256.1.1.1"));
    }
}

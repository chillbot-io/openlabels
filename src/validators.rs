//! Validation functions for detected entities
//!
//! Fast implementations of common validation algorithms.
//! These run in Rust for maximum performance on the hot path.

use memchr::memchr;

/// Validate credit card number using Luhn algorithm
pub fn luhn(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Credit cards are 13-19 digits
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

/// Validate US phone number format
pub fn phone_format(phone: &str) -> bool {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();

    // US phone numbers are 10 or 11 digits (with country code)
    let digits = if digits.len() == 11 && digits.starts_with('1') {
        &digits[1..]
    } else if digits.len() == 10 {
        &digits[..]
    } else {
        return false;
    };

    if digits.len() != 10 {
        return false;
    }

    // Area code can't start with 0 or 1
    let area_code = &digits[0..3];
    if area_code.starts_with('0') || area_code.starts_with('1') {
        return false;
    }

    // Exchange can't start with 0 or 1
    let exchange = &digits[3..6];
    if exchange.starts_with('0') || exchange.starts_with('1') {
        return false;
    }

    // Reject fake numbers (555-01xx are reserved for fiction)
    if &digits[3..6] == "555" && digits[6..8].parse::<u32>().unwrap_or(100) < 2 {
        return false;
    }

    true
}

/// Validate IPv4 address format
pub fn ipv4_format(ip: &str) -> bool {
    // Quick check using memchr - must have exactly 3 dots
    let bytes = ip.as_bytes();
    let mut dot_count = 0;
    let mut pos = 0;
    while let Some(idx) = memchr(b'.', &bytes[pos..]) {
        dot_count += 1;
        pos += idx + 1;
    }
    if dot_count != 3 {
        return false;
    }

    // Parse octets
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    for part in parts {
        // No leading zeros (except for "0" itself)
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
        // Must be valid number 0-255
        match part.parse::<u32>() {
            Ok(n) if n <= 255 => continue,
            _ => return false,
        }
    }

    true
}

/// Check if IP is a private/reserved address (likely false positive)
pub fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u32> = ip
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();

    if parts.len() != 4 {
        return false;
    }

    let (a, b, _, _) = (parts[0], parts[1], parts[2], parts[3]);

    // Private ranges
    a == 10 ||                          // 10.0.0.0/8
    (a == 172 && (16..=31).contains(&b)) ||  // 172.16.0.0/12
    (a == 192 && b == 168) ||           // 192.168.0.0/16
    a == 127 ||                         // Loopback
    a == 0 ||                           // This network
    a >= 224                            // Multicast/Reserved
}

/// Validate SSN format (basic format check, not context)
pub fn ssn_format(ssn: &str) -> bool {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return false;
    }

    // Parse area, group, serial
    let area: u32 = match digits[0..3].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let group: u32 = match digits[3..5].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let serial: u32 = match digits[5..9].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Invalid areas: 000, 666, 900-999
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Group and serial can't be 0
    group > 0 && serial > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid() {
        // Valid test card numbers
        assert!(luhn("4111111111111111")); // Visa test
        assert!(luhn("5500000000000004")); // Mastercard test
        assert!(luhn("4111-1111-1111-1111")); // With dashes
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn("4111111111111112")); // Wrong check digit
        assert!(!luhn("1234567890")); // Too short
        assert!(!luhn("abcd")); // Not numbers
    }

    #[test]
    fn test_ssn_valid() {
        assert!(ssn_format("123-45-6789"));
        assert!(ssn_format("123456789"));
    }

    #[test]
    fn test_ssn_invalid() {
        assert!(!ssn_format("000-45-6789")); // Invalid area
        assert!(!ssn_format("666-45-6789")); // Invalid area
        assert!(!ssn_format("900-45-6789")); // Invalid area
        assert!(!ssn_format("123-00-6789")); // Invalid group
        assert!(!ssn_format("123-45-0000")); // Invalid serial
        assert!(!ssn_format("12345678")); // Too short
    }

    #[test]
    fn test_phone_valid() {
        assert!(phone_format("212-555-1234"));
        assert!(phone_format("(212) 555-1234"));
        assert!(phone_format("2125551234"));
        assert!(phone_format("1-212-555-1234")); // With country code
    }

    #[test]
    fn test_phone_invalid() {
        assert!(!phone_format("012-555-1234")); // Area starts with 0
        assert!(!phone_format("212-155-1234")); // Exchange starts with 1
        assert!(!phone_format("555-555-0100")); // Reserved 555-01xx
        assert!(!phone_format("12345")); // Too short
    }

    #[test]
    fn test_ipv4_valid() {
        assert!(ipv4_format("192.168.1.1"));
        assert!(ipv4_format("10.0.0.1"));
        assert!(ipv4_format("255.255.255.255"));
        assert!(ipv4_format("0.0.0.0"));
    }

    #[test]
    fn test_ipv4_invalid() {
        assert!(!ipv4_format("256.1.1.1")); // Octet > 255
        assert!(!ipv4_format("1.2.3")); // Missing octet
        assert!(!ipv4_format("1.2.3.4.5")); // Too many octets
        assert!(!ipv4_format("01.2.3.4")); // Leading zero
        assert!(!ipv4_format("abc.def.ghi.jkl")); // Not numbers
    }

    #[test]
    fn test_private_ip() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("8.8.8.8")); // Google DNS - public
        assert!(!is_private_ip("1.1.1.1")); // Cloudflare - public
    }
}

//! Risk scoring engine.
//!
//! Computes risk scores from detected entities and exposure context.
//! Mirrors scorer.py with identical weights, thresholds, and formulas.
//!
//! Formula:
//!   content_score = Σ(weight × WEIGHT_SCALE × (1 + ln(count)) × confidence)
//!   content_score *= co_occurrence_multiplier
//!   final_score = min(100, content_score × exposure_multiplier)

use pyo3::prelude::*;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use lazy_static::lazy_static;

const WEIGHT_SCALE: f64 = 4.0;

lazy_static! {
    static ref ENTITY_WEIGHTS: HashMap<&'static str, i32> = {
        let mut m = HashMap::new();
        // Critical (10)
        for k in &["SSN", "PASSPORT", "CREDIT_CARD", "PASSWORD", "API_KEY",
                    "PRIVATE_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY",
                    "DATABASE_URL", "GITHUB_TOKEN", "GITLAB_TOKEN",
                    "SLACK_TOKEN", "STRIPE_KEY", "CRYPTO_SEED_PHRASE"] {
            m.insert(*k, 10);
        }
        // High (8-9)
        m.insert("MRN", 9);
        m.insert("DIAGNOSIS", 9);
        m.insert("HEALTH_PLAN_ID", 9);
        m.insert("JWT", 9);
        m.insert("DRIVER_LICENSE", 8);
        m.insert("NPI", 8);
        m.insert("DEA", 8);
        m.insert("TAX_ID", 8);
        m.insert("MILITARY_ID", 8);
        // Elevated (6-7)
        for k in &["BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "IBAN", "SWIFT_BIC"] {
            m.insert(*k, 7);
        }
        for k in &["PHONE", "EMAIL", "SENDGRID_KEY", "TWILIO_KEY"] {
            m.insert(*k, 6);
        }
        // Moderate (4-5)
        for k in &["NAME", "ADDRESS", "IP_ADDRESS", "MAC_ADDRESS", "VIN",
                    "CUSIP", "ISIN", "LEI", "DATE_DOB"] {
            m.insert(*k, 5);
        }
        for k in &["AGE", "CLASSIFICATION_LEVEL", "DOD_CONTRACT",
                    "GSA_CONTRACT", "CAGE_CODE", "UEI"] {
            m.insert(*k, 4);
        }
        // Low (2-3)
        m.insert("DATE", 3);
        m.insert("ZIP", 3);
        for k in &["CITY", "STATE", "COUNTRY", "TRACKING_NUMBER"] {
            m.insert(*k, 2);
        }
        // Minimal (1)
        m.insert("FACILITY", 1);
        m.insert("ORGANIZATION", 1);
        m
    };

    static ref ENTITY_CATEGORIES: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        // Direct identifiers
        for k in &["SSN", "PASSPORT", "DRIVER_LICENSE", "MILITARY_ID",
                    "TAX_ID", "MRN", "STATE_ID"] {
            m.insert(*k, "direct_identifier");
        }
        // Health info
        for k in &["DIAGNOSIS", "MEDICATION", "HEALTH_PLAN_ID", "NPI",
                    "DEA", "LAB_TEST", "PROCEDURE"] {
            m.insert(*k, "health_info");
        }
        // Financial
        for k in &["CREDIT_CARD", "IBAN", "SWIFT_BIC", "ACCOUNT_NUMBER",
                    "CUSIP", "ISIN", "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS",
                    "CRYPTO_SEED_PHRASE"] {
            m.insert(*k, "financial");
        }
        // Contact
        for k in &["EMAIL", "PHONE", "ADDRESS", "ZIP", "FAX"] {
            m.insert(*k, "contact");
        }
        // Credentials
        for k in &["PASSWORD", "API_KEY", "PRIVATE_KEY", "JWT",
                    "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN",
                    "GITLAB_TOKEN", "SLACK_TOKEN", "STRIPE_KEY", "DATABASE_URL"] {
            m.insert(*k, "credential");
        }
        // Quasi-identifiers
        for k in &["NAME", "DATE_DOB", "AGE", "DATE"] {
            m.insert(*k, "quasi_identifier");
        }
        // Classification markings
        for k in &["CLASSIFICATION_LEVEL", "CLASSIFICATION_MARKING",
                    "SCI_MARKING", "DISSEMINATION_CONTROL"] {
            m.insert(*k, "classification_marking");
        }
        m
    };

    static ref ENTITY_ALIASES: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("US_SSN", "SSN");
        m.insert("SOCIAL_SECURITY", "SSN");
        m.insert("SOCIALSECURITYNUMBER", "SSN");
        m.insert("PER", "NAME");
        m.insert("PERSON", "NAME");
        m.insert("PATIENT", "NAME_PATIENT");
        m.insert("DOCTOR", "NAME_PROVIDER");
        m.insert("PHYSICIAN", "NAME_PROVIDER");
        m.insert("HCW", "NAME_PROVIDER");
        m.insert("DOB", "DATE_DOB");
        m.insert("BIRTHDAY", "DATE_DOB");
        m.insert("DATEOFBIRTH", "DATE_DOB");
        m.insert("DATE_OF_BIRTH", "DATE_DOB");
        m.insert("BIRTH_DATE", "DATE_DOB");
        m.insert("BIRTHDATE", "DATE_DOB");
        m.insert("CC", "CREDIT_CARD");
        m.insert("CREDITCARD", "CREDIT_CARD");
        m.insert("CREDITCARDNUMBER", "CREDIT_CARD");
        m.insert("CREDIT_CARD_NUMBER", "CREDIT_CARD");
        m.insert("TELEPHONE", "PHONE");
        m.insert("TEL", "PHONE");
        m.insert("MOBILE", "PHONE");
        m.insert("CELL", "PHONE");
        m.insert("PHONENUMBER", "PHONE");
        m.insert("PHONE_NUMBER", "PHONE");
        m.insert("US_PHONE_NUMBER", "PHONE");
        m.insert("EMAILADDRESS", "EMAIL");
        m.insert("EMAIL_ADDRESS", "EMAIL");
        m.insert("STREET_ADDRESS", "ADDRESS");
        m.insert("STREET", "ADDRESS");
        m.insert("IP", "IP_ADDRESS");
        m.insert("IPADDRESS", "IP_ADDRESS");
        m.insert("IPV4", "IP_ADDRESS");
        m.insert("IPV6", "IP_ADDRESS");
        m.insert("MEDICAL_RECORD", "MRN");
        m.insert("MEDICALRECORD", "MRN");
        m.insert("LICENSE", "DRIVER_LICENSE");
        m.insert("US_DRIVER_LICENSE", "DRIVER_LICENSE");
        m.insert("DRIVERSLICENSE", "DRIVER_LICENSE");
        m.insert("US_PASSPORT", "PASSPORT");
        m.insert("PASSPORT_NUMBER", "PASSPORT");
        m.insert("ZIPCODE", "ZIP");
        m.insert("ZIP_CODE", "ZIP");
        m.insert("POSTCODE", "ZIP");
        m.insert("LOCATION_ZIP", "ZIP");
        m
    };

    /// Co-occurrence rules: (required_categories, multiplier, rule_name)
    static ref CO_OCCURRENCE_RULES: Vec<(Vec<&'static str>, f64, &'static str)> = vec![
        (vec!["direct_identifier", "health_info"], 2.0, "hipaa_phi"),
        (vec!["direct_identifier", "financial"], 1.8, "identity_theft"),
        (vec!["credential"], 1.5, "credential_exposure"),
        (vec!["quasi_identifier", "health_info"], 1.5, "phi_without_id"),
        (vec!["contact", "health_info"], 1.4, "phi_with_contact"),
        (vec!["direct_identifier", "quasi_identifier", "financial"], 2.2, "full_identity"),
        (vec!["classification_marking"], 2.5, "classified_data"),
    ];

    static ref EXPOSURE_MULTIPLIERS: HashMap<&'static str, f64> = {
        let mut m = HashMap::new();
        m.insert("PRIVATE", 1.0);
        m.insert("INTERNAL", 1.2);
        m.insert("ORG_WIDE", 1.8);
        m.insert("PUBLIC", 2.5);
        m
    };
}

const DEFAULT_WEIGHT: i32 = 5;

/// Tier thresholds
const TIER_CRITICAL: f64 = 80.0;
const TIER_HIGH: f64 = 55.0;
const TIER_MEDIUM: f64 = 31.0;
const TIER_LOW: f64 = 11.0;

fn normalize_entity(entity_type: &str) -> String {
    let upper = entity_type.to_uppercase();
    match ENTITY_ALIASES.get(upper.as_str()) {
        Some(canonical) => canonical.to_string(),
        None => upper,
    }
}

fn get_weight(entity_type: &str) -> i32 {
    let normalized = normalize_entity(entity_type);
    *ENTITY_WEIGHTS.get(normalized.as_str()).unwrap_or(&DEFAULT_WEIGHT)
}

fn get_category(entity_type: &str) -> &'static str {
    let normalized = normalize_entity(entity_type);
    ENTITY_CATEGORIES.get(normalized.as_str()).copied().unwrap_or("unknown")
}

fn get_categories(entities: &HashMap<String, i32>) -> HashSet<String> {
    let mut cats = HashSet::new();
    for entity_type in entities.keys() {
        let cat = get_category(entity_type);
        if cat != "unknown" {
            cats.insert(cat.to_string());
        }
    }
    cats
}

fn get_co_occurrence_multiplier(entities: &HashMap<String, i32>) -> (f64, Vec<String>) {
    if entities.is_empty() {
        return (1.0, vec![]);
    }

    let categories = get_categories(entities);
    let mut max_mult = 1.0f64;
    let mut triggered_rules: Vec<String> = vec![];

    for (required_cats, mult, rule_name) in CO_OCCURRENCE_RULES.iter() {
        let all_present = required_cats.iter().all(|c| categories.contains(*c));
        if all_present {
            if *mult > max_mult {
                max_mult = *mult;
                triggered_rules = vec![rule_name.to_string()];
            } else if (*mult - max_mult).abs() < f64::EPSILON {
                triggered_rules.push(rule_name.to_string());
            }
        }
    }

    (max_mult, triggered_rules)
}

fn score_to_tier(score: f64) -> &'static str {
    if score >= TIER_CRITICAL {
        "CRITICAL"
    } else if score >= TIER_HIGH {
        "HIGH"
    } else if score >= TIER_MEDIUM {
        "MEDIUM"
    } else if score >= TIER_LOW {
        "LOW"
    } else {
        "MINIMAL"
    }
}

/// Internal scoring function returning all components.
fn score_internal(
    entities: &HashMap<String, i32>,
    exposure: &str,
    confidence: f64,
) -> ScoringResultInternal {
    if entities.is_empty() {
        return ScoringResultInternal {
            score: 0,
            tier: "MINIMAL".to_string(),
            content_score: 0.0,
            exposure_multiplier: 1.0,
            co_occurrence_multiplier: 1.0,
            co_occurrence_rules: vec![],
            categories: HashSet::new(),
            exposure: exposure.to_uppercase(),
        };
    }

    // Calculate content score
    let mut base_score = 0.0f64;
    for (entity_type, &count) in entities {
        let weight = get_weight(entity_type) as f64 * WEIGHT_SCALE;
        let aggregation = 1.0 + (count.max(1) as f64).ln();
        let entity_score = weight * aggregation * confidence;
        base_score += entity_score;
    }

    // Co-occurrence multiplier
    let (co_mult, co_rules) = get_co_occurrence_multiplier(entities);
    let content_score = (base_score * co_mult).min(100.0);

    // Exposure multiplier
    let exp_upper = exposure.to_uppercase();
    let exp_mult = *EXPOSURE_MULTIPLIERS.get(exp_upper.as_str()).unwrap_or(&1.0);
    let final_score = (content_score * exp_mult).min(100.0);

    let tier = score_to_tier(final_score).to_string();

    ScoringResultInternal {
        score: final_score.round() as i32,
        tier,
        content_score: (content_score * 10.0).round() / 10.0,
        exposure_multiplier: exp_mult,
        co_occurrence_multiplier: co_mult,
        co_occurrence_rules: co_rules,
        categories: get_categories(entities),
        exposure: exp_upper,
    }
}

struct ScoringResultInternal {
    score: i32,
    tier: String,
    content_score: f64,
    exposure_multiplier: f64,
    co_occurrence_multiplier: f64,
    co_occurrence_rules: Vec<String>,
    categories: HashSet<String>,
    exposure: String,
}

/// PyO3-exported scoring result.
#[pyclass]
#[derive(Clone)]
pub struct RustScoringResult {
    #[pyo3(get)]
    pub score: i32,
    #[pyo3(get)]
    pub tier: String,
    #[pyo3(get)]
    pub content_score: f64,
    #[pyo3(get)]
    pub exposure_multiplier: f64,
    #[pyo3(get)]
    pub co_occurrence_multiplier: f64,
    #[pyo3(get)]
    pub co_occurrence_rules: Vec<String>,
    #[pyo3(get)]
    pub categories: Vec<String>,
    #[pyo3(get)]
    pub exposure: String,
}

#[pymethods]
impl RustScoringResult {
    fn __repr__(&self) -> String {
        format!(
            "RustScoringResult(score={}, tier='{}', content_score={:.1})",
            self.score, self.tier, self.content_score
        )
    }
}

impl From<ScoringResultInternal> for RustScoringResult {
    fn from(r: ScoringResultInternal) -> Self {
        RustScoringResult {
            score: r.score,
            tier: r.tier,
            content_score: r.content_score,
            exposure_multiplier: r.exposure_multiplier,
            co_occurrence_multiplier: r.co_occurrence_multiplier,
            co_occurrence_rules: r.co_occurrence_rules,
            categories: r.categories.into_iter().collect(),
            exposure: r.exposure,
        }
    }
}

/// Score a single set of entities.
#[pyfunction]
#[pyo3(signature = (entities, exposure = "PRIVATE", confidence = 0.85))]
pub fn score_entities(
    entities: HashMap<String, i32>,
    exposure: &str,
    confidence: f64,
) -> RustScoringResult {
    score_internal(&entities, exposure, confidence).into()
}

/// Score a batch of entity sets in parallel using Rayon.
/// Each item is (entities_dict, exposure_str, confidence_float).
#[pyfunction]
pub fn score_entities_batch(
    py: Python,
    batch: Vec<(HashMap<String, i32>, String, f64)>,
) -> Vec<RustScoringResult> {
    py.allow_threads(|| {
        batch
            .par_iter()
            .map(|(entities, exposure, confidence)| {
                score_internal(entities, exposure, *confidence).into()
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_single_ssn() {
        let mut entities = HashMap::new();
        entities.insert("SSN".to_string(), 1);
        let result = score_internal(&entities, "PRIVATE", 0.85);
        // weight=10, scale=4.0, aggregation=1+ln(1)=1.0, conf=0.85
        // base = 10 * 4.0 * 1.0 * 0.85 = 34.0
        // co_mult = 1.0 (just direct_identifier, no co-occurrence)
        // content = 34.0
        // exp = 1.0 (PRIVATE)
        // final = 34.0 => MEDIUM
        assert_eq!(result.score, 34);
        assert_eq!(result.tier, "MEDIUM");
    }

    #[test]
    fn test_score_hipaa_phi() {
        let mut entities = HashMap::new();
        entities.insert("SSN".to_string(), 1);
        entities.insert("DIAGNOSIS".to_string(), 1);
        let result = score_internal(&entities, "PRIVATE", 0.85);
        // SSN: 10*4*1*0.85 = 34
        // DIAGNOSIS: 9*4*1*0.85 = 30.6
        // base = 64.6
        // co_mult = 2.0 (hipaa_phi)
        // content = min(100, 64.6 * 2.0) = 100
        assert_eq!(result.score, 100);
        assert_eq!(result.tier, "CRITICAL");
    }

    #[test]
    fn test_score_empty() {
        let entities = HashMap::new();
        let result = score_internal(&entities, "PRIVATE", 0.85);
        assert_eq!(result.score, 0);
        assert_eq!(result.tier, "MINIMAL");
    }
}

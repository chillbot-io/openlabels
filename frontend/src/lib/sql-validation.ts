/**
 * Client-side SQL validation utilities.
 *
 * These checks are **defense-in-depth only** — the backend's `validate_sql()`
 * in `server/routes/query.py` performs authoritative server-side validation
 * (allowed statement types, forbidden patterns, blocked functions, multi-
 * statement detection). The client-side checks provide immediate user feedback
 * and an extra safety layer, but must never be relied upon as the sole guard.
 */

/** Maximum allowed query length (matches backend MAX_QUERY_LENGTH). */
export const SQL_MAX_LENGTH = 10_000;

/**
 * Regex that matches SQL keywords indicating data-modifying or schema-altering
 * statements. Used to warn users before execution — the backend will also
 * reject these server-side.
 */
export const DANGEROUS_SQL_PATTERNS =
  /\b(DROP|TRUNCATE|DELETE\s+FROM|ALTER|CREATE|INSERT|UPDATE|GRANT|REVOKE)\b/i;

export interface SqlValidationResult {
  valid: boolean;
  /** Set when the query exceeds the max length. */
  tooLong?: boolean;
  /** Set when the query matches a dangerous pattern. */
  dangerous?: boolean;
  /** Human-readable error/warning message. */
  message?: string;
}

/**
 * Validate a SQL string against client-side safety checks.
 *
 * Returns an object describing the validation outcome. When `dangerous` is
 * true the caller should prompt the user for confirmation before executing.
 */
export function validateSql(sql: string): SqlValidationResult {
  if (!sql.trim()) {
    return { valid: false, message: 'Query is empty' };
  }

  if (sql.length > SQL_MAX_LENGTH) {
    return {
      valid: false,
      tooLong: true,
      message: `SQL query exceeds maximum length of ${SQL_MAX_LENGTH} characters`,
    };
  }

  if (DANGEROUS_SQL_PATTERNS.test(sql)) {
    return {
      valid: true,
      dangerous: true,
      message:
        'This query contains operations that may modify data (DROP, DELETE, ALTER, etc.).',
    };
  }

  return { valid: true };
}

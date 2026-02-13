"""
SQL query and AI assistant API endpoints.

Provides (router-local paths, mounted at ``/api/v1/query``):
- POST /              — Execute read-only SQL against the DuckDB analytics layer
- GET  /schema        — Introspect available tables and columns for autocomplete
- POST /ai            — Natural language → SQL translation via LLM, then execute

Security:
- All queries are validated as read-only (SELECT/WITH only)
- Tenant isolation is enforced by exposing a ``$tenant_id`` parameter
- Query execution is bounded to 30 seconds
- Result sets are size-limited
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter

from openlabels.server.dependencies import TenantContextDep
from openlabels.server.utils import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_client_ip)

# --- Safety: SQL validation ---

# Statements that are NEVER allowed
_FORBIDDEN_PATTERNS = re.compile(
    r"""
    \b(
        INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|
        REPLACE|MERGE|GRANT|REVOKE|COPY|ATTACH|DETACH|
        LOAD|INSTALL|EXPORT|IMPORT|CALL|EXECUTE|EXEC|
        PRAGMA|SET\s+|VACUUM|CHECKPOINT
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Only allow queries that start with SELECT or WITH (CTEs)
_ALLOWED_START = re.compile(
    r"^\s*(SELECT|WITH)\b",
    re.IGNORECASE,
)

# Block attempts to use system functions that could read filesystem or leak info
_BLOCKED_FUNCTIONS = re.compile(
    r"\b(pg_read_file|pg_read_binary_file|read_text|read_blob|"
    r"read_csv|read_csv_auto|read_json|read_json_auto|read_parquet|"
    r"read_ndjson|read_ndjson_auto|"
    r"glob|scan_parquet|scan_csv|scan_json|"
    r"httpfs|http_get|http_post)\b",
    re.IGNORECASE,
)

MAX_RESULT_ROWS = 10_000
MAX_QUERY_LENGTH = 10_000
QUERY_TIMEOUT_SECONDS = 30


def validate_sql(sql: str) -> str:
    """Validate that a SQL query is safe to execute.

    Returns the cleaned SQL string. Raises ValueError on unsafe input.
    """
    sql = sql.strip().rstrip(";")

    if not sql:
        raise ValueError("Empty query")

    if len(sql) > MAX_QUERY_LENGTH:
        raise ValueError(f"Query exceeds maximum length ({MAX_QUERY_LENGTH} characters)")

    if not _ALLOWED_START.match(sql):
        raise ValueError("Only SELECT and WITH (CTE) queries are allowed")

    if _FORBIDDEN_PATTERNS.search(sql):
        raise ValueError("Query contains forbidden statements (DDL/DML not allowed)")

    if _BLOCKED_FUNCTIONS.search(sql):
        raise ValueError("Query contains blocked functions")

    # Check for multiple statements (semicolons within the query)
    # Allow semicolons inside string literals but block bare ones.
    # SQL uses doubled quotes ('' or "") for escaping, not backslash.
    in_string = False
    quote_char: str | None = None
    i = 0
    length = len(sql)
    while i < length:
        ch = sql[i]
        if in_string:
            if ch == quote_char:
                # Doubled quote = escape, stay in string
                if i + 1 < length and sql[i + 1] == quote_char:
                    i += 2  # skip both quotes
                    continue
                # Single quote = end of string
                in_string = False
        else:
            if ch in ("'", '"'):
                in_string = True
                quote_char = ch
            elif ch == ";":
                raise ValueError("Multiple statements are not allowed")
        i += 1

    return sql


def _replace_param_placeholders(sql: str) -> tuple[str, int]:
    """Replace ``$1`` placeholders with ``?`` only outside SQL string literals.

    Returns the rewritten SQL and the number of replacements made.
    SQL uses doubled quotes (``''`` / ``""``) for escaping, not backslash.
    """
    result: list[str] = []
    count = 0
    i = 0
    length = len(sql)

    while i < length:
        ch = sql[i]

        # Enter string literal
        if ch in ("'", '"'):
            quote = ch
            result.append(ch)
            i += 1
            # Consume until closing quote (handling doubled-quote escapes)
            while i < length:
                if sql[i] == quote:
                    result.append(sql[i])
                    i += 1
                    # Doubled quote = escape, stay in string
                    if i < length and sql[i] == quote:
                        result.append(sql[i])
                        i += 1
                        continue
                    # Single quote = end of string
                    break
                else:
                    result.append(sql[i])
                    i += 1
            continue

        # Outside string: check for $1
        if ch == "$" and i + 1 < length and sql[i + 1] == "1":
            # Make sure it's not $10, $11, etc.
            if i + 2 >= length or not sql[i + 2].isdigit():
                result.append("?")
                count += 1
                i += 2
                continue

        result.append(ch)
        i += 1

    return "".join(result), count


# --- Request / Response models ---


class QueryRequest(BaseModel):
    """Execute a SQL query against the analytics layer."""

    sql: str = Field(
        ...,
        description=(
            "Read-only SQL query (SELECT/WITH). "
            "Use $1 as a parameter placeholder for tenant_id. "
            "Available tables: scan_results, file_inventory, folder_inventory, "
            "directory_tree, access_events, audit_log, remediation_actions."
        ),
        max_length=MAX_QUERY_LENGTH,
    )
    limit: int = Field(
        default=1000,
        ge=1,
        le=MAX_RESULT_ROWS,
        description="Maximum rows to return",
    )


class QueryResponse(BaseModel):
    """SQL query execution result."""

    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    truncated: bool = False
    execution_time_ms: int
    sql: str  # The actual SQL that was executed


class SchemaColumn(BaseModel):
    """Column metadata."""

    name: str
    type: str


class SchemaTable(BaseModel):
    """Metadata for one analytics table/view."""

    name: str
    columns: list[SchemaColumn]


class SchemaResponse(BaseModel):
    """Available tables and columns for autocomplete."""

    tables: list[SchemaTable]


class AIQueryRequest(BaseModel):
    """Natural language query to be translated to SQL."""

    question: str = Field(
        ...,
        min_length=5,
        max_length=2000,
        description="Natural language question about the data",
    )
    execute: bool = Field(
        default=True,
        description="Whether to execute the generated SQL or just return it",
    )
    limit: int = Field(
        default=1000,
        ge=1,
        le=MAX_RESULT_ROWS,
        description="Maximum rows to return if executing",
    )


class AIQueryResponse(BaseModel):
    """Result of an AI-generated SQL query."""

    question: str
    generated_sql: str
    explanation: str
    result: QueryResponse | None = None
    error: str | None = None


# --- Schema introspection ---

# Known analytics views and their columns (from DuckDBEngine._VIEW_DEFS).
# These are the Parquet-backed views registered by the engine.
_ANALYTICS_SCHEMA: dict[str, list[tuple[str, str]]] = {
    "scan_results": [
        ("tenant", "VARCHAR"),
        ("scan_date", "VARCHAR"),
        ("job_id", "BLOB"),
        ("file_path", "VARCHAR"),
        ("file_name", "VARCHAR"),
        ("risk_score", "INTEGER"),
        ("risk_tier", "VARCHAR"),
        ("entity_counts", "MAP(VARCHAR, INTEGER)"),
        ("total_entities", "INTEGER"),
        ("exposure_level", "VARCHAR"),
        ("owner", "VARCHAR"),
        ("current_label_name", "VARCHAR"),
        ("label_applied", "BOOLEAN"),
        ("policy_violations", "JSON"),
    ],
    "file_inventory": [
        ("tenant", "VARCHAR"),
        ("file_path", "VARCHAR"),
        ("file_name", "VARCHAR"),
        ("content_hash", "VARCHAR"),
        ("risk_score", "INTEGER"),
        ("risk_tier", "VARCHAR"),
        ("entity_counts", "MAP(VARCHAR, INTEGER)"),
        ("total_entities", "INTEGER"),
        ("label_applied", "BOOLEAN"),
    ],
    "folder_inventory": [
        ("tenant", "VARCHAR"),
        ("folder_path", "VARCHAR"),
        ("has_sensitive_files", "BOOLEAN"),
        ("highest_risk_tier", "VARCHAR"),
        ("total_entities_found", "INTEGER"),
    ],
    "directory_tree": [
        ("tenant", "VARCHAR"),
        ("dir_path", "VARCHAR"),
        ("dir_name", "VARCHAR"),
        ("child_dir_count", "INTEGER"),
        ("child_file_count", "INTEGER"),
    ],
    "access_events": [
        ("tenant", "VARCHAR"),
        ("file_path", "VARCHAR"),
        ("action", "VARCHAR"),
        ("user_name", "VARCHAR"),
        ("user_domain", "VARCHAR"),
        ("process_name", "VARCHAR"),
        ("event_time", "TIMESTAMP"),
        ("success", "BOOLEAN"),
    ],
    "audit_log": [
        ("tenant", "VARCHAR"),
        ("user_email", "VARCHAR"),
        ("action", "VARCHAR"),
        ("resource_type", "VARCHAR"),
        ("created_at", "TIMESTAMP"),
    ],
    "remediation_actions": [
        ("tenant", "VARCHAR"),
        ("action_type", "VARCHAR"),
        ("status", "VARCHAR"),
        ("source_path", "VARCHAR"),
        ("performed_by", "VARCHAR"),
        ("created_at", "TIMESTAMP"),
    ],
}


def _build_schema() -> list[SchemaTable]:
    """Build schema metadata from the known view definitions."""
    tables = []
    for name, cols in _ANALYTICS_SCHEMA.items():
        tables.append(SchemaTable(
            name=name,
            columns=[SchemaColumn(name=c, type=t) for c, t in cols],
        ))
    return tables


# --- Endpoints ---


@router.get("/schema", response_model=SchemaResponse)
async def get_query_schema(
    request: Request,
    tenant: TenantContextDep,
) -> SchemaResponse:
    """
    Return available analytics tables and columns.

    Used by the frontend SQL editor for autocomplete and syntax
    validation. Dynamically reads from DuckDB if the analytics engine
    is available, falls back to static schema definitions.
    """
    analytics = getattr(request.app.state, "analytics", None)

    if analytics:
        # Try to get live schema from DuckDB
        try:
            tables = []
            for view_name in _ANALYTICS_SCHEMA:
                try:
                    rows = await analytics.query(
                        f"SELECT column_name, data_type "
                        f"FROM information_schema.columns "
                        f"WHERE table_name = ? ORDER BY ordinal_position",
                        [view_name],
                    )
                    if rows and not any(r["column_name"] == "placeholder" for r in rows):
                        tables.append(SchemaTable(
                            name=view_name,
                            columns=[
                                SchemaColumn(name=r["column_name"], type=r["data_type"])
                                for r in rows
                            ],
                        ))
                    else:
                        # Stub table — use static schema
                        tables.append(SchemaTable(
                            name=view_name,
                            columns=[
                                SchemaColumn(name=c, type=t)
                                for c, t in _ANALYTICS_SCHEMA[view_name]
                            ],
                        ))
                except Exception:
                    tables.append(SchemaTable(
                        name=view_name,
                        columns=[
                            SchemaColumn(name=c, type=t)
                            for c, t in _ANALYTICS_SCHEMA[view_name]
                        ],
                    ))
            return SchemaResponse(tables=tables)
        except Exception as e:
            logger.debug("Dynamic analytics schema lookup failed, using static: %s", e)

    # Fallback to static schema
    return SchemaResponse(tables=_build_schema())


@router.post("", response_model=QueryResponse)
@limiter.limit("30/minute")
async def execute_query(
    body: QueryRequest,
    request: Request,
    tenant: TenantContextDep,
) -> QueryResponse:
    """
    Execute a read-only SQL query against the DuckDB analytics layer.

    The query runs against Parquet-backed views with hive partitioning.
    Use ``WHERE tenant = $1`` to scope queries to your tenant (required
    for data isolation).

    Available tables: ``scan_results``, ``file_inventory``,
    ``folder_inventory``, ``directory_tree``, ``access_events``,
    ``audit_log``, ``remediation_actions``.
    """
    analytics = getattr(request.app.state, "analytics", None)
    if not analytics:
        raise HTTPException(status_code=503, detail="Analytics engine unavailable")

    # Validate SQL safety
    try:
        clean_sql = validate_sql(body.sql)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Inject tenant_id as a parameter — replace $1 with positional ?.
    # DuckDB uses positional parameters (?), and each ? consumes one param,
    # so we must append one copy of tenant_id per occurrence.
    # Replacement is string-literal-aware to avoid mangling $1 inside quotes.
    tenant_str = str(tenant.tenant_id)
    execution_sql, occurrence_count = _replace_param_placeholders(clean_sql)
    params: list[Any] = [tenant_str] * occurrence_count

    # Enforce row limit via wrapping
    limited_sql = f"SELECT * FROM ({execution_sql}) AS __q LIMIT {body.limit + 1}"

    start = time.monotonic()
    try:
        rows = await asyncio.wait_for(
            analytics.query(limited_sql, params or None),
            timeout=QUERY_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=408,
            detail=f"Query timed out after {QUERY_TIMEOUT_SECONDS} seconds",
        )
    except Exception as e:
        error_msg = str(e)
        # Don't leak internal details
        if "placeholder" in error_msg:
            raise HTTPException(
                status_code=400,
                detail="No data available for the queried table yet",
            )
        logger.warning("Query execution failed: %s", error_msg)
        # Truncate to first line and limit length to avoid leaking internal details
        safe_msg = error_msg.split("\n")[0][:200] if error_msg else "Unknown error"
        raise HTTPException(status_code=400, detail=f"Query error: {safe_msg}")
    elapsed_ms = int((time.monotonic() - start) * 1000)

    truncated = len(rows) > body.limit
    if truncated:
        rows = rows[: body.limit]

    # Extract column names from first row (or empty)
    columns = list(rows[0].keys()) if rows else []

    # Convert to row arrays for efficient transfer
    row_arrays = [[_serialize_value(row.get(col)) for col in columns] for row in rows]

    return QueryResponse(
        columns=columns,
        rows=row_arrays,
        row_count=len(row_arrays),
        truncated=truncated,
        execution_time_ms=elapsed_ms,
        sql=clean_sql,
    )


@router.post("/ai", response_model=AIQueryResponse)
@limiter.limit("10/minute")
async def ai_query(
    body: AIQueryRequest,
    request: Request,
    tenant: TenantContextDep,
) -> AIQueryResponse:
    """
    Translate a natural language question to SQL and optionally execute it.

    Uses the Anthropic Claude API (or OpenAI as fallback) to generate
    a DuckDB-compatible SQL query from the user's question. The generated
    SQL is validated for safety before execution.

    Requires ``ANTHROPIC_API_KEY`` or ``OPENAI_API_KEY`` environment variable.
    """
    # Build the schema context for the LLM
    schema_text = _build_schema_prompt()
    tenant_str = str(tenant.tenant_id)

    # Generate SQL via LLM
    try:
        generated_sql, explanation = await _generate_sql(
            question=body.question,
            schema=schema_text,
        )
    except Exception as e:
        logger.error("AI SQL generation failed: %s", e)
        raise HTTPException(
            status_code=503,
            detail="AI query generation failed. Check server logs for details.",
        )

    # Validate the generated SQL
    try:
        clean_sql = validate_sql(generated_sql)
    except ValueError as e:
        return AIQueryResponse(
            question=body.question,
            generated_sql=generated_sql,
            explanation=explanation,
            error=f"Generated SQL failed validation: {e}",
        )

    if not body.execute:
        return AIQueryResponse(
            question=body.question,
            generated_sql=clean_sql,
            explanation=explanation,
        )

    # Execute the query
    analytics = getattr(request.app.state, "analytics", None)
    if not analytics:
        return AIQueryResponse(
            question=body.question,
            generated_sql=clean_sql,
            explanation=explanation,
            error="Analytics engine unavailable",
        )

    execution_sql, occurrence_count = _replace_param_placeholders(clean_sql)
    params: list[Any] = [tenant_str] * occurrence_count

    limited_sql = f"SELECT * FROM ({execution_sql}) AS __q LIMIT {body.limit + 1}"

    start = time.monotonic()
    try:
        rows = await asyncio.wait_for(
            analytics.query(limited_sql, params or None),
            timeout=QUERY_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        return AIQueryResponse(
            question=body.question,
            generated_sql=clean_sql,
            explanation=explanation,
            error=f"Query timed out after {QUERY_TIMEOUT_SECONDS} seconds",
        )
    except Exception as e:
        return AIQueryResponse(
            question=body.question,
            generated_sql=clean_sql,
            explanation=explanation,
            error=f"Query execution failed: {e}",
        )
    elapsed_ms = int((time.monotonic() - start) * 1000)

    truncated = len(rows) > body.limit
    if truncated:
        rows = rows[: body.limit]

    columns = list(rows[0].keys()) if rows else []
    row_arrays = [[_serialize_value(row.get(col)) for col in columns] for row in rows]

    return AIQueryResponse(
        question=body.question,
        generated_sql=clean_sql,
        explanation=explanation,
        result=QueryResponse(
            columns=columns,
            rows=row_arrays,
            row_count=len(row_arrays),
            truncated=truncated,
            execution_time_ms=elapsed_ms,
            sql=clean_sql,
        ),
    )


# --- Helpers ---


def _serialize_value(value: Any) -> Any:
    """Convert DuckDB values to JSON-safe types."""
    if value is None:
        return None
    if isinstance(value, (int, float, str, bool)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (dict, list)):
        return value
    # datetime, date, etc.
    return str(value)


def _build_schema_prompt() -> str:
    """Build a text description of the analytics schema for the LLM."""
    lines = [
        "Available DuckDB tables (Parquet-backed with hive partitioning):",
        "All tables have a 'tenant' VARCHAR column for multi-tenant isolation.",
        "Use WHERE tenant = $1 to filter by the current tenant.",
        "",
    ]
    for table_name, columns in _ANALYTICS_SCHEMA.items():
        col_defs = ", ".join(f"{name} {dtype}" for name, dtype in columns)
        lines.append(f"  {table_name}({col_defs})")

    lines.extend([
        "",
        "Risk tiers: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL",
        "Exposure levels: PUBLIC, ORG_WIDE, INTERNAL, PRIVATE",
        "Access actions: READ, WRITE, DELETE, RENAME, PERMISSION_CHANGE",
        "Remediation types: quarantine, lockdown, rollback",
        "Remediation statuses: pending, completed, failed, rolled_back",
    ])
    return "\n".join(lines)


async def _generate_sql(
    question: str,
    schema: str,
) -> tuple[str, str]:
    """Generate SQL from a natural language question using an LLM.

    Tries Anthropic first, then OpenAI. Raises if neither is available.

    Returns (sql, explanation) tuple.
    """
    import os

    system_prompt = f"""You are a SQL query assistant for OpenLabels, a data classification platform.
Generate DuckDB-compatible SQL queries based on user questions.

{schema}

Rules:
- ALWAYS include WHERE tenant = $1 for tenant isolation ($1 is a parameter placeholder — do NOT substitute it with a real value)
- Only generate SELECT queries (no INSERT, UPDATE, DELETE, DDL)
- Use DuckDB SQL syntax (not PostgreSQL-specific features)
- For entity_counts MAP column, use unnest(map_keys(...)) and unnest(map_values(...))
- Return ONLY the SQL query on the first line, followed by a blank line, then an explanation
- Keep queries efficient — use LIMIT when appropriate"""

    user_prompt = f"Question: {question}\n\nGenerate a DuckDB SQL query to answer this question."

    # Try Anthropic first
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        return await _call_anthropic(system_prompt, user_prompt, anthropic_key)

    # Try OpenAI
    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        return await _call_openai(system_prompt, user_prompt, openai_key)

    raise RuntimeError(
        "No AI provider configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable."
    )


async def _call_anthropic(
    system: str, user: str, api_key: str
) -> tuple[str, str]:
    """Call Anthropic Claude API for SQL generation."""
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

    client = anthropic.Anthropic(api_key=api_key)

    # Run sync client in thread to avoid blocking
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=2000,
            system=system,
            messages=[{"role": "user", "content": user}],
        ),
    )

    text = response.content[0].text
    return _parse_llm_response(text)


async def _call_openai(
    system: str, user: str, api_key: str
) -> tuple[str, str]:
    """Call OpenAI API for SQL generation."""
    try:
        import openai
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")

    client = openai.OpenAI(api_key=api_key)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.chat.completions.create(
            model="gpt-4o",
            max_tokens=2000,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        ),
    )

    text = response.choices[0].message.content or ""
    return _parse_llm_response(text)


def _parse_llm_response(text: str) -> tuple[str, str]:
    """Parse the LLM response into (sql, explanation).

    Expected format:
        SELECT ... FROM ...
        WHERE tenant = $1
        ...

        This query does X by Y...
    """
    text = text.strip()

    # Remove markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```sql or ```) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    # Split on double newline to separate SQL from explanation
    parts = text.split("\n\n", 1)
    sql = parts[0].strip()
    explanation = parts[1].strip() if len(parts) > 1 else "Generated SQL query."

    # If the SQL still has non-SQL text at the beginning, try to extract it
    if not _ALLOWED_START.match(sql):
        # Try to find the SELECT or WITH statement
        for i, line in enumerate(sql.split("\n")):
            if _ALLOWED_START.match(line):
                sql = "\n".join(sql.split("\n")[i:])
                break

    return sql.rstrip(";"), explanation

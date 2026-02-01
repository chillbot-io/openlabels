"""Audit log with hash chain integrity."""

import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Tuple

from .database import Database
from ..types import AuditEventType, AuditEntry


class AuditLog:
    """
    Hash-chained audit log backed by SQLite.
    
    Each entry contains:
    - sequence: Sequential number (no gaps)
    - event_type: What happened
    - timestamp: When it happened (UTC)
    - session_id: Which session
    - data: Event-specific payload (JSON)
    - prev_hash: Hash of previous entry
    - entry_hash: Hash of this entry
    
    Any modification to historical entries breaks the chain.
    """

    def __init__(self, db: Database, session_id: str):
        self._db = db
        # Hash session ID before storage to prevent correlation attacks
        # if attacker gains read access to database
        # Use 32 hex chars (128 bits) to prevent birthday collisions
        self._session_id = hashlib.sha256(session_id.encode()).hexdigest()[:32]

    def _compute_hash(
        self,
        sequence: int,
        event_type: str,
        timestamp: str,
        data_json: str,
        prev_hash: str
    ) -> str:
        """Compute entry hash."""
        payload = f"{sequence}|{event_type}|{timestamp}|{data_json}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _get_last_hash(self) -> str:
        """Get hash of last entry for this session, or 'GENESIS' if empty."""
        row = self._db.fetchone("""
            SELECT entry_hash FROM audit_log
            WHERE session_id = ?
            ORDER BY sequence DESC LIMIT 1
        """, (self._session_id,))
        return row["entry_hash"] if row else "GENESIS"

    def _get_next_sequence(self) -> int:
        """Get next sequence number for this session."""
        row = self._db.fetchone("""
            SELECT MAX(sequence) as max_seq FROM audit_log
            WHERE session_id = ?
        """, (self._session_id,))
        return (row["max_seq"] or 0) + 1

    def log(self, event_type: AuditEventType, data: Dict) -> AuditEntry:
        """
        Log an event atomically.
        
        Uses a transaction to prevent race conditions where concurrent
        calls could get the same sequence number.
        
        Args:
            event_type: Type of event
            data: Event-specific data (must be JSON-serializable)
        
        Returns:
            The created audit entry
        """
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        data_json = json.dumps(data, sort_keys=True, separators=(",", ":"))

        # Use transaction for atomicity
        with self._db.transaction():
            sequence = self._get_next_sequence()
            prev_hash = self._get_last_hash()

            entry_hash = self._compute_hash(
                sequence, event_type.value, timestamp, data_json, prev_hash
            )

            self._db.conn.execute("""
                INSERT INTO audit_log (sequence, event_type, timestamp, session_id,
                                      data, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (sequence, event_type.value, timestamp, self._session_id,
                  data_json, prev_hash, entry_hash))

        return AuditEntry(
            sequence=sequence,
            event_type=event_type,
            timestamp=datetime.fromisoformat(timestamp.rstrip("Z")),
            session_id=self._session_id,
            data=data,
            prev_hash=prev_hash,
            entry_hash=entry_hash
        )

    def log_detection(self, input_text: str, spans: list, processing_time_ms: float) -> AuditEntry:
        """Log PHI detection event."""
        # Use 128-bit hash (32 hex chars) instead of 64-bit (16 chars)
        # 64 bits has ~2^32 birthday collision threshold, 128 bits is collision-resistant
        input_hash = hashlib.sha256(input_text.encode("utf-8")).hexdigest()[:32]
        return self.log(AuditEventType.PHI_DETECTED, {
            "input_hash": input_hash,
            "detection_count": len(spans),
            "entity_types": list(set(s.entity_type for s in spans)),
            "detectors": list(set(s.detector for s in spans)),
            "processing_time_ms": round(processing_time_ms, 2)
        })

    def log_redaction(self, input_text: str, output_text: str, tokens: list) -> AuditEntry:
        """Log PHI redaction event."""
        # Use 128-bit hashes
        input_hash = hashlib.sha256(input_text.encode("utf-8")).hexdigest()[:32]
        output_hash = hashlib.sha256(output_text.encode("utf-8")).hexdigest()[:32]
        return self.log(AuditEventType.PHI_REDACTED, {
            "input_hash": input_hash,
            "output_hash": output_hash,
            "tokens_assigned": tokens,
            "token_count": len(tokens)
        })

    def log_restoration(self, tokens_restored: list, unknown_tokens: list) -> AuditEntry:
        """Log PHI restoration event."""
        return self.log(AuditEventType.PHI_RESTORED, {
            "tokens_restored": tokens_restored,
            "unknown_tokens": unknown_tokens,
            "restoration_count": len(tokens_restored)
        })

    def log_error(
        self,
        error_type: str,
        component: str,
        message: str,
        phi_exposed: bool = False
    ) -> AuditEntry:
        """Log error event."""
        return self.log(AuditEventType.ERROR, {
            "error_type": error_type,
            "component": component,
            "message": message,
            "phi_exposed": phi_exposed,
            "stack_hash": hashlib.sha256(message.encode()).hexdigest()[:16]
        })

    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        """
        Verify hash chain integrity.

        Returns:
            (is_valid, error_message)
        """
        result = self.verify_chain_detailed()
        if result["valid"]:
            return True, None
        return False, result.get("first_error")

    def verify_chain_detailed(self) -> Dict:
        """
        Verify hash chain integrity with detailed results.

        Returns dict with:
            - valid: bool - whether chain is fully valid
            - total_entries: int - total entries checked
            - valid_entries: int - entries that passed validation
            - first_error: str - description of first error (if any)
            - first_error_sequence: int - sequence number of first bad entry
            - last_valid_sequence: int - sequence of last known-good entry
            - last_valid_hash: str - hash of last known-good entry
            - errors: list - all errors found

        This information enables recovery by forking from last_valid_sequence.
        """
        rows = self._db.fetchall("""
            SELECT sequence, event_type, timestamp, data, prev_hash, entry_hash
            FROM audit_log WHERE session_id = ?
            ORDER BY sequence ASC
        """, (self._session_id,))

        result = {
            "valid": True,
            "total_entries": len(rows),
            "valid_entries": 0,
            "first_error": None,
            "first_error_sequence": None,
            "last_valid_sequence": 0,
            "last_valid_hash": "GENESIS",
            "errors": [],
        }

        if not rows:
            return result

        prev_hash = "GENESIS"
        last_valid_seq = 0
        last_valid_hash = "GENESIS"

        for i, row in enumerate(rows):
            error = None

            # Check prev_hash links correctly
            if row["prev_hash"] != prev_hash:
                error = f"Chain broken at sequence {row['sequence']}: prev_hash mismatch (expected {prev_hash[:16]}..., got {row['prev_hash'][:16]}...)"

            # Recompute and verify entry_hash
            if not error:
                expected = self._compute_hash(
                    row["sequence"],
                    row["event_type"],
                    row["timestamp"],
                    row["data"],
                    row["prev_hash"]
                )
                if row["entry_hash"] != expected:
                    error = f"Hash mismatch at sequence {row['sequence']}: entry may have been modified"

            # Check sequence is contiguous
            if not error and i > 0:
                prev_row = rows[i - 1]
                if row["sequence"] != prev_row["sequence"] + 1:
                    error = f"Sequence gap before {row['sequence']}: missing entries {prev_row['sequence'] + 1} to {row['sequence'] - 1}"

            if error:
                result["errors"].append(error)
                if result["first_error"] is None:
                    result["valid"] = False
                    result["first_error"] = error
                    result["first_error_sequence"] = row["sequence"]
                # Continue checking to find all errors
            else:
                result["valid_entries"] += 1
                last_valid_seq = row["sequence"]
                last_valid_hash = row["entry_hash"]

            prev_hash = row["entry_hash"]

        result["last_valid_sequence"] = last_valid_seq
        result["last_valid_hash"] = last_valid_hash

        return result

    def fork_chain_after(self, sequence: int) -> Tuple[bool, str]:
        """
        Fork the audit chain after a specific sequence number.

        This is a recovery operation for when the chain is corrupted.
        It deletes corrupted entries at and after sequence+1, then creates
        a CHAIN_FORK event which becomes the new continuation point.

        WARNING: Entries at and after the fork point are DELETED. The
        CHAIN_FORK event records metadata about what was deleted for
        forensic purposes. Consider backing up the database before calling.

        Args:
            sequence: Fork after this sequence number (use 0 to start fresh)

        Returns:
            (success, message)
        """
        verification = self.verify_chain_detailed()

        if verification["valid"]:
            return False, "Chain is valid, no fork needed"

        if sequence > verification["last_valid_sequence"]:
            return False, f"Cannot fork after sequence {sequence}: last valid is {verification['last_valid_sequence']}"

        # Get the hash at the fork point
        if sequence == 0:
            fork_prev_hash = "GENESIS"
        else:
            row = self._db.fetchone("""
                SELECT entry_hash FROM audit_log
                WHERE session_id = ? AND sequence = ?
            """, (self._session_id, sequence))
            if not row:
                return False, f"Sequence {sequence} not found"
            fork_prev_hash = row["entry_hash"]

        # Log a CHAIN_FORK event
        # This becomes the new "genesis" for entries after the corruption
        timestamp = datetime.now(timezone.utc).isoformat() + "Z"
        fork_data = json.dumps({
            "reason": "chain_corruption_recovery",
            "forked_after_sequence": sequence,
            "original_last_valid_sequence": verification["last_valid_sequence"],
            "errors_found": len(verification["errors"]),
            "first_error": verification["first_error"],
        }, sort_keys=True, separators=(",", ":"))

        new_sequence = sequence + 1

        # Compute hash for the fork entry
        entry_hash = self._compute_hash(
            new_sequence,
            "CHAIN_FORK",
            timestamp,
            fork_data,
            fork_prev_hash
        )

        # Insert the fork entry (may conflict with existing bad entries)
        try:
            with self._db.transaction():
                # Delete any entries at or after the fork point for this session
                self._db.conn.execute("""
                    DELETE FROM audit_log
                    WHERE session_id = ? AND sequence >= ?
                """, (self._session_id, new_sequence))

                # Insert the fork entry
                self._db.conn.execute("""
                    INSERT INTO audit_log (sequence, event_type, timestamp, session_id,
                                          data, prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (new_sequence, "CHAIN_FORK", timestamp, self._session_id,
                      fork_data, fork_prev_hash, entry_hash))

            return True, f"Chain forked after sequence {sequence}. {verification['total_entries'] - sequence - 1} entries orphaned."

        except Exception as e:
            return False, f"Fork failed: {e}"

    def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[AuditEventType] = None,
        since: Optional[datetime] = None
    ) -> List[AuditEntry]:
        """
        Get audit entries with filtering.
        
        Args:
            limit: Max entries to return
            offset: Skip this many entries
            event_type: Filter by event type
            since: Only entries after this time
        
        Returns:
            List of AuditEntry
        """
        sql = "SELECT * FROM audit_log WHERE 1=1"
        params = []

        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type.value)

        if since:
            sql += " AND timestamp >= ?"
            params.append(since.isoformat())

        sql += " ORDER BY sequence DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._db.fetchall(sql, tuple(params))

        return [
            AuditEntry(
                sequence=row["sequence"],
                event_type=AuditEventType(row["event_type"]),
                timestamp=datetime.fromisoformat(row["timestamp"].rstrip("Z")),
                session_id=row["session_id"],
                data=json.loads(row["data"]),
                prev_hash=row["prev_hash"],
                entry_hash=row["entry_hash"]
            )
            for row in rows
        ]

    def count(self) -> int:
        """Count total audit entries."""
        row = self._db.fetchone("SELECT COUNT(*) as n FROM audit_log")
        return row["n"] if row else 0

    def size_bytes(self) -> int:
        """
        P3: Get approximate size of audit log in bytes.
        
        Useful for monitoring growth and planning archival.
        """
        # SQLite page_count * page_size gives DB size, but we want just audit
        # Estimate based on row count and average row size (~500 bytes)
        return self.count() * 500

    def export_entries(
        self,
        before: datetime,
        format: str = "jsonl"
    ) -> str:
        """
        P3: Export old entries for archival.
        
        IMPORTANT: This does NOT delete entries. The hash chain must remain
        intact for integrity verification. Use this to create backups that
        can be stored externally, then optionally compact the database.
        
        Args:
            before: Export entries older than this timestamp
            format: Output format ("jsonl" for JSON Lines)
        
        Returns:
            Exported data as string
        """
        rows = self._db.fetchall("""
            SELECT sequence, event_type, timestamp, session_id,
                   data, prev_hash, entry_hash
            FROM audit_log 
            WHERE timestamp < ?
            ORDER BY sequence ASC
        """, (before.isoformat(),))

        if format == "jsonl":
            lines = []
            for row in rows:
                entry = {
                    "sequence": row["sequence"],
                    "event_type": row["event_type"],
                    "timestamp": row["timestamp"],
                    "session_id": row["session_id"],
                    "data": json.loads(row["data"]),
                    "prev_hash": row["prev_hash"],
                    "entry_hash": row["entry_hash"],
                }
                lines.append(json.dumps(entry, sort_keys=True))
            return "\n".join(lines)
        else:
            raise ValueError(f"Unknown format: {format}")

    def get_oldest_timestamp(self) -> Optional[datetime]:
        """Get timestamp of oldest entry."""
        row = self._db.fetchone("""
            SELECT timestamp FROM audit_log ORDER BY sequence ASC LIMIT 1
        """)
        if row:
            return datetime.fromisoformat(row["timestamp"].rstrip("Z"))
        return None

    def get_retention_status(self, retention_days: int = 2190) -> dict:
        """
        P3: Check if any entries are past retention period.
        
        Args:
            retention_days: HIPAA default is 6 years (2190 days)
        
        Returns:
            Dict with retention status info
        """
        oldest = self.get_oldest_timestamp()
        if oldest is None:
            return {
                "total_entries": 0,
                "oldest_entry": None,
                "entries_past_retention": 0,
                "retention_days": retention_days,
            }
        
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        past_retention = self._db.fetchone("""
            SELECT COUNT(*) as n FROM audit_log WHERE timestamp < ?
        """, (cutoff.isoformat(),))
        
        return {
            "total_entries": self.count(),
            "oldest_entry": oldest.isoformat(),
            "entries_past_retention": past_retention["n"] if past_retention else 0,
            "retention_days": retention_days,
            "estimated_size_mb": round(self.size_bytes() / (1024 * 1024), 2),
        }

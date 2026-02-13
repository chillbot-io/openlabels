"""Add label FK constraints and risk_score CHECK constraint

Revision ID: e7f8a9b0c1d3
Revises: c3d4e5f6a7b8
Create Date: 2026-02-13

Adds:
- Foreign key constraints on scan_results.current_label_id and
  scan_results.recommended_label_id referencing sensitivity_labels.id
  with ON DELETE SET NULL so label deletions don't cascade to results.
- CHECK constraint on scan_results.risk_score to enforce 0-100 bounds.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e7f8a9b0c1d3'
down_revision: Union[str, Sequence[str]] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Clean up any orphaned label references before adding FK constraints.
    # This sets label IDs to NULL where the referenced label no longer exists.
    op.execute(
        """
        UPDATE scan_results
        SET current_label_id = NULL
        WHERE current_label_id IS NOT NULL
          AND current_label_id NOT IN (SELECT id FROM sensitivity_labels)
        """
    )
    op.execute(
        """
        UPDATE scan_results
        SET recommended_label_id = NULL
        WHERE recommended_label_id IS NOT NULL
          AND recommended_label_id NOT IN (SELECT id FROM sensitivity_labels)
        """
    )

    # Add FK constraints (supported on partitioned tables in PG 12+)
    op.create_foreign_key(
        "fk_scan_results_current_label",
        "scan_results",
        "sensitivity_labels",
        ["current_label_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_scan_results_recommended_label",
        "scan_results",
        "sensitivity_labels",
        ["recommended_label_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # Clamp any out-of-range risk scores before adding the CHECK constraint
    op.execute(
        """
        UPDATE scan_results
        SET risk_score = LEAST(GREATEST(risk_score, 0), 100)
        WHERE risk_score < 0 OR risk_score > 100
        """
    )

    op.create_check_constraint(
        "ck_scan_results_risk_score_range",
        "scan_results",
        "risk_score >= 0 AND risk_score <= 100",
    )


def downgrade() -> None:
    op.drop_constraint("ck_scan_results_risk_score_range", "scan_results", type_="check")
    op.drop_constraint("fk_scan_results_recommended_label", "scan_results", type_="foreignkey")
    op.drop_constraint("fk_scan_results_current_label", "scan_results", type_="foreignkey")

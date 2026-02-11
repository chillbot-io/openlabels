"""filesystem_engine_v2_directory_tree

Revision ID: a1b2c3d4e5f6
Revises: 5f934314bd30
Create Date: 2026-02-11 15:30:00.000000

Adds three tables for the filesystem engine v2 (folder-only index):
- shares: network share definitions (SMB/NFS/DFS)
- security_descriptors: deduplicated ACL storage keyed by SHA-256
- directory_tree: one row per directory per volume, with tree links
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str]] = '5f934314bd30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create shares, security_descriptors, and directory_tree tables."""

    # ======================================================================
    # shares
    # ======================================================================
    op.create_table(
        'shares',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('scan_targets.id'), nullable=False),
        sa.Column('share_name', sa.String(255), nullable=False),
        sa.Column('share_path', sa.Text(), nullable=False),
        sa.Column('unc_path', sa.Text(), nullable=True),
        sa.Column('protocol', sa.String(10), nullable=False,
                  server_default='smb'),
        sa.Column('share_type', sa.String(20), nullable=True),
        sa.Column('share_permissions', postgresql.JSONB(), nullable=True),
        sa.Column('is_hidden', sa.Boolean(), server_default='false'),
        sa.Column('is_admin_share', sa.Boolean(), server_default='false'),
        sa.Column('discovered_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )
    op.create_index(
        'ix_shares_tenant_target_name',
        'shares', ['tenant_id', 'target_id', 'share_name'],
        unique=True,
    )

    # ======================================================================
    # security_descriptors
    # ======================================================================
    op.create_table(
        'security_descriptors',
        sa.Column('sd_hash', sa.LargeBinary(32), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('owner_sid', sa.String(255), nullable=True),
        sa.Column('group_sid', sa.String(255), nullable=True),
        sa.Column('dacl_sddl', sa.Text(), nullable=True),
        sa.Column('permissions_json', postgresql.JSONB(), nullable=True),
        sa.Column('world_accessible', sa.Boolean(), server_default='false'),
        sa.Column('authenticated_users', sa.Boolean(),
                  server_default='false'),
        sa.Column('custom_acl', sa.Boolean(), server_default='false'),
        sa.Column('discovered_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )
    op.create_index(
        'ix_security_descriptors_tenant',
        'security_descriptors', ['tenant_id'],
    )
    op.create_index(
        'ix_security_descriptors_world',
        'security_descriptors', ['tenant_id'],
        postgresql_where=sa.text('world_accessible = true'),
    )

    # ======================================================================
    # directory_tree
    # ======================================================================
    op.create_table(
        'directory_tree',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('scan_targets.id'), nullable=False),
        # Filesystem-native identifiers
        sa.Column('dir_ref', sa.BigInteger(), nullable=True),
        sa.Column('parent_ref', sa.BigInteger(), nullable=True),
        sa.Column('parent_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('directory_tree.id'), nullable=True),
        # Path
        sa.Column('dir_path', sa.Text(), nullable=False),
        sa.Column('dir_name', sa.String(255), nullable=False),
        # Security
        sa.Column('sd_hash', sa.LargeBinary(32), nullable=True),
        sa.Column('share_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('shares.id'), nullable=True),
        # Metadata
        sa.Column('dir_modified', sa.DateTime(timezone=True), nullable=True),
        sa.Column('child_dir_count', sa.Integer(), nullable=True),
        sa.Column('child_file_count', sa.Integer(), nullable=True),
        sa.Column('flags', sa.Integer(), server_default='0'),
        # Timestamps
        sa.Column('discovered_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True),
                  server_default=sa.func.now()),
    )

    # Unique path per target
    op.create_index(
        'ix_dirtree_tenant_target_path',
        'directory_tree', ['tenant_id', 'target_id', 'dir_path'],
        unique=True,
    )
    # Tree navigation: list children
    op.create_index(
        'ix_dirtree_parent',
        'directory_tree', ['tenant_id', 'parent_id'],
    )
    # Filesystem-native lookups (delta sync)
    op.create_index(
        'ix_dirtree_ref',
        'directory_tree', ['tenant_id', 'target_id', 'dir_ref'],
    )
    # Security analysis: directories sharing a permission set
    op.create_index(
        'ix_dirtree_sd',
        'directory_tree', ['tenant_id', 'sd_hash'],
        postgresql_where=sa.text('sd_hash IS NOT NULL'),
    )
    # Share scoping
    op.create_index(
        'ix_dirtree_share',
        'directory_tree', ['share_id'],
        postgresql_where=sa.text('share_id IS NOT NULL'),
    )


def downgrade() -> None:
    """Drop directory_tree, security_descriptors, and shares tables."""
    op.drop_table('directory_tree')
    op.drop_table('security_descriptors')
    op.drop_table('shares')

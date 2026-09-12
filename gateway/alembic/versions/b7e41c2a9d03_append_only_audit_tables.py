"""make audit tables append-only

Revision ID: b7e41c2a9d03
Revises: 042ffd96435b
Create Date: 2026-09-12 13:40:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "b7e41c2a9d03"
down_revision: str | None = "042ffd96435b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AUDIT_TABLES = ("screening_events", "adjudications", "adjudication_votes")


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION forbid_audit_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit table % is append-only (% blocked)', TG_TABLE_NAME, TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for table in AUDIT_TABLES:
        op.execute(
            f"CREATE TRIGGER {table}_no_mutation BEFORE UPDATE OR DELETE ON {table} "  # noqa: S608
            "FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_mutation()"
        )


def downgrade() -> None:
    for table in AUDIT_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table}")
        op.execute(f"DROP TRIGGER IF EXISTS {table}_no_mutation ON {table}")
    op.execute("DROP FUNCTION IF EXISTS forbid_audit_mutation()")

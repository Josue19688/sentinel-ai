"""add rls
Revision ID: 625c48aca74c
Revises: 625c48aca74b
Create Date: 2026-04-06 19:25:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '625c48aca74c'
down_revision: Union[str, None] = '625c48aca74b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Activar RLS en las tablas principales
    op.execute('''
    DO $$ 
    BEGIN
        -- normalized_features
        IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'normalized_features') THEN
            ALTER TABLE normalized_features ENABLE ROW LEVEL SECURITY;
            DROP POLICY IF EXISTS tenant_isolation ON normalized_features;
            CREATE POLICY tenant_isolation ON normalized_features
                USING (client_id = current_setting('app.current_client_id', TRUE));
        END IF;

        -- ml_recommendations
        IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'ml_recommendations') THEN
            ALTER TABLE ml_recommendations ENABLE ROW LEVEL SECURITY;
            DROP POLICY IF EXISTS tenant_isolation ON ml_recommendations;
            CREATE POLICY tenant_isolation ON ml_recommendations
                USING (client_id = current_setting('app.current_client_id', TRUE));
        END IF;

        -- assets
        IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'assets') THEN
            ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
            DROP POLICY IF EXISTS tenant_isolation ON assets;
            CREATE POLICY tenant_isolation ON assets
                USING (client_id = current_setting('app.current_client_id', TRUE));
        END IF;
    END $$;
    ''')


def downgrade() -> None:
    op.execute('''
    DO $$ 
    BEGIN
        IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'normalized_features') THEN
            ALTER TABLE normalized_features DISABLE ROW LEVEL SECURITY;
            DROP POLICY IF EXISTS tenant_isolation ON normalized_features;
        END IF;

        IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'ml_recommendations') THEN
            ALTER TABLE ml_recommendations DISABLE ROW LEVEL SECURITY;
            DROP POLICY IF EXISTS tenant_isolation ON ml_recommendations;
        END IF;

        IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'assets') THEN
            ALTER TABLE assets DISABLE ROW LEVEL SECURITY;
            DROP POLICY IF EXISTS tenant_isolation ON assets;
        END IF;
    END $$;
    ''')

"""run_all_legacy_migrations

Revision ID: 625c48aca74b
Revises: 625c48aca74a
Create Date: 2026-04-06 19:15:00.000000

"""
import os
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '625c48aca74b'
down_revision: Union[str, None] = '625c48aca74a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Ensure all legacy SQL migrations are executed here so the DB state matches
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    migrations_dir = os.path.join(base_dir, 'migrations')
    
    files = [
        '001_auth_users.sql',
        '002_auth_api_keys.sql',
        '003_risk_metrics.sql',
        'add_risk_fields_to_recommendations.sql'
    ]
    
    for f in files:
        filepath = os.path.join(migrations_dir, f)
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as sql_file:
                sql_content = sql_file.read()
                # Run the sql statements
                op.execute(sa.text(sql_content))

def downgrade() -> None:
    pass

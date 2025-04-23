"""
Add is_discovered to Node model

Revision ID: 20250423153311
Revises: 42eaa5132467
Create Date: 2025-04-23 15:33:11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic
revision = '20250423153311'
down_revision = '42eaa5132467'
branch_labels = None
depends_on = None


def upgrade():
    # Check if column already exists before trying to add it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [col['name'] for col in inspector.get_columns('nodes')]
    
    # Only add the column if it doesn't exist
    if 'is_discovered' not in columns:
        op.add_column('nodes', sa.Column('is_discovered', sa.Boolean(), nullable=True))
    
    # Set default values for existing rows regardless
    op.execute('UPDATE nodes SET is_discovered = 0 WHERE is_discovered IS NULL')


def downgrade():
    # Check if column exists before trying to remove it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [col['name'] for col in inspector.get_columns('nodes')]
    
    if 'is_discovered' in columns:
        op.drop_column('nodes', 'is_discovered')

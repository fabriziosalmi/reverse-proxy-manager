"""Add GeoIP features to Site model

Revision ID: a12e3695b0db
Revises: 7709fc32742e
Create Date: 2025-04-23 21:37:52.800262

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a12e3695b0db'
down_revision = '7709fc32742e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sites', schema=None) as batch_op:
        batch_op.add_column(sa.Column('use_geoip', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('geoip_mode', sa.String(length=10), nullable=True))
        batch_op.add_column(sa.Column('geoip_countries', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('geoip_level', sa.String(length=10), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sites', schema=None) as batch_op:
        batch_op.drop_column('geoip_level')
        batch_op.drop_column('geoip_countries')
        batch_op.drop_column('geoip_mode')
        batch_op.drop_column('use_geoip')

    # ### end Alembic commands ###

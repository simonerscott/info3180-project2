"""empty message

Revision ID: 57654ecea803
Revises: f2506126b2bd
Create Date: 2017-05-01 00:44:25.733985

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '57654ecea803'
down_revision = 'f2506126b2bd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('wishlist')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('wishlist',
    sa.Column('title', sa.VARCHAR(length=80), autoincrement=False, nullable=True),
    sa.Column('description', sa.VARCHAR(length=80), autoincrement=False, nullable=True),
    sa.Column('address', sa.VARCHAR(length=80), autoincrement=False, nullable=True),
    sa.Column('itemid', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('userid', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['userid'], [u'user.userid'], name=u'wishlist_userid_fkey')
    )
    # ### end Alembic commands ###

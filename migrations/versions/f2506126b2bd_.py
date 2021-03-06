"""empty message

Revision ID: f2506126b2bd
Revises: 6eff87a68023
Create Date: 2017-04-29 03:49:06.788309

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f2506126b2bd'
down_revision = '6eff87a68023'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wishlist', sa.Column('itemid', sa.Integer(), nullable=False))
    op.add_column('wishlist', sa.Column('userid', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'wishlist', 'user', ['userid'], ['userid'])
    op.drop_column('wishlist', 'wish_id')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wishlist', sa.Column('wish_id', sa.INTEGER(), nullable=False))
    op.drop_constraint(None, 'wishlist', type_='foreignkey')
    op.drop_column('wishlist', 'userid')
    op.drop_column('wishlist', 'itemid')
    # ### end Alembic commands ###

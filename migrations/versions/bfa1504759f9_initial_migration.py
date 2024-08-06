from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision = '234'
down_revision = '12345'
branch_labels = None
depends_on = None

# Define the enum type without creating it immediately
userrole_enum = postgresql.ENUM('USER', 'ADMIN', name='userrole', create_type=False)

def upgrade():
    conn = op.get_bind()
    
    # Create the enum type if it doesn't exist
    if not conn.dialect.has_type(conn, 'userrole'):
        userrole_enum.create(op.get_bind(), checkfirst=True)

    # Create the table with the enum column
    op.create_table(
        'user',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String(length=64), unique=True, nullable=False),
        sa.Column('first_name', sa.String(length=64), nullable=False),
        sa.Column('last_name', sa.String(length=64), nullable=False),
        sa.Column('password', sa.String(length=128), nullable=False),
        sa.Column('email', sa.String(length=120), unique=True, nullable=False),
        sa.Column('role', userrole_enum, nullable=False, server_default='USER'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=True, onupdate=sa.func.now()),
        sa.Column('active', sa.Boolean(), nullable=False, server_default='True'),
        sa.Column('reset_token', sa.String(length=32), unique=True, nullable=True),
    )

def downgrade():
    op.drop_table('user')
    userrole_enum.drop(op.get_bind(), checkfirst=True)

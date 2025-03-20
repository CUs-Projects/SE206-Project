from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

def upgrade():
    """Add program_id column to application table"""
    op.add_column('application', sa.Column('program_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'application', 'program', ['program_id'], ['id'])

def downgrade():
    """Remove program_id column from application table"""
    op.drop_constraint(None, 'application', type_='foreignkey')
    op.drop_column('application', 'program_id')
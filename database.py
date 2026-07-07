import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

# Get database URL from environment
db_url = os.environ.get('DATABASE_URL', '')

# Vercel Postgres uses postgres:// but SQLAlchemy needs postgresql://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# If no remote DB provided (local dev), use SQLite
# On Vercel with no DATABASE_URL, use /tmp which is the only writable directory
if not db_url:
    # Use /tmp for serverless environments (like Vercel AWS Lambda) where root is read-only
    db_url = 'sqlite:////tmp/sliceguard.db' if os.environ.get('VERCEL') or os.environ.get('AWS_EXECUTION_ENV') else 'sqlite:///sliceguard.db'

# SQLite needs check_same_thread=False; Postgres does not
connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True
)

db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    # import all modules here that might define models so that
    # they are registered properly on the metadata.
    import models
    Base.metadata.create_all(bind=engine)

"""
UniGuard Database Configuration (Milestone 8, Hardened in Milestone 15)

Initializes SQLAlchemy engine and session factory using DATABASE_URL from config.
Handles connection failures gracefully to prevent crashing environments without Postgres.
Configures robust connection pooling and pre-ping checks for production PostgreSQL.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings
from backend.app.db.base import Base

# By default, use sqlite if DATABASE_URL is entirely absent, 
# but if configured for postgres, use it with production-grade pooling.
DATABASE_URL = settings.database_url
if not DATABASE_URL:
    # Safe fallback for local unconfigured development
    DATABASE_URL = "sqlite:///./uniguard.db"

connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,  # Test connection health before acquiring from pool
}

if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
else:
    # PostgreSQL production pool configuration
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
        "pool_recycle": 1800,
    })

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI Dependency for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_health() -> bool:
    """Return True if the database can execute a basic query, False otherwise."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

"""
UniGuard Database Initialization (Milestone 8)

Safe schema creation for development. Does not perform destructive migrations.
"""

from backend.app.db.database import engine
from backend.app.db.models import Base
import logging

logger = logging.getLogger(__name__)

def init_db():
    """
    Create tables if they do not exist.
    This is safe to run multiple times, it will not drop existing data.
    """
    logger.info("Initializing database schema...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialization complete.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise e

if __name__ == "__main__":
    init_db()

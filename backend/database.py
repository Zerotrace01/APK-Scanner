"""
DroidScan — database.py
========================
SQLAlchemy models and session factory.
"""

from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://droidscan:droidscan@localhost/droidscan"
)

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base         = declarative_base()


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id            = Column(String,   primary_key=True)
    filename      = Column(String,   nullable=False)
    status        = Column(String,   default="QUEUED")   # QUEUED|RUNNING|DONE|FAILED
    progress      = Column(Integer,  default=0)           # 0–100
    submitted_at  = Column(DateTime, default=datetime.utcnow)
    completed_at  = Column(DateTime, nullable=True)
    results_json  = Column(Text,     nullable=True)
    error_message = Column(Text,     nullable=True)


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)

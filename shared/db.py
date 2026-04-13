"""
Database connection and session management (The Keeper)
"""

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Float, Integer, DateTime, JSON, Enum as SAEnum
from sqlalchemy.sql import func
from shared.models.test_result import TestStatus, VulnerabilityLevel

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://saptara_keeper:seven_relics_unite@database:5432/saptara_knowledge"
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class ScanResultRow(Base):
    """Persisted scan result row"""
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True)
    scan_id = Column(String, nullable=False, index=True)
    service_name = Column(String, nullable=False)
    category = Column(String, nullable=False)
    test_name = Column(String, nullable=False)
    status = Column(SAEnum(TestStatus), nullable=False)
    vulnerability_level = Column(SAEnum(VulnerabilityLevel), nullable=True)
    target_url = Column(String, nullable=False)
    method = Column(String, default="GET")
    payload = Column(String, nullable=True)
    response_code = Column(Integer, nullable=True)
    response_time = Column(Float, nullable=True)
    details = Column(String, nullable=True)
    evidence = Column(JSON, nullable=True)
    recommendations = Column(String, nullable=True)
    metadata_ = Column("metadata", JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())


class ScanJobRow(Base):
    """Persisted scan job record"""
    __tablename__ = "scan_jobs"

    scan_id = Column(String, primary_key=True)
    service_name = Column(String, nullable=False)
    target_url = Column(String, nullable=False)
    status = Column(String, nullable=False, default="running")
    progress = Column(Float, default=0.0)
    results_count = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    config = Column(JSON, nullable=True)
    service_results = Column(JSON, nullable=True)   # orchestrator: full service result map
    error = Column(String, nullable=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)


async def init_db():
    """Create all tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    """Yield a database session"""
    async with AsyncSessionLocal() as session:
        yield session


def sanitize(value: str | None) -> str | None:
    """
    Strip null bytes from strings before inserting into PostgreSQL.
    asyncpg raises CharacterNotInRepertoireError on \\x00 in UTF-8 columns.
    """
    if value is None:
        return None
    return value.replace("\x00", "")

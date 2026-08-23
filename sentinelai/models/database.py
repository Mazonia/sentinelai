"""
Database Models using SQLAlchemy 2.0
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
import json
import os

from sqlalchemy import (
    Column, Integer, String, Float, DateTime, 
    Boolean, Text, ForeignKey, JSON, Enum,
    create_engine, select
)
from sqlalchemy.ext.asyncio import (
    AsyncSession, 
    create_async_engine,
    async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    pass


class ScanStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(50), ForeignKey("scan_results.scan_id"), index=True)
    
    # Vulnerability details
    type = Column(String(50), nullable=False, index=True)  # sql_injection, xss, etc.
    subtype = Column(String(50), nullable=True)
    severity = Column(Enum(Severity), nullable=False)
    confidence = Column(Float, default=0.5)  # AI confidence score
    
    # Location
    url = Column(Text, nullable=False)
    parameter = Column(String(255), nullable=True)
    payload = Column(Text, nullable=True)
    
    # Evidence and details
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)
    remediation = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    
    # AI analysis
    risk_score = Column(Float, nullable=True)
    exploit_complexity = Column(String(50), nullable=True)
    false_positive = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    exploitation_confirmed = Column(Boolean, default=False)
    exploitation_proof = Column(Text, nullable=True)
    
    # Metadata
    module = Column(String(50), nullable=False)  # Which detector found it
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("ScanResult", back_populates="vulnerabilities")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type,
            'subtype': self.subtype,
            'severity': self.severity.value if self.severity else None,
            'confidence': self.confidence,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'ai_remediation': self.ai_remediation,
            'risk_score': self.risk_score,
            'exploit_complexity': self.exploit_complexity,
            'false_positive': self.false_positive,
            'notes': self.notes,
            'exploitation_confirmed': self.exploitation_confirmed,
            'exploitation_proof': self.exploitation_proof,
            'module': self.module,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ScanResult(Base):
    __tablename__ = "scan_results"
    
    scan_id = Column(String(50), primary_key=True, index=True)
    target = Column(Text, nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    
    # Timing
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    
    # Statistics
    pages_discovered = Column(Integer, default=0)
    pages_scanned = Column(Integer, default=0)
    vulnerability_count = Column(Integer, default=0)
    
    # Configuration
    config = Column(JSON, nullable=True)
    
    # Results
    findings = Column(JSON, nullable=True)  # Store as JSON for quick access
    discovered_urls = Column(JSON, nullable=True)
    scanned_urls = Column(JSON, nullable=True)
    report_path = Column(String(500), nullable=True)
    
    # Relationships
    vulnerabilities = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan", foreign_keys="[Vulnerability.scan_id]") if False else relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'status': self.status.value if self.status else None,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else None,
            'pages_discovered': self.pages_discovered,
            'pages_scanned': self.pages_scanned,
            'vulnerability_count': self.vulnerability_count,
            'discovered_urls': self.discovered_urls or [],
            'scanned_urls': self.scanned_urls or [],
        }


class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    url = Column(Text, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    
    # Authentication
    auth_type = Column(String(50), nullable=True)  # none, basic, bearer, cookie
    auth_config = Column(JSON, nullable=True)
    
    # Scanning preferences
    scan_frequency = Column(String(50), default="manual")  # manual, daily, weekly
    last_scan = Column(DateTime, nullable=True)
    
    # Metadata
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    owner = relationship("User", back_populates="targets")


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    targets = relationship("Target", back_populates="owner")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://sentinel:sentinel@localhost/sentinelai")


# Create async engine
engine = create_async_engine(DATABASE_URL, echo=False)
async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_async_session() -> AsyncSession:
    """Get database session"""
    async with async_session_maker() as session:
        yield session


async def init_db():
    """Initialize database tables with retry logic"""
    import asyncio
    import logging
    logger = logging.getLogger(__name__)
    
    max_retries = 15
    retry_delay = 3
    
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Database connection attempt {attempt}/{max_retries}...")
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables initialized successfully.")
            return
        except Exception as e:
            if attempt == max_retries:
                logger.error(f"Failed to connect to database after {max_retries} attempts.")
                raise e
            logger.warning(f"Database connection failed: {e}. Retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)
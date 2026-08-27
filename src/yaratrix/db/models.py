from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .session import Base

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String, index=True, default="pending")  # pending, running, completed, failed
    target_path = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    artifacts = relationship("FileArtifact", back_populates="job")


class FileArtifact(Base):
    __tablename__ = "file_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    file_path = Column(String, index=True)
    file_hash = Column(String, index=True)  # SHA256
    file_size = Column(Integer)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
    confidence_score = Column(Float, default=0.0)
    
    job = relationship("ScanJob", back_populates="artifacts")
    match_events = relationship("MatchEvent", back_populates="artifact")


class MatchEvent(Base):
    __tablename__ = "match_events"

    id = Column(Integer, primary_key=True, index=True)
    artifact_id = Column(Integer, ForeignKey("file_artifacts.id"))
    rule_name = Column(String, index=True)
    mitre_techniques = Column(String)  # Comma separated technique IDs
    mitre_tactics = Column(String)     # Comma separated tactics
    severity = Column(String)
    description = Column(Text)
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    artifact = relationship("FileArtifact", back_populates="match_events")

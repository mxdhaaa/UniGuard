"""
UniGuard SQLAlchemy ORM Models (Milestone 8)

Defines the persistent tables for flows, features, ML results, risk assessments,
evidence items, and alerts. These models correspond to the domain schemas.
"""

from __future__ import annotations

import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Integer, Float, Boolean, ForeignKey, DateTime, JSON
from sqlalchemy.orm import relationship

from backend.app.db.base import Base


class TrafficFlowModel(Base):
    __tablename__ = "traffic_flows"

    flow_id = Column(String, primary_key=True, index=True)
    source_ip = Column(String, nullable=False, index=True)
    destination_ip = Column(String, nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    duration = Column(Float, nullable=False)
    packet_count = Column(Integer, nullable=False)
    byte_count = Column(Integer, nullable=False)
    feature_schema_version = Column(String, nullable=False, default="1.0")
    timestamp = Column(String, nullable=False)  # ISO 8601 string
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    # Relationships
    features = relationship("FeatureModel", back_populates="flow", uselist=False, cascade="all, delete-orphan")
    ml_result = relationship("MLResultModel", back_populates="flow", uselist=False, cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessmentModel", back_populates="flow", uselist=False, cascade="all, delete-orphan")
    evidence = relationship("EvidenceModel", back_populates="flow", cascade="all, delete-orphan")
    alert = relationship("AlertModel", back_populates="flow", uselist=False, cascade="all, delete-orphan")


class FeatureModel(Base):
    __tablename__ = "features"

    flow_id = Column(String, ForeignKey("traffic_flows.flow_id", ondelete="CASCADE"), primary_key=True)
    
    # 16 Canonical Features
    flow_duration = Column(Float, nullable=False)
    packet_count = Column(Float, nullable=False)
    byte_count = Column(Float, nullable=False)
    packets_per_second = Column(Float, nullable=False)
    bytes_per_second = Column(Float, nullable=False)
    average_packet_size = Column(Float, nullable=False)
    packet_size_std = Column(Float, nullable=False)
    unique_destination_count = Column(Float, nullable=False)
    unique_destination_port_count = Column(Float, nullable=False)
    destination_port_entropy = Column(Float, nullable=False)
    packet_size_entropy = Column(Float, nullable=False)
    burst_score = Column(Float, nullable=False)
    source_activity_rate = Column(Float, nullable=False)
    destination_diversity = Column(Float, nullable=False)
    port_diversity = Column(Float, nullable=False)
    protocol_indicator = Column(Float, nullable=False)

    feature_schema_version = Column(String, nullable=False, default="1.0")
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    flow = relationship("TrafficFlowModel", back_populates="features")


class MLResultModel(Base):
    __tablename__ = "ml_results"

    flow_id = Column(String, ForeignKey("traffic_flows.flow_id", ondelete="CASCADE"), primary_key=True)
    threat_type = Column(String, nullable=False, index=True)
    classifier_confidence = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    is_anomaly = Column(Boolean, nullable=False)
    model_version = Column(String, nullable=False)
    
    # Stored as JSONB in PostgreSQL
    class_probabilities = Column(JSON, nullable=False)
    feature_importances = Column(JSON, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    flow = relationship("TrafficFlowModel", back_populates="ml_result")


class RiskAssessmentModel(Base):
    __tablename__ = "risk_assessments"

    flow_id = Column(String, ForeignKey("traffic_flows.flow_id", ondelete="CASCADE"), primary_key=True)
    risk_score = Column(Float, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    threat_type = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    is_anomaly = Column(Boolean, nullable=False)
    explanation = Column(String, nullable=False)
    recommended_action = Column(String, nullable=False)
    
    # Stored as JSONB
    risk_factors = Column(JSON, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    flow = relationship("TrafficFlowModel", back_populates="risk_assessment")


class EvidenceModel(Base):
    __tablename__ = "evidence_items"

    evidence_id = Column(String, primary_key=True, index=True)
    flow_id = Column(String, ForeignKey("traffic_flows.flow_id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    value_str = Column(String, nullable=True) # Serialized representation for display/storage
    contribution = Column(Float, nullable=False)
    source = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    feature_name = Column(String, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    flow = relationship("TrafficFlowModel", back_populates="evidence")


class AlertModel(Base):
    __tablename__ = "alerts"

    alert_id = Column(String, primary_key=True, index=True)
    flow_id = Column(String, ForeignKey("traffic_flows.flow_id", ondelete="CASCADE"), nullable=False, unique=True)
    threat_type = Column(String, nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    severity = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, index=True, default="OPEN") # OPEN, ACKNOWLEDGED, RESOLVED
    summary = Column(String, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=datetime.datetime.now(datetime.timezone.utc))

    flow = relationship("TrafficFlowModel", back_populates="alert")

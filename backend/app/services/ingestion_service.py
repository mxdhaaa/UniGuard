"""
UniGuard Ingestion Orchestration Service (Milestone 10)

Manages the LiveTrafficCollector and pushes expired directional flows through
the existing M3-M9 analysis and persistence pipeline. Provides thread-safe API controls.
"""

import threading
import logging
from typing import Dict, Any, Optional

from backend.app.config import settings
from backend.app.collectors.live_collector import LiveTrafficCollector
from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.schemas.ingestion import IngestionStatusResponse

from backend.app.core.feature_engine import FeatureEngine
from backend.app.ml.inference import run_inference
from backend.app.core.risk_engine import risk_engine
from backend.app.core.evidence_engine import evidence_engine
from backend.app.services.persistence_service import persistence_service
from backend.app.db.database import SessionLocal

logger = logging.getLogger(__name__)

class IngestionService:
    def __init__(self):
        self._lock = threading.Lock()
        self.collector: Optional[LiveTrafficCollector] = None
        self.feature_engine = FeatureEngine()
        
    def get_status(self) -> IngestionStatusResponse:
        with self._lock:
            if not self.collector:
                return IngestionStatusResponse(
                    state="STOPPED",
                    interface=settings.capture_interface or "ANY",
                    capture_filter=settings.capture_filter,
                    active_flows=0,
                    packets_captured=0,
                    flows_completed=0,
                    errors=0
                )
                
            return IngestionStatusResponse(
                state="RUNNING" if self.collector.is_running else "STOPPED",
                interface=self.collector.interface or "ANY",
                capture_filter=self.collector.bpf_filter,
                active_flows=len(self.collector.active_flows),
                packets_captured=self.collector.packets_captured,
                flows_completed=self.collector.flows_completed,
                errors=self.collector.errors
            )

    def start(self) -> IngestionStatusResponse:
        with self._lock:
            if self.collector and self.collector.is_running:
                return self.get_status()
                
            self.collector = LiveTrafficCollector(
                interface=settings.capture_interface,
                bpf_filter=settings.capture_filter,
                idle_timeout=settings.flow_idle_timeout,
                max_duration=settings.flow_max_duration,
                on_flow_expired=self._process_expired_flow
            )
            self.collector.start()
            
        return self.get_status()

    def stop(self) -> IngestionStatusResponse:
        with self._lock:
            if self.collector and self.collector.is_running:
                self.collector.stop()
                self.collector.flush() # Ensure any remaining flows are processed
        return self.get_status()

    def _process_expired_flow(self, flow: DirectionalFlowRecord) -> None:
        """
        Executed in the background collector thread.
        Pushes a completed flow through the entire M3-M9 pipeline.
        """
        # Create a fresh database session for this flow's transaction
        db = SessionLocal()
        try:
            # Feature extraction
            features = self.feature_engine.extract_features(flow)
            
            # ML Inference
            ml_result = run_inference(flow)
            
            # Risk Engine
            risk = risk_engine.assess(ml_result)
            
            # Evidence Engine
            evidence = evidence_engine.assess(flow, ml_result, risk)
            
            # Persistence (M8) & Alert Broadcast (M9)
            persistence_service.save_analysis_result(db, flow, features, ml_result, risk, evidence)
            
        except Exception as e:
            logger.error(f"Pipeline error processing flow {flow.flow_id}: {e}")
            raise e
        finally:
            db.close()

# Singleton instance
ingestion_service = IngestionService()

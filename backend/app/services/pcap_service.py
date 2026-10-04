"""
UniGuard PCAP Orchestration Service (Milestone 11)

Manages background jobs for PCAP/PCAPNG file processing. Orchestrates the 
PcapCollector and pushes expired directional flows through the existing M3-M9 
analysis and persistence pipeline safely.
"""

import os
import uuid
import threading
import logging
from typing import Dict, Optional

from backend.app.config import settings
from backend.app.schemas.pcap import PcapJobStatusResponse, PcapJobUploadResponse
from backend.app.collectors.pcap_collector import PcapCollector
from backend.app.schemas.traffic import DirectionalFlowRecord

from backend.app.core.feature_engine import FeatureEngine
from backend.app.ml.inference import run_inference
from backend.app.core.risk_engine import risk_engine
from backend.app.core.evidence_engine import evidence_engine
from backend.app.services.persistence_service import persistence_service
from backend.app.db.database import SessionLocal

logger = logging.getLogger(__name__)


class PcapService:
    def __init__(self):
        self._lock = threading.Lock()
        self.jobs: Dict[str, PcapJobStatusResponse] = {}
        self.feature_engine = FeatureEngine()
        
    def start_job(self, file_path: str, original_filename: str) -> PcapJobUploadResponse:
        """Initialize a new job and spawn the background worker."""
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        
        with self._lock:
            self.jobs[job_id] = PcapJobStatusResponse(
                job_id=job_id,
                status="PROCESSING",
                filename=original_filename
            )
            
        thread = threading.Thread(
            target=self._process_job,
            args=(job_id, file_path),
            daemon=True
        )
        thread.start()
        
        return PcapJobUploadResponse(
            job_id=job_id,
            status="PROCESSING",
            message="PCAP uploaded successfully. Processing started in background."
        )

    def get_job_status(self, job_id: str) -> Optional[PcapJobStatusResponse]:
        with self._lock:
            return self.jobs.get(job_id)

    def _process_job(self, job_id: str, file_path: str):
        """Background worker that reads the PCAP and orchestrates the pipeline."""
        collector = PcapCollector(
            pcap_path=file_path,
            idle_timeout=settings.flow_idle_timeout,
            max_duration=settings.flow_max_duration,
            on_flow_expired=self._process_expired_flow
        )
        
        try:
            total_packets, flows_completed, errors = collector.process()
            
            with self._lock:
                job = self.jobs[job_id]
                job.total_packets = total_packets
                job.flows_completed = flows_completed
                job.errors = errors
                job.status = "COMPLETED"
                job.message = "Processing finished successfully."
                
        except Exception as e:
            with self._lock:
                job = self.jobs[job_id]
                job.total_packets = collector.total_packets
                job.flows_completed = collector.flows_completed
                job.errors = collector.errors + 1
                job.status = "FAILED"
                job.message = f"Failed during processing: {e}"
        finally:
            # Privacy / Cleanup: ALWAYS delete the temporary PCAP file
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except OSError as e:
                logger.error(f"Failed to delete temporary PCAP {file_path}: {e}")

    def _process_expired_flow(self, flow: DirectionalFlowRecord) -> None:
        """
        Executed in the background job thread per completed flow.
        Pushes the flow through the entire M3-M9 pipeline safely.
        """
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
            logger.error(f"Pipeline error processing PCAP flow {flow.flow_id}: {e}")
            raise e
        finally:
            db.close()


# Singleton instance
pcap_service = PcapService()

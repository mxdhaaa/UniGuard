"""
UniGuard Persistence Service (Milestone 8)

Orchestrates atomic saving of a full pipeline analysis:
Flow + Features + MLResult + RiskAssessment + EvidenceAssessment.
Optionally generates an Alert if Risk is HIGH or CRITICAL.
"""

import asyncio
import uuid
from typing import Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector
from backend.app.schemas.ml import UnifiedMLResult
from backend.app.schemas.risk import RiskAssessment, Severity
from backend.app.schemas.evidence import EvidenceAssessment
from backend.app.db import repositories
from backend.app.services.websocket_manager import websocket_manager


class PersistenceService:
    def _broadcast_alert(self, alert_payload: Dict[str, Any]) -> None:
        """Broadcast an alert after a successful database commit."""
        try:
            asyncio.run(websocket_manager.broadcast(alert_payload))
        except Exception:
            # WebSocket failures must never undo successful persistence.
            pass

    def save_analysis_result(
        self,
        db: Session,
        flow: DirectionalFlowRecord,
        features: FeatureVector,
        ml_result: UnifiedMLResult,
        risk: RiskAssessment,
        evidence: EvidenceAssessment
    ) -> Dict[str, Any]:
        """
        Atomically persist a complete analysis result.
        Returns a dictionary of persisted IDs.
        """

        existing_flow = repositories.get_flow(db, flow.flow_id)
        if existing_flow:
            return {"status": "skipped", "reason": "flow_id already exists"}

        try:
            # 1. Flow
            repositories.save_flow(db, flow)

            # 2. Features
            repositories.save_features(db, flow.flow_id, features)

            # 3. ML Result
            repositories.save_ml_result(db, flow.flow_id, ml_result)

            # 4. Risk Assessment
            repositories.save_risk_assessment(db, flow.flow_id, risk)

            # 5. Evidence
            repositories.save_evidence(db, flow.flow_id, evidence)

            # 6. Alert Creation Rule
            alert_id = None

            if risk.severity in (Severity.HIGH, Severity.CRITICAL):
                alert_id = f"ALRT-{uuid.uuid4().hex[:8].upper()}"

                repositories.save_alert(
                    db=db,
                    alert_id=alert_id,
                    flow_id=flow.flow_id,
                    threat_type=risk.threat_type,
                    risk_score=risk.risk_score,
                    severity=risk.severity.value,
                    summary=evidence.summary
                )

            # 7. Commit all persistence changes first.
            db.commit()

            # 8. Broadcast only after a successful commit.
            if alert_id:
                self._broadcast_alert(
                    {
                        "event": "alert",
                        "alert_id": alert_id,
                        "flow_id": flow.flow_id,
                        "threat_type": risk.threat_type,
                        "risk_score": risk.risk_score,
                        "severity": risk.severity.value,
                        "status": "OPEN",
                        "summary": evidence.summary,
                    }
                )

            return {
                "status": "success",
                "flow_id": flow.flow_id,
                "alert_id": alert_id
            }

        except IntegrityError as e:
            db.rollback()
            return {
                "status": "error",
                "reason": f"Integrity error (duplicate?): {e}"
            }

        except Exception as e:
            db.rollback()
            raise e


persistence_service = PersistenceService()
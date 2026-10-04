"""
UniGuard Demo Service
Orchestrates the safe synthetic flow generation pipeline:
Collector -> Directional Flow -> Feature Engine -> Preprocessor -> DemoResult.
"""

from typing import List, Dict, Optional
from backend.app.schemas.demo import (
    DemoState,
    DemoStatusResponse,
    DemoResultItem,
)
from backend.app.collectors.demo_collector import (
    DemoTrafficCollector,
    DEFAULT_PROFILE_MIX,
    VALID_PROFILES,
)
from backend.app.core.feature_engine import FeatureEngine
from backend.app.core.preprocessing import FeaturePreprocessor
from backend.app.ml.inference import run_inference
from backend.app.core.risk_engine import risk_engine
from backend.app.core.evidence_engine import evidence_engine
from backend.app.services.persistence_service import persistence_service
from backend.app.db.database import SessionLocal


class DemoService:
    """
    Manages operational lifecycle state and execution of the synthetic demo pipeline.
    """

    def __init__(self, default_seed: int = 42) -> None:
        self.state: DemoState = DemoState.STOPPED
        self.seed: Optional[int] = default_seed
        self.profile_mix: Dict[str, float] = dict(DEFAULT_PROFILE_MIX)
        self.generated_flows_count: int = 0
        self._collector = DemoTrafficCollector(seed=self.seed)

    def start(self, seed: Optional[int] = None, profile_mix: Optional[Dict[str, float]] = None) -> DemoStatusResponse:
        """Starts or resumes demo simulation with optional seed / custom profile mix."""
        if seed is not None:
            self.seed = seed
            self._collector.set_seed(seed)
        if profile_mix is not None:
            self._validate_profile_mix(profile_mix)
            self.profile_mix = profile_mix

        self.state = DemoState.RUNNING
        return self.get_status()

    def pause(self) -> DemoStatusResponse:
        """Pauses the demo simulation."""
        self.state = DemoState.PAUSED
        return self.get_status()

    def stop(self) -> DemoStatusResponse:
        """Stops the demo simulation."""
        self.state = DemoState.STOPPED
        return self.get_status()

    def clear(self) -> DemoStatusResponse:
        """Resets the demo simulation state and counters."""
        self.state = DemoState.STOPPED
        self.generated_flows_count = 0
        self._collector.set_seed(self.seed)
        return self.get_status()

    def get_status(self) -> DemoStatusResponse:
        """Returns the current state and metrics of the demo engine."""
        return DemoStatusResponse(
            state=self.state,
            generated_flows=self.generated_flows_count,
            seed=self.seed,
            active_profile_mix=self.profile_mix,
            disclaimer="Demo traffic is synthetic and is not evidence of real-world malicious activity.",
        )

    def _validate_profile_mix(self, mix: Dict[str, float]) -> None:
        """Validates that all profile keys are legitimate and weights sum to ~1.0."""
        for key in mix.keys():
            if key not in VALID_PROFILES:
                raise ValueError(f"Invalid profile key '{key}'. Allowed: {VALID_PROFILES}")
        total = sum(mix.values())
        if total <= 0.0 or abs(total - 1.0) > 0.05:
            raise ValueError(f"Profile mix weights must sum to approximately 1.0, got {total}")

    def generate_batch(
        self,
        count: int = 20,
        profile_mix: Optional[Dict[str, float]] = None,
        seed: Optional[int] = None,
    ) -> List[DemoResultItem]:
        """
        Executes the complete pipeline for a synthetic batch:
        DirectionalFlowRecord -> FeatureEngine (with context) -> FeaturePreprocessor -> DemoResultItem.
        """
        if count <= 0:
            raise ValueError(f"Count must be a positive integer, got {count}")

        if seed is not None:
            self._collector.set_seed(seed)

        mix = profile_mix or self.profile_mix
        self._validate_profile_mix(mix)

        # 1. Generate raw directional flows
        flows = self._collector.generate_batch(count=count, profile_mix=mix)

        results: List[DemoResultItem] = []
        db = SessionLocal()
        try:
            for flow in flows:
                features = FeatureEngine.extract_features(flow, context_flows=flows)
                ml_result = run_inference(flow)
                risk = risk_engine.assess(ml_result)
                evidence = evidence_engine.assess(flow, ml_result, risk)
                persistence_service.save_analysis_result(
                    db,
                    flow,
                    features,
                    ml_result,
                    risk,
                    evidence,
                )
                preprocessed = FeaturePreprocessor.preprocess(features)
                profile_label = flow.metadata.get("simulated_profile", "UNKNOWN")
                results.append(
                    DemoResultItem(
                        flow=flow,
                        features=features,
                        preprocessed=preprocessed,
                        simulated_profile=profile_label,
                    )
                )
        finally:
            db.close()
        self.generated_flows_count += len(results)
        return results


# Global singleton instance for application session
demo_service = DemoService()


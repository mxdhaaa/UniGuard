"""
Base Detector Interface for UniGuard MVP Detectors.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from ..schemas import FlowRecord, DetectionResult


class BaseDetector(ABC):
    """
    Abstract Base Class for all UniGuard threat detectors.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def analyze(self, flow: FlowRecord, features: Dict[str, Any], context_flows: Optional[List[FlowRecord]] = None) -> Optional[DetectionResult]:
        """
        Analyzes a flow and features.
        Returns DetectionResult if threat is detected with confidence > threshold, else None.
        """
        pass

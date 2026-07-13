from pydantic import BaseModel
from typing import List, Optional
from .request import RequestModel
from .features import FeaturesModel

class DetectionModel(BaseModel):
    type: str
    confidence: float
    reasoning: str

class MetadataModel(BaseModel):
    risk_level: str
    timestamp: str

class AnalysisResultModel(BaseModel):
    request: RequestModel
    features: FeaturesModel
    detections: List[DetectionModel]
    metadata: MetadataModel

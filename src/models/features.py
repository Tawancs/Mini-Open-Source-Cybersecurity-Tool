from pydantic import BaseModel
from typing import List, Optional

class DetectionDetail(BaseModel):
    pattern: str
    description: str
    location: Optional[str] = None

class FeaturesModel(BaseModel):
    detected_keywords: List[str] = []
    encoding: Optional[str] = None
    suspicious_patterns: List[str] = []
    detailed_detections: List[DetectionDetail] = []

from typing import List, Optional
from src.models.analysis import DetectionModel
from src.models.features import DetectionDetail

def detect_sqli(features: List[DetectionDetail]) -> Optional[DetectionModel]:
    if not features:
        return None
    
    score = 0.0
    for f in features:
        desc = f.description.lower()
        if "obfuscated" in desc: score += 0.8
        elif "[high]" in desc: score += 0.9
        elif "[medium]" in desc: score += 0.3
        elif "[low]" in desc: score += 0.1
        elif "keyword" in desc: score += 0.4
    
    confidence = min(1.0, score)
    patterns = [f"{f.pattern} (in {f.location})" if f.location else f.pattern for f in features]
    reasoning = f"Detected {len(features)} SQL injection patterns: {', '.join(patterns)}"
    return DetectionModel(
        type="SQL Injection",
        confidence=confidence,
        reasoning=reasoning
    )

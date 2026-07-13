from typing import List, Optional
from src.models.analysis import DetectionModel
from src.models.features import DetectionDetail

def detect_xss(features: List[DetectionDetail]) -> Optional[DetectionModel]:
    if not features:
        return None
    score = 0.0
    for f in features:
        desc = f.description.lower()
        if "html tag" in desc: score += 0.2
        elif "javascript uri" in desc: score += 0.8
        elif "event handler" in desc: score += 0.8
        elif "dangerous javascript" in desc: score += 0.6
        elif "script tag" in desc: score += 0.8
        else: score += 0.4
        
    confidence = min(1.0, score)
    patterns = [f"{f.pattern} (in {f.location})" if f.location else f.pattern for f in features]
    reasoning = f"Detected {len(features)} XSS patterns: {', '.join(patterns)}"
    return DetectionModel(
        type="Cross-Site Scripting (XSS)",
        confidence=confidence,
        reasoning=reasoning
    )

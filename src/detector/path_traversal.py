from typing import List, Optional
from src.models.analysis import DetectionModel
from src.models.features import DetectionDetail

def detect_path_traversal(features: List[DetectionDetail]) -> Optional[DetectionModel]:
    if not features:
        return None
    
    score = 0.0
    for f in features:
        desc = f.description.lower()
        if "directory traversal" in desc: score += 0.6
        elif "null byte" in desc: score += 0.8
        elif "sensitive file" in desc: score += 0.6
        elif "absolute path" in desc: score += 0.2
        elif "unc path" in desc: score += 0.2
        elif "encoded" in desc: score += 0.4
    
    confidence = min(1.0, score)
    patterns = [f"{f.pattern} (in {f.location})" if f.location else f.pattern for f in features]
    reasoning = f"Detected {len(features)} Path Traversal patterns: {', '.join(patterns)}"
    return DetectionModel(
        type="Path Traversal",
        confidence=confidence,
        reasoning=reasoning
    )

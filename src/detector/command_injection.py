from typing import List, Optional
from src.models.analysis import DetectionModel
from src.models.features import DetectionDetail

def detect_command_injection(features: List[DetectionDetail]) -> Optional[DetectionModel]:
    if not features:
        return None
    
    score = 0.0
    seen_desc = set()
    for f in features:
        desc = f.description.lower()
        if desc in seen_desc: continue
        seen_desc.add(desc)
        if "shell operator" in desc: score += 0.6
        elif "command substitution" in desc: score += 0.5
        elif "shell redirection" in desc: score += 0.1
        elif "dangerous command" in desc: score += 0.2
        
    confidence = min(1.0, score)
    patterns = [f"{f.pattern} (in {f.location})" if f.location else f.pattern for f in features]
    reasoning = f"Detected {len(features)} Command Injection patterns: {', '.join(patterns)}"
    return DetectionModel(
        type="Command Injection",
        confidence=confidence,
        reasoning=reasoning
    )

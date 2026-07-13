from typing import List
from src.models.features import DetectionDetail

def remove_duplicates(detected: List[DetectionDetail]) -> List[DetectionDetail]:
    unique = []
    seen = set()
    for d in detected:
        key = (d.pattern, d.description, d.location)
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique
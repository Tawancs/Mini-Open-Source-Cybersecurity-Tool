import json
from pathlib import Path
from urllib.parse import unquote
from src.models.features import DetectionDetail

# Decode url into the string version (default to 5)
def decode_url(payload: str, depth: int = 5) -> str:
    decoded = payload
    for _ in range(depth):
        new = unquote(decoded)
        if new == decoded:
            break
        decoded = new
    return decoded

# Load JSON signature file
def load_signature(filename: str) -> dict:
    sig_path = Path(__file__).parent / "signatures" / filename
    with open(sig_path, "r", encoding="utf-8") as f:
        return json.load(f)

# Create detection detail
def create_detection(pattern: str, description: str, location: str = None) -> DetectionDetail:
    return DetectionDetail(pattern=pattern, description=description, location=location)

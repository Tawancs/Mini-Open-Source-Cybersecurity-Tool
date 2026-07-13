
from typing import List
import re

from src.models.features import DetectionDetail
from src.extractor.utils import decode_url, load_signature, create_detection

SIG = load_signature("path_traversal.json")
SENSITIVE_FILES = SIG["SENSITIVE_FILES"]

def normalize_path(payload: str) -> str:
    decoded = decode_url(payload)
    decoded = decoded.replace("\\", "/")
    decoded = re.sub(r"/+", "/", decoded)
    return decoded

def check_directory_traversal(decoded: str) -> List[DetectionDetail]:
    if re.search(r"(^|/)\.\.(/|;|$)", decoded):
        return [create_detection("../", "Relative directory traversal")]
    return []

def check_encoded_traversal(payload: str) -> List[DetectionDetail]:
    if re.search(r"%2e|%252e|%2f|%252f|%5c|%255c", payload, re.IGNORECASE):
        return [create_detection("%2e", "Encoded traversal sequence")]
    return []

def check_null_byte(payload: str, decoded: str) -> List[DetectionDetail]:
    if "\x00" in decoded or "\\x00" in payload:
        return [create_detection("NULL", "Null byte injection")]
    return []

def check_sensitive_files(decoded: str) -> List[DetectionDetail]:
    detected = []
    lower = decoded.lower()
    for file in SENSITIVE_FILES:
        if file.lower() in lower:
            detected.append(create_detection(file, "Sensitive file access"))
    return detected

def check_windows_absolute_path(decoded: str) -> List[DetectionDetail]:
    if re.match(r"^[a-zA-Z]:/", decoded):
        return [create_detection(decoded[:2], "Windows absolute path")]
    return []

def check_unc_path(decoded: str) -> List[DetectionDetail]:
    if decoded.startswith("//"):
        return [create_detection("//", "Windows UNC path")]
    return []

def extract_path_traversal(payload: str) -> List[DetectionDetail]:
    if not payload:
        return []
    decoded = normalize_path(payload)
    checker = [
        check_directory_traversal,
        check_encoded_traversal,
        check_sensitive_files,
        check_windows_absolute_path,
        check_unc_path
        ]
    detected = []
    detected.extend(check_null_byte(payload, decoded)),
    for check in checker:
        detected.extend(check(decoded))
    return detected

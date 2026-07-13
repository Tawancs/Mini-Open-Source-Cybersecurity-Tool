import re
from typing import List

from src.models.features import DetectionDetail
from src.extractor.utils import decode_url, load_signature, create_detection

SIG = load_signature("sql_injection.json")
SQL_KEYWORDS = SIG["SQL_KEYWORDS"]
CLASSIC_RULES = SIG["CLASSIC_RULES"]

def normalize_payload(payload: str) -> str:
    decoded = decode_url(payload)
    # remove sql comment
    decoded = re.sub(r"/\*.*?\*/", "", decoded, flags=re.DOTALL)
    return decoded

def check_obfuscated_keywords(decoded: str) -> List[DetectionDetail]:
    detected = []
    for keyword in SQL_KEYWORDS:
        regex = r"\b" + r"(?:\s|/\*.*?\*/)*".join(keyword) + r"\b"
        for match in re.finditer(regex, decoded, re.IGNORECASE):
            matched_str = match.group(0)
            if len(matched_str) > len(keyword): 
                detected.append(create_detection(matched_str, "Obfuscated SQL keyword"))
    return detected

def check_classic_sqli(decoded: str) -> List[DetectionDetail]:
    detected = []
    for level, rules in CLASSIC_RULES.items():
        for regex, description in rules.items():
            if re.search(regex, decoded):
                detected.append(create_detection(regex, f"[{level}] {description}"))
    return detected

def extract_sqli(payload: str) -> List[DetectionDetail]:
    if not payload:
        return []
    decoded = normalize_payload(payload)
    checker = [
        check_obfuscated_keywords,
        check_classic_sqli
    ]
    detected = []
    for check in checker:
        detected.extend(check(decoded))
    return detected

import html
import re
from html.parser import HTMLParser
from typing import List

from src.models.features import DetectionDetail
from src.extractor.utils import decode_url, load_signature, create_detection

SIG = load_signature("xss.json")
DANGEROUS_TAGS = set(SIG["DANGEROUS_TAGS"])
DANGEROUS_JS = SIG["DANGEROUS_JS"]
DANGEROUS_URI_SCHEMES = tuple(SIG["DANGEROUS_URI_SCHEMES"])

def normalize_payload(payload: str) -> str:
    decoded = decode_url(payload)
    decoded = html.unescape(decoded)
    return decoded

class XSSParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.detected = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in DANGEROUS_TAGS:
            self.detected.append(create_detection(f"<{tag}>", "Dangerous HTML tag"))
        for attr_name, attr_value in attrs:
            attr_name = attr_name.lower()
            if attr_name.startswith("on"):
                self.detected.append(create_detection(attr_name, "Event handler attribute"))
            if attr_value:
                value = str(attr_value).lower()
                if value.startswith(DANGEROUS_URI_SCHEMES):
                    self.detected.append(create_detection(value.split(":")[0] + ":", "Dangerous URI scheme"))


def check_javascript(decoded: str) -> List[DetectionDetail]:
    detected = []
    lower = decoded.lower()
    for js in DANGEROUS_JS:
        if js.lower() in lower:
            detected.append(create_detection(js, "Dangerous JavaScript"))
    return detected

def check_script_pattern(decoded: str) -> List[DetectionDetail]:
    if re.search(r"<\s*script\b", decoded, re.IGNORECASE):
        return [create_detection("<script>", "Script tag")]
    return []

def extract_xss(payload: str) -> List[DetectionDetail]:
    if not payload:
        return []
    decoded = normalize_payload(payload)
    detected = []
    parser = XSSParser()
    try:
        parser.feed(decoded)
        detected.extend(parser.detected)
    except Exception:
        pass
    checker = [
        check_javascript,
        check_script_pattern
    ]
    detected = []
    for check in checker:
        detected.extend(check(decoded))
    return detected


import re
from typing import List

from src.models.features import DetectionDetail
from src.extractor.utils import decode_url, load_signature, create_detection

SIG = load_signature("command_injection.json")
COMMANDS = SIG["COMMANDS"]

def normalize_payload(payload: str) -> str:
    return decode_url(payload)

def check_shell_operators(decoded: str) -> List[DetectionDetail]:
    detected = []
    operators = [
        ";",
        "&&",
        "||",
        "|",
        "`",
        "$(",
    ]
    for op in operators:
        if op in decoded:
            detected.append(create_detection(op, "Shell operator"))
    return detected


def check_dangerous_commands(decoded: str) -> List[DetectionDetail]:
    detected = []
    for cmd in COMMANDS:
        if re.search(rf"\b{re.escape(cmd)}\b", decoded, re.IGNORECASE):
            detected.append(create_detection(cmd, "Dangerous command"))
    return detected


def check_command_substitution(decoded: str) -> List[DetectionDetail]:
    detected = []
    if re.search(r"`[^`]+`", decoded):
        detected.append(create_detection("`...`", "Command substitution"))
    if re.search(r"\$\([^)]{1,500}\)", decoded):
        detected.append(create_detection("$()", "Command substitution"))
    return detected


def check_redirection(decoded: str) -> List[DetectionDetail]:
    detected = []
    for symbol in [">", ">>", "<", "2>", "&>"]:
        if symbol in decoded:
            detected.append(create_detection(symbol, "Shell redirection"))
    return detected


def extract_command_injection(payload: str) -> List[DetectionDetail]:
    if not payload:
        return []
    decoded = normalize_payload(payload)
    checker = [
        check_shell_operators,
        check_dangerous_commands,
        check_command_substitution,
        check_redirection
    ]
    detected = []
    for check in checker:
        detected.extend(check(decoded))
    return detected

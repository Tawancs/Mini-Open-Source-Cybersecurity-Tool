from src.detector.command_injection import detect_command_injection
from src.models.features import DetectionDetail

def test_detect_ci_medium_confidence():
    features = [DetectionDetail(pattern=">", description="shell redirection")]
    result = detect_command_injection(features)
    assert result is not None
    assert result.type == "Command Injection"
    assert 0.0 < result.confidence < 0.4

def test_detect_ci_high_confidence():
    features = [DetectionDetail(pattern=";", description="shell operator")]
    result = detect_command_injection(features)
    assert result is not None
    assert 0.4 <= result.confidence < 0.7

def test_detect_ci_critical_confidence():
    features = [
        DetectionDetail(pattern=";", description="shell operator"),
        DetectionDetail(pattern="cat /etc/passwd", description="dangerous command")
    ]
    result = detect_command_injection(features)
    assert result is not None
    assert result.confidence >= 0.7

def test_detect_ci_empty():
    features = []
    result = detect_command_injection(features)
    assert result is None

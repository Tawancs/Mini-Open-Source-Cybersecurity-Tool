from src.detector.sql_injection import detect_sqli
from src.models.features import DetectionDetail

def test_detect_sqli_medium_confidence():
    features = [DetectionDetail(pattern="SELECT", description="[low] query")]
    result = detect_sqli(features)
    assert result is not None
    assert result.type == "SQL Injection"
    assert 0.0 < result.confidence < 0.4

def test_detect_sqli_high_confidence():
    features = [DetectionDetail(pattern="SELECT", description="keyword")]
    result = detect_sqli(features)
    assert result is not None
    assert 0.4 <= result.confidence < 0.7

def test_detect_sqli_critical_confidence():
    features = [DetectionDetail(pattern="' OR 1=1", description="[high] logic")]
    result = detect_sqli(features)
    assert result is not None
    assert result.confidence >= 0.7

def test_detect_sqli_empty():
    features = []
    result = detect_sqli(features)
    assert result is None

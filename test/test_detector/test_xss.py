from src.detector.xss import detect_xss
from src.models.features import DetectionDetail

def test_detect_xss_low_confidence():
    features = [DetectionDetail(pattern="<b>", description="html tag")]
    result = detect_xss(features)
    assert result is not None
    assert result.type == "Cross-Site Scripting (XSS)"
    assert 0.0 < result.confidence < 0.4

def test_detect_xss_medium_confidence():
    features = [DetectionDetail(pattern="alert(1)", description="dangerous javascript")]
    result = detect_xss(features)
    assert result is not None
    assert 0.4 <= result.confidence < 0.7

def test_detect_xss_high_confidence():
    features = [DetectionDetail(pattern="<script>", description="script tag")]
    result = detect_xss(features)
    assert result is not None
    assert 0.7 <= result.confidence < 0.9

def test_detect_xss_critical_confidence():
    features = [
        DetectionDetail(pattern="<script>", description="script tag"),
        DetectionDetail(pattern="alert(1)", description="dangerous javascript")
    ]
    result = detect_xss(features)
    assert result is not None
    assert result.confidence >= 0.9

def test_detect_xss_empty():
    features = []
    result = detect_xss(features)
    assert result is None

from src.detector.path_traversal import detect_path_traversal
from src.models.features import DetectionDetail

def test_detect_pt_low_confidence():
    features = [DetectionDetail(pattern="/etc/", description="absolute path")]
    result = detect_path_traversal(features)
    assert result is not None
    assert result.type == "Path Traversal"
    assert 0.0 < result.confidence < 0.4

def test_detect_pt_medium_confidence():
    features = [
        DetectionDetail(pattern="%00", description="null byte")
    ]
    result = detect_path_traversal(features)
    assert result is not None
    assert 0.4 <= result.confidence < 0.7

def test_detect_pt_high_confidence():
    features = [DetectionDetail(pattern="/etc/passwd", description="sensitive file")]
    result = detect_path_traversal(features)
    assert result is not None
    assert 0.7 <= result.confidence < 0.9

def test_detect_pt_critical_confidence():
    features = [
        DetectionDetail(pattern="/etc/passwd", description="sensitive file"),
        DetectionDetail(pattern="../", description="directory traversal")
    ]
    result = detect_path_traversal(features)
    assert result is not None
    assert result.confidence >= 0.9

def test_detect_pt_empty():
    features = []
    result = detect_path_traversal(features)
    assert result is None

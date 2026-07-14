from src.extractor.xss import extract_xss

def test_extract_xss_basic_script():
    payload = "<script>alert(1)</script>"
    features = extract_xss(payload)
    assert len(features) > 0
    assert any("script" in feat.pattern.lower() for feat in features)

def test_extract_xss_event_handler():
    payload = "<img src=x onerror=alert(1)>"
    features = extract_xss(payload)
    assert len(features) > 0

def test_extract_xss_javascript_uri():
    payload = "javascript:alert(1)"
    features = extract_xss(payload)
    assert len(features) > 0

def test_extract_xss_encoded():
    payload = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    features = extract_xss(payload)
    assert len(features) > 0

def test_extract_xss_empty():
    features = extract_xss("")
    assert len(features) == 0

def test_extract_xss_normal_string():
    payload = "Hello World"
    features = extract_xss(payload)
    assert len(features) == 0

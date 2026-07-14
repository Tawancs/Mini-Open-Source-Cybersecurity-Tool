from src.extractor.path_traversal import extract_path_traversal

def test_extract_pt_basic():
    payload = "../../../etc/passwd"
    features = extract_path_traversal(payload)
    assert len(features) > 0
    assert any(".." in feat.pattern for feat in features)

def test_extract_pt_windows():
    payload = "..\\..\\..\\windows\\win.ini"
    features = extract_path_traversal(payload)
    assert len(features) > 0

def test_extract_pt_absolute():
    payload = "/etc/shadow"
    features = extract_path_traversal(payload)
    assert len(features) > 0

def test_extract_pt_encoded():
    payload = "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    features = extract_path_traversal(payload)
    assert len(features) > 0

def test_extract_pt_null_byte():
    payload = "../../../etc/passwd%00"
    features = extract_path_traversal(payload)
    assert len(features) > 0

def test_extract_pt_empty():
    features = extract_path_traversal("")
    assert len(features) == 0

def test_extract_pt_normal():
    payload = "images/logo.png"
    features = extract_path_traversal(payload)
    assert len(features) == 0

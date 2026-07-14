from src.extractor.sql_injection import extract_sqli

def test_extract_sqli_basic():
    payload = "UNION SELECT 1, 2"
    features = extract_sqli(payload)
    assert len(features) > 0
    assert any("SELECT" in feat.pattern.upper() for feat in features)

def test_extract_sqli_classic():
    payload = "' OR 1=1"
    features = extract_sqli(payload)
    assert len(features) > 0

def test_extract_sqli_obfuscated():
    payload = "S E L E C T * F R O M users"
    features = extract_sqli(payload)
    assert len(features) > 0

def test_extract_sqli_comment():
    payload = "admin' --"
    features = extract_sqli(payload)
    assert len(features) > 0

def test_extract_sqli_empty():
    features = extract_sqli("")
    assert len(features) == 0

def test_extract_sqli_normal_string():
    payload = "John Doe"
    features = extract_sqli(payload)
    assert len(features) == 0

def test_extract_sqli_normal_string2():
    payload = "page=2"
    features = extract_sqli(payload)
    assert len(features) == 0

def test_extract_sqli_normal_string3():
    payload = "search=shoes"
    features = extract_sqli(payload)
    assert len(features) == 0

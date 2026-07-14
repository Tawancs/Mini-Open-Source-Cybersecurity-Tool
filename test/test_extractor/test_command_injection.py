from src.extractor.command_injection import extract_command_injection

def test_extract_ci_basic_pipe():
    payload = "127.0.0.1 | cat /etc/passwd"
    features = extract_command_injection(payload)
    assert len(features) > 0

def test_extract_ci_semicolon():
    payload = "127.0.0.1; ls -la"
    features = extract_command_injection(payload)
    assert len(features) > 0

def test_extract_ci_ampersand():
    payload = "127.0.0.1 && whoami"
    features = extract_command_injection(payload)
    assert len(features) > 0

def test_extract_ci_backticks():
    payload = "`whoami`"
    features = extract_command_injection(payload)
    assert len(features) > 0

def test_extract_ci_subshell():
    payload = "$(id)"
    features = extract_command_injection(payload)
    assert len(features) > 0

def test_extract_ci_encoded():
    payload = "127.0.0.1%3B%20ls"
    features = extract_command_injection(payload)
    assert len(features) > 0

def test_extract_ci_empty():
    features = extract_command_injection("")
    assert len(features) == 0

def test_extract_ci_normal():
    payload = "127.0.0.1"
    features = extract_command_injection(payload)
    assert len(features) == 0

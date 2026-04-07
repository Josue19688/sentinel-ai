import pytest
from app.security.sanitizer import sanitize, validate_payload_size, unwrap_embedded_json

def test_scalar_types():
    assert sanitize(42) == 42
    assert sanitize(3.14) == 3.14
    assert sanitize(True) is True
    assert sanitize(None) is None

def test_null_bytes_and_control_chars():
    assert sanitize("hello\x00world") == "helloworld"
    assert sanitize("test\x1fbuzz") == "testbuzz"

def test_injection_patterns():
    attacks = [
        "../etc/passwd",
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "onload=alert(1)",
        "<iframe src='x'>",
        "${7*7}",
        "__proto__",
        "constructor[",
        "UNION ALL SELECT",
        "DROP TABLE users;",
        "DELETE FROM users"
    ]
    for attack in attacks:
        assert "[REDACTED]" in sanitize(attack)

def test_long_string_truncation():
    long_str = "A" * 3000
    sanitized = sanitize(long_str)
    assert len(sanitized) <= 2005
    assert sanitized.endswith("[...]")

def test_dict_sanitization():
    raw = {"key": "UNION ALL SELECT", "valid": 123}
    clean = sanitize(raw)
    assert "[REDACTED]" in clean["key"]
    assert clean["valid"] == 123

def test_list_sanitization():
    raw = ["valid", "../traversal"]
    clean = sanitize(raw)
    assert clean[0] == "valid"
    assert "[REDACTED]" in clean[1]

def test_max_object_depth():
    raw = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": "value"}}}}}}}}}}}
    clean = sanitize(raw)
    curr = clean
    has_truncation = False
    while isinstance(curr, dict):
        val = list(curr.values())[0]
        if val == "[truncado: demasiado anidado]":
            has_truncation = True
            break
        curr = val
    assert has_truncation

def test_validate_payload_size():
    assert validate_payload_size(b"A" * 1024) is True
    assert validate_payload_size(b"A" * 20_000_000) is False

def test_unwrap_embedded_json():
    assert unwrap_embedded_json('{"Role":"Admin"}') == {"Role": "Admin"}
    assert unwrap_embedded_json('{"Role":"Admin"') == '{"Role":"Admin"'

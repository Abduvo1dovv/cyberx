from __future__ import annotations

from cyberx.evidence.redactor import REDACTED, Redactor


def test_redacts_jwt_and_pem() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb"
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE\n-----END RSA PRIVATE KEY-----"
    text, refs = Redactor().redact_text(f"token={jwt}\n{pem}")
    assert jwt not in text
    assert "PRIVATE KEY" not in text
    assert REDACTED in text
    assert {item.kind for item in refs} >= {"jwt", "pem"}
    assert all(item.sha256 and "aaa" not in item.sha256 for item in refs)


def test_redacts_headers_and_secret_keys() -> None:
    redactor = Redactor()
    value, refs = redactor.redact_header("Authorization", "Bearer abc.def.ghi")
    assert value == REDACTED
    assert refs
    mapping = redactor.redact({"password": "hunter2", "title": "ok", "api_key": "xyz"})
    assert mapping["password"] == REDACTED
    assert mapping["api_key"] == REDACTED
    assert mapping["title"] == "ok"


def test_non_secrets_pass_through() -> None:
    assert Redactor().redact("nginx/1.24.0") == "nginx/1.24.0"
    assert Redactor().redact(200) == 200
    assert Redactor().redact(True) is True

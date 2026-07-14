"""Tests for the live-target posture checks (network fully mocked)."""

from __future__ import annotations

import httpx

from argus.dynamic import posture


def _client_returning(routes: dict[str, httpx.Response]):
    """A mock httpx.Client whose .get(url) returns a canned Response per path."""

    class _MockClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            from urllib.parse import urlparse
            path = urlparse(url).path.lstrip("/")
            for key, resp in routes.items():
                if key == path or (key == "" and path == ""):
                    resp.request = httpx.Request("GET", url)
                    return resp
            # default: the main page
            main = routes.get("", routes.get("__main__"))
            if main is not None:
                main.request = httpx.Request("GET", url)
                return main
            r = httpx.Response(404, request=httpx.Request("GET", url))
            return r

    return _MockClient


def _resp(url, status=200, headers=None, content=b"ok"):
    r = httpx.Response(status, headers=headers or {}, content=content,
                       request=httpx.Request("GET", url))
    return r


def test_missing_all_security_headers(monkeypatch):
    main = _resp("https://ex.com/", headers={"content-type": "text/html"})
    monkeypatch.setattr(httpx, "Client", _client_returning({"": main}))
    findings = posture.probe("https://ex.com", check_paths=False)
    rules = {f.rule_id for f in findings}
    assert "posture.missing-content-security-policy" in rules
    assert "posture.missing-strict-transport-security" in rules
    assert "posture.missing-x-content-type-options" in rules
    assert "posture.missing-frame-options" in rules


def test_good_headers_produce_no_header_findings(monkeypatch):
    main = _resp("https://ex.com/", headers={
        "content-type": "text/html",
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })
    monkeypatch.setattr(httpx, "Client", _client_returning({"": main}))
    findings = posture.probe("https://ex.com", check_paths=False)
    rules = {f.rule_id for f in findings}
    assert not any(r.startswith("posture.missing-") for r in rules)


def test_insecure_cookie_flags(monkeypatch):
    main = _resp("https://ex.com/", headers={
        "content-type": "text/html",
        "set-cookie": "session=abc; Path=/",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=1",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })
    monkeypatch.setattr(httpx, "Client", _client_returning({"": main}))
    findings = posture.probe("https://ex.com", check_paths=False)
    cookie = [f for f in findings if f.rule_id.startswith("posture.cookie-flags")]
    assert cookie
    assert "Secure" in cookie[0].title and "HttpOnly" in cookie[0].title


def test_version_disclosure(monkeypatch):
    main = _resp("https://ex.com/", headers={
        "content-type": "text/html",
        "server": "nginx/1.18.0",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=1",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })
    monkeypatch.setattr(httpx, "Client", _client_returning({"": main}))
    findings = posture.probe("https://ex.com", check_paths=False)
    assert any(f.rule_id.startswith("posture.version-disclosure") for f in findings)


def test_exposed_sensitive_path(monkeypatch):
    main = _resp("https://ex.com/", headers={
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=1",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })
    env = _resp("https://ex.com/.env",
                headers={"content-type": "text/plain"},
                content=b"SECRET_KEY=abc123")
    monkeypatch.setattr(httpx, "Client",
                        _client_returning({"": main, ".env": env}))
    findings = posture.probe("https://ex.com", check_paths=True)
    exposed = [f for f in findings if f.rule_id == "posture.exposed-path"]
    assert exposed
    assert any(".env" in f.title for f in exposed)


def test_unreachable_target_degrades_gracefully(monkeypatch):
    class _Boom:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url): raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(httpx, "Client", _Boom)
    findings = posture.probe("https://nope.invalid")
    assert len(findings) == 1
    assert findings[0].rule_id == "posture.unreachable"


def test_bare_hostname_gets_https_scheme(monkeypatch):
    seen = {}

    class _Client:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url):
            seen["url"] = url
            return _resp(url, headers={"content-type": "text/html"})

    monkeypatch.setattr(httpx, "Client", _Client)
    posture.probe("example.com", check_paths=False)
    assert seen["url"].startswith("https://")

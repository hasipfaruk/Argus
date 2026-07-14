"""Safe, read-only security-posture checks for a running URL (pre-DAST).

Given a deployed URL, ``probe`` makes a handful of ordinary GET requests and
reports runtime misconfigurations that source analysis cannot observe:

* **Transport**, plaintext HTTP, and HTTP that does not redirect to HTTPS.
* **Security headers**, HSTS, CSP, X-Frame-Options / frame-ancestors,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
* **Cookie flags**, Secure, HttpOnly, SameSite on any Set-Cookie.
* **Exposed paths**, a short allowlist of well-known sensitive endpoints
  (``/.env``, ``/.git/config``, ``/actuator``, …) checked for accidental
  exposure.
* **Version disclosure**, Server / X-Powered-By advertising exact versions.

Deliberately non-intrusive: only GETs, only the paths listed here, one pass,
short timeout, redirects followed. It never sends payloads, mutates state, or
attempts exploitation, so it is safe to point at systems you are authorized to
assess. It is not a substitute for full DAST.
"""

from __future__ import annotations

import logging
from urllib.parse import urljoin, urlparse

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)

log = logging.getLogger("argus.dynamic.posture")

_TIMEOUT = 10.0
_UA = {"User-Agent": "argus-posture-check"}

# Header -> (severity, why, fix). Absence of the header is the finding.
_SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "No HSTS header, so browsers may connect over plaintext HTTP and are "
        "exposed to SSL-stripping downgrade attacks.",
        "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains`.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy, so the app has no defense-in-depth against "
        "cross-site scripting and content injection.",
        "Define a restrictive CSP (start with `default-src 'self'`).",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "No X-Content-Type-Options: nosniff, so browsers may MIME-sniff responses "
        "into an unintended, dangerous content type.",
        "Send `X-Content-Type-Options: nosniff`.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "No Referrer-Policy, so full URLs (possibly with sensitive tokens) may leak "
        "to third parties via the Referer header.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
    ),
}


def _clickjacking_missing(headers) -> bool:
    if "x-frame-options" in headers:
        return False
    csp = headers.get("content-security-policy", "").lower()
    return "frame-ancestors" not in csp


def _finding(rule: str, url: str, title: str, severity: Severity, why: str,
             fix: str, *, cwe, owasp, confidence=Confidence.HIGH,
             snippet: str | None = None) -> Finding:
    return Finding(
        id=f"posture:{rule}:{urlparse(url).netloc}:{urlparse(url).path or '/'}",
        rule_id=f"posture.{rule}",
        scanner="posture",
        title=title,
        description=why,
        location=Location(path=url, snippet=snippet),
        severity=severity, confidence=confidence, likelihood=Likelihood.POSSIBLE,
        cwe=cwe, owasp=owasp,
        why_vulnerable=why,
        attacker_perspective="Observable directly in the HTTP response by anyone "
                             "who can reach the URL.",
        business_impact="Weakens the app's runtime security posture; exact impact "
                        "depends on the specific misconfiguration.",
        remediation=Remediation(summary=fix, guidance=fix),
        tags=["dynamic", "posture"],
    )


# Well-known sensitive paths, accidental exposure is high-impact. GET only.
_SENSITIVE_PATHS = [
    (".env", "Environment file exposed"),
    (".git/config", "Git metadata exposed"),
    (".git/HEAD", "Git repository exposed"),
    (".aws/credentials", "AWS credentials file exposed"),
    ("actuator/env", "Spring Boot Actuator env exposed"),
    ("server-status", "Apache server-status exposed"),
    ("phpinfo.php", "phpinfo() exposed"),
    ("config.json", "Configuration file exposed"),
]


def probe(url: str, *, check_paths: bool = True) -> list[Finding]:
    """Run posture checks against ``url``. Returns findings; never raises.

    Network/TLS/import errors degrade to a single informational finding rather
    than aborting, so a scan that includes ``--live-target`` always completes.
    """
    try:
        import httpx
    except ImportError:
        log.warning("httpx not available; skipping live-target checks")
        return []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    findings: list[Finding] = []
    try:
        with httpx.Client(follow_redirects=True, timeout=_TIMEOUT,
                          headers=_UA) as client:
            resp = client.get(url)
            findings.extend(_check_transport(client, url, resp))
            findings.extend(_check_headers(str(resp.url), resp))
            findings.extend(_check_cookies(str(resp.url), resp))
            findings.extend(_check_version_disclosure(str(resp.url), resp))
            if check_paths:
                findings.extend(_check_sensitive_paths(client, str(resp.url)))
    except Exception as exc:
        log.warning("live-target probe of %s failed: %s", url, exc)
        return [_finding(
            "unreachable", url, "Live target could not be probed", Severity.INFO,
            f"Argus could not complete posture checks against {url}: {exc}.",
            "Confirm the URL is reachable from this host and try again.",
            cwe=[], owasp=[], confidence=Confidence.LOW)]
    return findings


def _check_transport(client, url: str, resp) -> list[Finding]:
    out: list[Finding] = []
    final = str(resp.url)
    if urlparse(url).scheme == "http" and urlparse(final).scheme != "https":
        out.append(_finding(
            "no-https", url, "Site served over plaintext HTTP", Severity.HIGH,
            "The URL is served over HTTP and does not redirect to HTTPS, so all "
            "traffic, including credentials and session cookies, is unencrypted.",
            "Serve the site over HTTPS and redirect all HTTP requests to it.",
            cwe=["CWE-319"], owasp=["A02:2021-Cryptographic Failures"]))
    return out


def _check_headers(url: str, resp) -> list[Finding]:
    out: list[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    is_https = urlparse(url).scheme == "https"
    for name, (severity, why, fix) in _SECURITY_HEADERS.items():
        if name == "strict-transport-security" and not is_https:
            continue  # HSTS is only meaningful over HTTPS
        if name not in headers:
            out.append(_finding(
                f"missing-{name}", url,
                f"Missing security header: {name}", severity, why, fix,
                cwe=["CWE-693"], owasp=["A05:2021-Security Misconfiguration"]))
    if _clickjacking_missing(headers):
        out.append(_finding(
            "missing-frame-options", url,
            "No clickjacking protection (X-Frame-Options / frame-ancestors)",
            Severity.MEDIUM,
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so "
            "the page can be framed by any site and used for clickjacking.",
            "Send `X-Frame-Options: DENY` or a CSP `frame-ancestors 'none'`.",
            cwe=["CWE-1021"], owasp=["A05:2021-Security Misconfiguration"]))
    return out


def _check_cookies(url: str, resp) -> list[Finding]:
    out: list[Finding] = []
    raw_cookies = resp.headers.get_list("set-cookie") if hasattr(
        resp.headers, "get_list") else resp.headers.get_all("set-cookie") \
        if hasattr(resp.headers, "get_all") else []
    for raw in raw_cookies:
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            out.append(_finding(
                f"cookie-flags-{name}", url,
                f"Cookie '{name}' missing flags: {', '.join(missing)}",
                Severity.MEDIUM if ("Secure" in missing or "HttpOnly" in missing)
                else Severity.LOW,
                f"The Set-Cookie for '{name}' is missing {', '.join(missing)}. "
                "Without HttpOnly it is readable by JavaScript (XSS theft); without "
                "Secure it is sent over HTTP; without SameSite it is exposed to CSRF.",
                "Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies.",
                cwe=["CWE-1004", "CWE-614"],
                owasp=["A05:2021-Security Misconfiguration"], snippet=name))
    return out


def _check_version_disclosure(url: str, resp) -> list[Finding]:
    out: list[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for h in ("server", "x-powered-by"):
        val = headers.get(h, "")
        if val and any(c.isdigit() for c in val):
            out.append(_finding(
                f"version-disclosure-{h}", url,
                f"Version disclosure via {h} header", Severity.LOW,
                f"The {h} header advertises `{val}`, telling an attacker exactly "
                "which software and version to target with known exploits.",
                f"Remove or genericize the {h} header.",
                cwe=["CWE-200"], owasp=["A05:2021-Security Misconfiguration"],
                confidence=Confidence.MEDIUM, snippet=f"{h}: {val}"))
    return out


def _check_sensitive_paths(client, base_url: str) -> list[Finding]:
    out: list[Finding] = []
    root = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}/"
    for path, title in _SENSITIVE_PATHS:
        target = urljoin(root, path)
        try:
            r = client.get(target)
        except Exception:
            continue
        # A 200 with non-trivial, non-HTML body is a real exposure; many apps
        # return a 200 SPA shell for unknown paths, so require it not be HTML.
        ctype = r.headers.get("content-type", "").lower()
        if r.status_code == 200 and "text/html" not in ctype and r.content:
            out.append(_finding(
                "exposed-path", target, f"{title} at /{path}", Severity.HIGH,
                f"{target} is publicly accessible and returned {r.status_code}. "
                "Sensitive files exposed at well-known paths leak secrets, source, "
                "or internal state.",
                f"Block public access to /{path} at the web server or app layer.",
                cwe=["CWE-538"], owasp=["A05:2021-Security Misconfiguration"],
                snippet=f"HTTP {r.status_code} {ctype}"))
    return out

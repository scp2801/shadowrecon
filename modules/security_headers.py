#!/usr/bin/env python3
"""
modules/security_headers.py
────────────────────────────
Audit HTTP security headers against OWASP and industry best practices.
Scores each header as PASS/FAIL/WARN and provides a total security grade.
"""

import ssl
import urllib.request
import urllib.error
from utils.logger import get_logger
from utils.helpers import build_url

# ─── Security Header Definitions ──────────────────────────────────────────────
# Each entry: (header_name, description, is_required)

SECURITY_HEADERS = [
    # Critical headers
    ("Strict-Transport-Security",  "Enforces HTTPS connections (HSTS)",              True),
    ("Content-Security-Policy",    "Prevents XSS and injection attacks (CSP)",       True),
    ("X-Content-Type-Options",     "Prevents MIME type sniffing",                    True),
    ("X-Frame-Options",            "Prevents clickjacking attacks",                  True),
    ("X-XSS-Protection",          "Legacy XSS filter (deprecated but checked)",     False),
    ("Referrer-Policy",            "Controls referrer header in requests",           True),
    ("Permissions-Policy",         "Controls browser feature access",               True),

    # Additional security headers
    ("Cross-Origin-Embedder-Policy",  "Isolation: restricts cross-origin loading",  False),
    ("Cross-Origin-Opener-Policy",    "Isolation: prevents cross-origin windows",   False),
    ("Cross-Origin-Resource-Policy",  "Controls cross-origin resource sharing",     False),
    ("Cache-Control",                  "Controls caching behavior",                  False),

    # Information disclosure
    ("Server",         "Should not disclose server software details",  False),
    ("X-Powered-By",   "Should not disclose backend technology",       False),
]

# CSP values that are considered insecure
CSP_UNSAFE_VALUES = ["unsafe-inline", "unsafe-eval", "*", "data:"]

# HSTS minimum recommended max-age (1 year)
HSTS_MIN_MAX_AGE = 31536000


class SecurityHeaders:
    """
    HTTP security headers audit module.
    Checks for presence, analyzes values, and grades overall security posture.
    """

    def __init__(self, target: str, timeout: int = 10):
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Fetch headers and perform a full security audit.
        
        Returns:
            Dictionary with per-header results, grade, and recommendations
        """
        self.logger.info(f"SecurityHeaders.run() → {self.target}")

        headers = self._fetch_headers()
        if headers is None:
            return {"error": f"Could not connect to {self.target}"}

        headers_lower = {k.lower(): v for k, v in headers.items()}
        results       = {}
        pass_count    = 0
        fail_count    = 0
        warn_count    = 0
        recommendations = []

        for header, description, required in SECURITY_HEADERS:
            key     = header.lower()
            present = key in headers_lower
            value   = headers_lower.get(key, "")

            analysis = self._analyze_header(header, value, present)
            status   = analysis["status"]

            results[header] = {
                "present":     present,
                "value":       value if present else "MISSING",
                "status":      status,
                "description": description,
                "required":    required,
                "note":        analysis.get("note", ""),
            }

            if status == "PASS":
                pass_count += 1
            elif status == "FAIL":
                fail_count += 1
                if required:
                    recommendations.append(f"Add {header}: {self._get_recommendation(header)}")
            elif status == "WARN":
                warn_count += 1

        # Calculate security grade
        total    = pass_count + fail_count + warn_count
        score    = int((pass_count / total * 100)) if total else 0
        grade    = self._score_to_grade(score)

        return {
            "URL":             build_url(self.target),
            "Security Grade":  f"{grade} ({score}/100)",
            "Headers Passed":  pass_count,
            "Headers Failed":  fail_count,
            "Headers Warning": warn_count,
            "Results":         results,
            "Recommendations": recommendations[:10],  # Top 10 fixes
        }

    def _fetch_headers(self) -> dict:
        """Fetch HTTP response headers from the target."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx)
        )

        for scheme in ("https", "http"):
            url = build_url(self.target, scheme=scheme)
            try:
                req = urllib.request.Request(
                    url,
                    method="HEAD",
                    headers={"User-Agent": "Mozilla/5.0 (compatible; ShadowRecon/1.0)"}
                )
                with opener.open(req, timeout=self.timeout) as resp:
                    return dict(resp.headers)
            except urllib.error.HTTPError as e:
                return dict(e.headers) if hasattr(e, "headers") else {}
            except Exception as e:
                self.logger.debug(f"SecurityHeaders fetch failed ({scheme}): {e}")

        return None

    def _analyze_header(self, header: str, value: str, present: bool) -> dict:
        """
        Analyze a single header's value for security best practices.
        
        Args:
            header: Header name
            value: Header value (empty if not present)
            present: Whether the header was found
            
        Returns:
            Dict with 'status' (PASS/FAIL/WARN) and optional 'note'
        """
        if header == "Strict-Transport-Security":
            if not present:
                return {"status": "FAIL", "note": "HSTS not enabled"}
            if "max-age" in value.lower():
                try:
                    max_age = int(value.lower().split("max-age=")[1].split(";")[0].strip())
                    if max_age < HSTS_MIN_MAX_AGE:
                        return {"status": "WARN", "note": f"max-age too short ({max_age}s, min {HSTS_MIN_MAX_AGE}s)"}
                    return {"status": "PASS", "note": f"max-age={max_age}s" + (" + includeSubDomains" if "includesubdomains" in value.lower() else "")}
                except Exception:
                    return {"status": "WARN", "note": "Could not parse max-age"}
            return {"status": "WARN", "note": "Missing max-age directive"}

        elif header == "Content-Security-Policy":
            if not present:
                return {"status": "FAIL", "note": "CSP not set — XSS protection missing"}
            for unsafe in CSP_UNSAFE_VALUES:
                if unsafe in value.lower():
                    return {"status": "WARN", "note": f"CSP contains '{unsafe}' — reduces protection"}
            return {"status": "PASS"}

        elif header == "X-Content-Type-Options":
            if not present:
                return {"status": "FAIL", "note": "MIME sniffing not disabled"}
            return {"status": "PASS" if "nosniff" in value.lower() else "WARN", "note": ""}

        elif header == "X-Frame-Options":
            if not present:
                return {"status": "FAIL", "note": "Clickjacking protection missing"}
            val_lower = value.lower()
            if val_lower in ("deny", "sameorigin"):
                return {"status": "PASS"}
            if "allow-from" in val_lower:
                return {"status": "WARN", "note": "ALLOW-FROM is deprecated, use CSP frame-ancestors"}
            return {"status": "WARN"}

        elif header in ("Server", "X-Powered-By"):
            # These should not reveal software details
            if not present:
                return {"status": "PASS", "note": "Header absent (good — no info disclosure)"}
            if any(version_hint in value for version_hint in [".", "/", "1", "2", "3", "4", "5", "6", "7", "8", "9"]):
                return {"status": "WARN", "note": f"Discloses version info: '{value[:40]}'"}
            return {"status": "WARN", "note": f"Discloses software: '{value[:40]}'"}

        elif header == "Referrer-Policy":
            if not present:
                return {"status": "FAIL", "note": "Referrer policy not set"}
            secure_values = ("no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin")
            if any(v in value.lower() for v in secure_values):
                return {"status": "PASS"}
            if "unsafe-url" in value.lower() or "no-referrer-when-downgrade" in value.lower():
                return {"status": "WARN", "note": "Referrer policy leaks URLs to third parties"}
            return {"status": "PASS"}

        else:
            # Generic: PASS if present, FAIL if absent (for required), WARN otherwise
            if present:
                return {"status": "PASS"}
            return {"status": "FAIL" if any(h[0] == header and h[2] for h in SECURITY_HEADERS) else "WARN"}

    def _score_to_grade(self, score: int) -> str:
        """Convert numeric security score to letter grade."""
        if score >= 90: return "A+"
        if score >= 80: return "A"
        if score >= 70: return "B"
        if score >= 60: return "C"
        if score >= 50: return "D"
        return "F"

    def _get_recommendation(self, header: str) -> str:
        """Get a recommended value for a missing header."""
        recs = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy":   "default-src 'self'; script-src 'self'",
            "X-Content-Type-Options":    "nosniff",
            "X-Frame-Options":           "DENY",
            "Referrer-Policy":           "strict-origin-when-cross-origin",
            "Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
        }
        return recs.get(header, "Consult OWASP Secure Headers Project")

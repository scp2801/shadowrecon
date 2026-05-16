#!/usr/bin/env python3
"""
modules/http_headers.py
────────────────────────
Fetch and analyze HTTP/HTTPS response headers from a target.
Identifies server info, caching, redirects, and interesting headers.
Tries HTTPS first, falls back to HTTP automatically.
"""

import urllib.request
import urllib.error
import ssl
from utils.logger import get_logger
from utils.helpers import build_url


# Headers worth flagging for security research
INTERESTING_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "via",
    "x-cache",
    "x-varnish",
    "x-amz-cf-id",
    "cf-ray",
    "x-drupal-cache",
    "x-wp-total",
    "x-ratelimit-limit",
}


class HTTPHeaders:
    """
    HTTP response header analysis module.
    Fetches headers, detects technologies, and flags interesting values.
    """

    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize HTTP headers module.
        
        Args:
            target: Domain name or IP to probe
            timeout: HTTP request timeout in seconds
        """
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Fetch HTTP headers from the target.
        Attempts HTTPS first, then HTTP.
        
        Returns:
            Dictionary with header data and analysis
        """
        self.logger.info(f"HTTPHeaders.run() → {self.target}")

        # Try HTTPS first, then HTTP
        for scheme in ("https", "http"):
            result = self._fetch_headers(scheme)
            if result and "error" not in result:
                return result

        return {"error": f"Could not connect to {self.target} via HTTP or HTTPS"}

    def _fetch_headers(self, scheme: str) -> dict:
        """
        Perform an HTTP HEAD request and parse the response headers.
        
        Args:
            scheme: 'http' or 'https'
            
        Returns:
            Dictionary of header data, or dict with 'error' key on failure
        """
        url = build_url(self.target, scheme=scheme)

        # Disable SSL verification for research purposes
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx)
        )

        req = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; ShadowRecon/1.0; Security Research)",
                "Accept":     "*/*",
                "Connection": "close",
            }
        )

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                headers_raw = dict(resp.headers)
                final_url   = resp.geturl()
                status_code = resp.status

        except urllib.error.HTTPError as e:
            # Still capture headers from error responses
            headers_raw = dict(e.headers) if hasattr(e, "headers") else {}
            final_url   = url
            status_code = e.code

        except urllib.error.URLError as e:
            return {"error": str(e.reason)}
        except Exception as e:
            self.logger.debug(f"HTTP {scheme} failed: {e}")
            return {"error": str(e)}

        # Analyze headers
        headers_lower = {k.lower(): v for k, v in headers_raw.items()}
        interesting   = {k: v for k, v in headers_lower.items() if k in INTERESTING_HEADERS}
        redirected    = final_url != url

        return {
            "URL":              url,
            "Final URL":        final_url if redirected else "No redirect",
            "Status Code":      status_code,
            "Redirected":       redirected,
            "Protocol":         scheme.upper(),
            "All Headers":      headers_raw,
            "Interesting":      interesting,
            "Header Count":     len(headers_raw),
            "Content-Type":     headers_lower.get("content-type", "N/A"),
            "Content-Length":   headers_lower.get("content-length", "N/A"),
            "Server":           headers_lower.get("server", "Not disclosed"),
            "X-Powered-By":     headers_lower.get("x-powered-by", "Not disclosed"),
            "Cache-Control":    headers_lower.get("cache-control", "N/A"),
            "Set-Cookie":       bool(headers_lower.get("set-cookie")),
            "Date":             headers_lower.get("date", "N/A"),
        }

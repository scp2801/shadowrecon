#!/usr/bin/env python3
"""
modules/tech_detection.py
──────────────────────────
Detect web technologies, frameworks, CMS, CDN, WAF, and server info
by analyzing HTTP headers, HTML content, cookies, and URL patterns.
No external Wappalyzer dependency — uses built-in signature database.
"""

import re
import ssl
import urllib.request
import urllib.error
from utils.logger import get_logger
from utils.helpers import build_url

# ─── Technology Signature Database ────────────────────────────────────────────

SIGNATURES = {
    # Web Servers
    "Apache":          {"headers": {"server": r"Apache"}},
    "Nginx":           {"headers": {"server": r"nginx"}},
    "IIS":             {"headers": {"server": r"Microsoft-IIS"}},
    "LiteSpeed":       {"headers": {"server": r"LiteSpeed"}},
    "Caddy":           {"headers": {"server": r"Caddy"}},
    "OpenResty":       {"headers": {"server": r"openresty"}},

    # Programming Languages/Frameworks
    "PHP":             {"headers": {"x-powered-by": r"PHP"}, "html": r"\.php"},
    "ASP.NET":         {"headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".+"}},
    "Node.js":         {"headers": {"x-powered-by": r"Express"}},
    "Ruby on Rails":   {"headers": {"x-powered-by": r"Phusion Passenger"}, "html": r"csrf-token"},
    "Django":          {"html": r"csrfmiddlewaretoken", "cookies": r"csrftoken"},
    "Laravel":         {"cookies": r"laravel_session"},
    "Flask":           {"cookies": r"session="},
    "Spring Boot":     {"headers": {"x-application-context": r".+"}},

    # CMS Platforms
    "WordPress":       {"html": r"/wp-content/|/wp-includes/|wordpress", "headers": {"x-pingback": r".+"}},
    "Joomla":          {"html": r"/components/com_|Joomla"},
    "Drupal":          {"html": r"Drupal\.settings|sites/default/files", "headers": {"x-drupal-cache": r".+"}},
    "Magento":         {"html": r"Mage\.Cookies|/skin/frontend/"},
    "Shopify":         {"html": r"cdn\.shopify\.com|Shopify\.theme"},
    "Ghost":           {"html": r"ghost-theme|ghost\.io"},
    "Squarespace":     {"html": r"squarespace\.com"},
    "Wix":             {"html": r"wix\.com|wixsite\.com"},
    "Webflow":         {"html": r"webflow\.com"},

    # JavaScript Frameworks
    "React":           {"html": r"react\.js|react-dom|__REACT_DEVTOOLS"},
    "Vue.js":          {"html": r"vue\.js|vue\.min\.js|__vue__"},
    "Angular":         {"html": r"ng-version=|angular\.js"},
    "jQuery":          {"html": r"jquery[.-]\d+|jquery\.min\.js"},
    "Next.js":         {"html": r"__NEXT_DATA__|/_next/static/"},
    "Nuxt.js":         {"html": r"__nuxt|_nuxt/"},
    "Svelte":          {"html": r"svelte-"},

    # CDN / Infrastructure
    "Cloudflare":      {"headers": {"cf-ray": r".+", "server": r"cloudflare"}},
    "AWS CloudFront":  {"headers": {"x-amz-cf-id": r".+", "via": r"CloudFront"}},
    "Fastly":          {"headers": {"x-served-by": r"cache-.+", "x-cache": r".+"}},
    "Varnish":         {"headers": {"x-varnish": r"\d+", "via": r"varnish"}},
    "Akamai":          {"headers": {"x-check-cacheable": r".+"}},

    # WAF / Security
    "Cloudflare WAF":  {"html": r"Attention Required|cloudflare-nginx", "headers": {"cf-ray": r".+"}},
    "ModSecurity":     {"headers": {"server": r"Mod_Security|NOYB"}},
    "Sucuri WAF":      {"headers": {"x-sucuri-id": r".+"}},
    "Incapsula":       {"cookies": r"incap_ses|visid_incap"},
    "Imperva":         {"headers": {"x-iinfo": r".+"}},

    # Analytics / Marketing
    "Google Analytics":{"html": r"UA-\d+|gtag\.js|analytics\.js|G-[A-Z0-9]+"},
    "Google Tag Manager":{"html": r"googletagmanager\.com/gtm\.js"},
    "Facebook Pixel":  {"html": r"connect\.facebook\.net/.*fbevents\.js"},
    "Hotjar":          {"html": r"static\.hotjar\.com"},

    # Databases (leaked via errors)
    "MySQL":           {"html": r"MySQL server|mysql_fetch"},
    "PostgreSQL":      {"html": r"PostgreSQL.*ERROR|pg_query"},
    "MongoDB":         {"html": r"MongoError|mongodb://"},

    # E-commerce
    "WooCommerce":     {"html": r"woocommerce|wc-api"},
    "PrestaShop":      {"html": r"prestashop|/modules/"},
    "OpenCart":        {"html": r"route=common/home|opencart"},
}


class TechDetection:
    """
    Technology detection via HTTP response analysis.
    Matches headers, HTML content, and cookies against signature database.
    """

    def __init__(self, target: str, timeout: int = 10):
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Fetch target page and detect technologies.
        
        Returns:
            Dictionary of detected technologies by category
        """
        self.logger.info(f"TechDetection.run() → {self.target}")

        # Fetch page content
        page_data = self._fetch_page()
        if not page_data:
            return {"error": "Could not fetch page content"}

        detected = self._detect_technologies(page_data)

        return {
            "URL":             page_data.get("url", "N/A"),
            "Status Code":     page_data.get("status", "N/A"),
            "Detected Technologies": detected,
            "Total Detected":  sum(len(v) for v in detected.values()) if isinstance(detected, dict) else len(detected),
        }

    def _fetch_page(self) -> dict:
        """Fetch a page and return headers + HTML content."""
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
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                with opener.open(req, timeout=self.timeout) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    html    = resp.read(50000).decode("utf-8", errors="replace")  # First 50KB
                    cookies = headers.get("set-cookie", "")
                    return {
                        "url":     url,
                        "status":  resp.status,
                        "headers": headers,
                        "html":    html.lower(),
                        "cookies": cookies.lower(),
                    }
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
                return {"url": url, "status": e.code, "headers": headers, "html": "", "cookies": ""}
            except Exception as e:
                self.logger.debug(f"TechDetection fetch {scheme} failed: {e}")

        return None

    def _detect_technologies(self, page_data: dict) -> dict:
        """
        Match page data against signature database.
        
        Args:
            page_data: Dict with headers, html, cookies keys
            
        Returns:
            Dict of category → list of detected tech names
        """
        matched = []
        headers = page_data.get("headers", {})
        html    = page_data.get("html", "")
        cookies = page_data.get("cookies", "")

        for tech, sigs in SIGNATURES.items():
            found = False

            # Check header signatures
            for header_name, pattern in sigs.get("headers", {}).items():
                val = headers.get(header_name, "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    found = True
                    break

            # Check HTML signatures
            if not found and "html" in sigs:
                if re.search(sigs["html"], html, re.IGNORECASE):
                    found = True

            # Check cookie signatures
            if not found and "cookies" in sigs:
                if re.search(sigs["cookies"], cookies, re.IGNORECASE):
                    found = True

            if found:
                matched.append(tech)

        # Categorize
        categories = {
            "Web Server":     [t for t in matched if t in ("Apache","Nginx","IIS","LiteSpeed","Caddy","OpenResty")],
            "Language/Framework": [t for t in matched if t in ("PHP","ASP.NET","Node.js","Ruby on Rails","Django","Laravel","Flask","Spring Boot")],
            "CMS":            [t for t in matched if t in ("WordPress","Joomla","Drupal","Magento","Shopify","Ghost","Squarespace","Wix","Webflow")],
            "JavaScript":     [t for t in matched if t in ("React","Vue.js","Angular","jQuery","Next.js","Nuxt.js","Svelte")],
            "CDN":            [t for t in matched if t in ("Cloudflare","AWS CloudFront","Fastly","Varnish","Akamai")],
            "WAF/Security":   [t for t in matched if "WAF" in t or t in ("ModSecurity","Sucuri WAF","Incapsula","Imperva")],
            "Analytics":      [t for t in matched if t in ("Google Analytics","Google Tag Manager","Facebook Pixel","Hotjar")],
            "E-commerce":     [t for t in matched if t in ("WooCommerce","PrestaShop","OpenCart")],
            "Database":       [t for t in matched if t in ("MySQL","PostgreSQL","MongoDB")],
        }

        return {cat: items for cat, items in categories.items() if items}

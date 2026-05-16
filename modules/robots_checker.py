#!/usr/bin/env python3
"""
modules/robots_checker.py
──────────────────────────
Fetch and parse robots.txt and sitemap.xml from a target domain.
Identifies disallowed paths, sitemaps, crawl delays, and interesting patterns
that may reveal hidden endpoints or application structure.
"""

import ssl
import re
import urllib.request
import urllib.error
from utils.logger import get_logger
from utils.helpers import build_url

# Patterns in robots.txt that may indicate sensitive/interesting paths
INTERESTING_PATTERNS = [
    r"/admin", r"/login", r"/dashboard", r"/api", r"/backup",
    r"/config", r"/secret", r"/private", r"/internal", r"/dev",
    r"/test", r"/staging", r"/debug", r"/upload", r"/database",
    r"/\.git", r"/\.env", r"/wp-admin", r"/phpmyadmin",
]


class RobotsChecker:
    """Robots.txt and sitemap.xml analysis module."""

    def __init__(self, target: str, timeout: int = 10):
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Fetch robots.txt and sitemaps, parse directives, flag interesting entries.
        
        Returns:
            Dictionary with robots.txt content, parsed rules, and sitemap data
        """
        self.logger.info(f"RobotsChecker.run() → {self.target}")
        result = {}

        # ── Robots.txt ──────────────────────────────────────────────
        robots_content = self._fetch_file("robots.txt")
        if robots_content:
            parsed = self._parse_robots(robots_content)
            result.update({
                "robots.txt Found":   True,
                "User-Agents":         parsed.get("agents", []),
                "Disallowed Paths":    parsed.get("disallowed", []),
                "Allowed Paths":       parsed.get("allowed", []),
                "Sitemaps in robots":  parsed.get("sitemaps", []),
                "Crawl Delay":         parsed.get("crawl_delay", "Not set"),
                "Interesting Paths":   self._flag_interesting(parsed.get("disallowed", [])),
                "Total Disallowed":    len(parsed.get("disallowed", [])),
            })
        else:
            result["robots.txt Found"] = False
            result["Note"] = "No robots.txt found or access denied"

        # ── Sitemap.xml ─────────────────────────────────────────────
        sitemap = self._fetch_file("sitemap.xml")
        if sitemap:
            urls = re.findall(r"<loc>(.*?)</loc>", sitemap, re.IGNORECASE)
            result["sitemap.xml Found"] = True
            result["Sitemap URL Count"] = len(urls)
            result["Sitemap Sample"]    = urls[:15]  # Show first 15 URLs
        else:
            result["sitemap.xml Found"] = False

        # ── Security.txt ─────────────────────────────────────────────
        for path in (".well-known/security.txt", "security.txt"):
            sec_txt = self._fetch_file(path)
            if sec_txt:
                result["security.txt Found"] = True
                result["security.txt Path"]  = path
                result["security.txt Content"] = sec_txt[:500]
                break
        else:
            result["security.txt Found"] = False

        return result

    def _fetch_file(self, path: str) -> str:
        """
        Fetch a file from the target server.
        
        Args:
            path: URL path relative to domain root
            
        Returns:
            File content as string, or None if not found
        """
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx)
        )

        for scheme in ("https", "http"):
            url = build_url(self.target, path=path, scheme=scheme)
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; ShadowRecon/1.0)"}
                )
                with opener.open(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        content = resp.read(100000).decode("utf-8", errors="replace")
                        self.logger.debug(f"Fetched {url} ({len(content)} bytes)")
                        return content
            except urllib.error.HTTPError:
                pass
            except Exception as e:
                self.logger.debug(f"Fetch {path} ({scheme}) failed: {e}")

        return None

    def _parse_robots(self, content: str) -> dict:
        """
        Parse robots.txt content into structured directives.
        
        Args:
            content: Raw robots.txt file content
            
        Returns:
            Dictionary with agents, disallowed, allowed, sitemaps, crawl_delay
        """
        result = {
            "agents":      [],
            "disallowed":  [],
            "allowed":     [],
            "sitemaps":    [],
            "crawl_delay": None,
        }

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            lower = line.lower()

            if lower.startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip()
                if agent and agent not in result["agents"]:
                    result["agents"].append(agent)

            elif lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    result["disallowed"].append(path)

            elif lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    result["allowed"].append(path)

            elif lower.startswith("sitemap:"):
                url = line.split(":", 1)[1].strip()
                if url:
                    result["sitemaps"].append(url)

            elif lower.startswith("crawl-delay:"):
                delay = line.split(":", 1)[1].strip()
                result["crawl_delay"] = delay

        return result

    def _flag_interesting(self, paths: list) -> list:
        """
        Identify potentially sensitive paths from the disallowed list.
        
        Args:
            paths: List of disallowed path strings
            
        Returns:
            List of paths matching interesting patterns
        """
        flagged = []
        for path in paths:
            for pattern in INTERESTING_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    if path not in flagged:
                        flagged.append(path)
                    break
        return flagged

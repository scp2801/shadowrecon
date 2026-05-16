#!/usr/bin/env python3
"""
modules/subdomain_finder.py
────────────────────────────
Enumerate subdomains via DNS brute-forcing using a built-in wordlist
and an optional custom wordlist. Uses concurrent threading for speed.
Also queries crt.sh certificate transparency logs for passive discovery.
"""

import socket
import time
import sys
import threading
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger
from utils.banner import print_subdomain, print_info, progress_bar, Colors, c

# ─── Built-in wordlist (top ~200 common subdomains) ───────────────────────────
BUILTIN_WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ssh",
    "vpn", "remote", "citrix", "api", "dev", "staging", "stage",
    "test", "beta", "alpha", "demo", "qa", "uat", "prod", "production",
    "admin", "administrator", "portal", "dashboard", "panel", "control",
    "login", "auth", "sso", "oauth", "secure", "security",
    "blog", "shop", "store", "pay", "payment", "checkout",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "upload", "downloads", "dl", "releases",
    "docs", "documentation", "wiki", "help", "support", "kb",
    "forum", "community", "chat", "slack", "teams",
    "git", "gitlab", "github", "bitbucket", "svn", "repo",
    "jira", "confluence", "jenkins", "ci", "cd", "build",
    "monitor", "status", "metrics", "grafana", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "mx", "mx1", "mx2", "mail1", "mail2", "smtp1", "smtp2",
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "web", "web1", "web2", "app", "app1", "app2",
    "mobile", "m", "wap",
    "intranet", "internal", "private", "local",
    "backup", "bak", "old", "archive", "legacy",
    "dev1", "dev2", "staging1", "staging2", "test1", "test2",
    "owa", "exchange", "autodiscover", "webmail", "roundcube",
    "cpanel", "whm", "plesk", "directadmin", "webdisk",
    "proxy", "gateway", "firewall", "router", "vpn1", "vpn2",
    "office", "sharepoint", "teams", "outlook",
    "api-v1", "api-v2", "apiv1", "apiv2", "v1", "v2",
    "graphql", "rest", "soap", "webhook", "ws",
    "analytics", "tracking", "ads", "campaign",
    "careers", "jobs", "hr",
    "legal", "privacy", "terms",
    "partner", "partners", "reseller", "affiliates",
    "cloud", "s3", "bucket", "storage",
    "update", "updates", "patches",
    "sandbox", "lab", "labs",
]


class SubdomainFinder:
    """
    Subdomain enumeration via:
    1. DNS brute-force with built-in + custom wordlists
    2. Certificate Transparency log (crt.sh) passive discovery
    """

    def __init__(self, target: str, wordlist: str = None, threads: int = 50, timeout: float = 2.0):
        """
        Initialize subdomain finder.
        
        Args:
            target: Base domain to enumerate (e.g., 'example.com')
            wordlist: Optional path to custom wordlist file
            threads: Number of concurrent DNS resolution threads
            timeout: Per-subdomain DNS timeout in seconds
        """
        self.target   = target
        self.threads  = threads
        self.timeout  = timeout
        self.logger   = get_logger()
        self.found    = []
        self._lock    = threading.Lock()

        # Load wordlist
        self.wordlist = self._load_wordlist(wordlist)

    def _load_wordlist(self, custom_path: str) -> list:
        """Load and merge built-in and custom wordlist entries."""
        words = list(BUILTIN_WORDLIST)

        if custom_path:
            try:
                with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
                    custom = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    words.extend(custom)
                    self.logger.info(f"Loaded {len(custom)} words from {custom_path}")
            except FileNotFoundError:
                self.logger.warning(f"Wordlist not found: {custom_path}, using built-in")

        # Deduplicate while preserving order
        seen = set()
        return [w for w in words if not (w in seen or seen.add(w))]

    def run(self) -> dict:
        """
        Execute subdomain enumeration (brute-force + crt.sh).
        
        Returns:
            Dictionary with found subdomains and statistics
        """
        self.logger.info(f"SubdomainFinder.run() → {self.target}")

        results = {"subdomains": [], "crtsh": [], "stats": {}}

        # ── 1. Passive: crt.sh certificate transparency ──────────────
        crt_subs = self._query_crtsh()
        if crt_subs:
            results["crtsh"] = crt_subs
            print_info(f"  crt.sh found {len(crt_subs)} subdomains passively")

        # ── 2. Active: DNS brute-force ────────────────────────────────
        total = len(self.wordlist)
        checked = 0
        found_count = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_subdomain, word): word
                for word in self.wordlist
            }

            for future in as_completed(futures):
                checked += 1
                result = future.result()

                if result:
                    with self._lock:
                        self.found.append(result)
                        found_count += 1
                    print_subdomain(result["subdomain"], result.get("ip", ""))

                # Progress bar update
                bar = progress_bar(checked, total, width=35, label=f"({found_count} found)")
                sys.stdout.write(bar)
                sys.stdout.flush()

        sys.stdout.write("\r" + " " * 80 + "\r")  # Clear progress bar
        sys.stdout.flush()

        results["subdomains"] = self.found
        results["stats"] = {
            "total_checked": total,
            "found_brute":   len(self.found),
            "found_crtsh":   len(crt_subs),
            "threads_used":  self.threads,
        }

        return results

    def _check_subdomain(self, word: str) -> dict:
        """
        Attempt to resolve a subdomain and return info if it exists.
        
        Args:
            word: Subdomain prefix (e.g., 'mail' → 'mail.example.com')
            
        Returns:
            Dict with subdomain and IP if resolved, else None
        """
        subdomain = f"{word}.{self.target}"
        original_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            ip = socket.gethostbyname(subdomain)
            return {"subdomain": subdomain, "ip": ip}
        except (socket.gaierror, socket.timeout):
            return None
        except Exception as e:
            self.logger.debug(f"Subdomain check error {subdomain}: {e}")
            return None
        finally:
            socket.setdefaulttimeout(original_timeout)

    def _query_crtsh(self) -> list:
        """
        Query crt.sh certificate transparency logs for passive subdomain discovery.
        
        Returns:
            Sorted list of unique subdomain strings
        """
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ShadowRecon/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.")
                    if self.target in line and line != self.target:
                        subs.add(line.lower())

            return sorted(subs)

        except Exception as e:
            self.logger.warning(f"crt.sh query failed: {e}")
            return []

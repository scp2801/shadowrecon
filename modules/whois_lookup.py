#!/usr/bin/env python3
"""
modules/whois_lookup.py
───────────────────────
Perform WHOIS lookups for domains and IP addresses.
Uses the python-whois library with fallback to raw socket queries.
"""

import socket
import re
from datetime import datetime
from utils.logger import get_logger
from utils.helpers import is_ip_address
from utils.banner import print_kv, print_warning

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class WhoisLookup:
    """
    WHOIS lookup module supporting domains and IP addresses.
    Falls back to raw socket query if python-whois is unavailable.
    """

    # Common WHOIS server for IP queries
    ARIN_WHOIS = "whois.arin.net"

    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize the WHOIS lookup module.
        
        Args:
            target: Domain name or IP address
            timeout: Socket timeout in seconds
        """
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Execute the WHOIS lookup and return structured results.
        
        Returns:
            Dictionary of WHOIS fields
        """
        self.logger.info(f"WhoisLookup.run() → {self.target}")

        if is_ip_address(self.target):
            return self._ip_whois()
        else:
            return self._domain_whois()

    def _domain_whois(self) -> dict:
        """Perform domain WHOIS lookup using python-whois."""
        if not WHOIS_AVAILABLE:
            self.logger.warning("python-whois not installed; using raw query")
            return self._raw_whois(self.target, "whois.iana.org")

        try:
            w = python_whois.whois(self.target)
        except Exception as e:
            self.logger.error(f"python-whois failed: {e}")
            return {"error": str(e)}

        def fmt_date(d):
            """Format date value (may be list or datetime)."""
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d.strftime("%Y-%m-%d %H:%M:%S UTC")
            return str(d) if d else "N/A"

        def fmt_list(lst):
            """Normalize list or string to a clean list."""
            if isinstance(lst, list):
                return [str(x).strip() for x in lst if x]
            return [str(lst).strip()] if lst else []

        return {
            "Domain Name":       getattr(w, "domain_name", "N/A"),
            "Registrar":         getattr(w, "registrar",   "N/A"),
            "WHOIS Server":      getattr(w, "whois_server","N/A"),
            "Created":           fmt_date(getattr(w, "creation_date",    None)),
            "Updated":           fmt_date(getattr(w, "updated_date",     None)),
            "Expires":           fmt_date(getattr(w, "expiration_date",  None)),
            "Status":            fmt_list(getattr(w, "status",           [])),
            "Name Servers":      fmt_list(getattr(w, "name_servers",     [])),
            "Registrant Org":    getattr(w, "org",                        "N/A"),
            "Registrant Country":getattr(w, "country",                   "N/A"),
            "Emails":            fmt_list(getattr(w, "emails",           [])),
            "DNSSEC":            getattr(w, "dnssec",                    "N/A"),
        }

    def _ip_whois(self) -> dict:
        """Perform IP WHOIS lookup using raw socket query to ARIN."""
        try:
            return self._raw_whois(self.target, self.ARIN_WHOIS)
        except Exception as e:
            self.logger.error(f"IP WHOIS failed: {e}")
            return {"error": str(e)}

    def _raw_whois(self, query: str, server: str) -> dict:
        """
        Send a raw WHOIS query over TCP port 43.
        
        Args:
            query: WHOIS query string
            server: WHOIS server hostname
            
        Returns:
            Parsed dictionary of key-value pairs
        """
        try:
            with socket.create_connection((server, 43), timeout=self.timeout) as sock:
                sock.sendall(f"{query}\r\n".encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

            raw = response.decode("utf-8", errors="replace")
            return self._parse_raw_whois(raw)

        except socket.timeout:
            return {"error": f"WHOIS query timed out ({self.timeout}s)"}
        except Exception as e:
            self.logger.error(f"Raw WHOIS error: {e}")
            return {"error": str(e)}

    def _parse_raw_whois(self, raw: str) -> dict:
        """
        Parse raw WHOIS response text into key-value pairs.
        Skips comment lines and deduplicates keys.
        
        Args:
            raw: Raw WHOIS response string
            
        Returns:
            Dictionary of parsed fields
        """
        result = {}
        for line in raw.splitlines():
            line = line.strip()
            # Skip empty lines and comment lines
            if not line or line.startswith("%") or line.startswith("#"):
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key   = key.strip()
                value = value.strip()
                if key and value and key not in result:
                    result[key] = value

        if not result:
            result["raw_response"] = raw[:500]  # Fallback: include partial raw

        return result

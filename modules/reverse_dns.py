#!/usr/bin/env python3
"""
modules/reverse_dns.py
───────────────────────
Perform reverse DNS lookups (PTR records) on a target IP or domain.
Resolves the domain first if needed, then queries PTR records.
"""

import socket
from utils.logger import get_logger
from utils.helpers import is_ip_address, resolve_to_ip


class ReverseDNS:
    """Reverse DNS (PTR record) lookup module."""

    def __init__(self, target: str, timeout: int = 5):
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Perform reverse DNS lookup on the target.
        
        Returns:
            Dictionary with PTR record info and related data
        """
        self.logger.info(f"ReverseDNS.run() → {self.target}")

        # Resolve to IP if domain
        ip = resolve_to_ip(self.target)
        if not ip:
            return {"error": f"Could not resolve {self.target}"}

        result = {
            "Original Target": self.target,
            "Resolved IP":     ip,
        }

        # PTR lookup
        try:
            socket.setdefaulttimeout(self.timeout)
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            result["PTR Hostname"] = hostname
            result["Aliases"]      = aliases if aliases else ["None"]
        except socket.herror as e:
            result["PTR Hostname"] = f"No PTR record ({e})"
        except Exception as e:
            result["PTR Hostname"] = f"Lookup failed: {e}"

        # Reverse PTR notation
        parts = ip.split(".")
        if len(parts) == 4:
            arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
            result["ARPA Address"] = arpa

        # Forward-confirmed reverse DNS check
        if "PTR Hostname" in result and "No PTR" not in result["PTR Hostname"]:
            try:
                forward_ip = socket.gethostbyname(result["PTR Hostname"])
                match = forward_ip == ip
                result["FCrDNS Match"] = f"{'✓ PASS' if match else '✗ FAIL'} ({forward_ip})"
            except Exception:
                result["FCrDNS Match"] = "Could not verify"

        return result

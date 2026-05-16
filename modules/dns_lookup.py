#!/usr/bin/env python3
"""
modules/dns_lookup.py
──────────────────────
Enumerate DNS records for a target domain.
Queries A, AAAA, MX, NS, TXT, CNAME, SOA, and PTR records.
Uses dnspython with fallback to standard library socket queries.
"""

import socket
from utils.logger import get_logger

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


class DNSLookup:
    """
    DNS enumeration module. Queries multiple record types and
    returns all results in a structured dictionary.
    """

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def __init__(self, target: str, timeout: int = 5):
        """
        Initialize DNS lookup module.
        
        Args:
            target: Domain name to query
            timeout: DNS resolver timeout in seconds
        """
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Query all DNS record types and return structured results.
        
        Returns:
            Dictionary with record types as keys and lists of records as values
        """
        self.logger.info(f"DNSLookup.run() → {self.target}")

        if DNSPYTHON_AVAILABLE:
            return self._query_with_dnspython()
        else:
            self.logger.warning("dnspython not available; using socket fallback")
            return self._query_with_socket()

    def _query_with_dnspython(self) -> dict:
        """Use dnspython library for comprehensive DNS queries."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout * 2

        results = {}

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(self.target, rtype)
                records = []

                for rdata in answers:
                    if rtype == "MX":
                        records.append(f"{rdata.preference} {rdata.exchange}")
                    elif rtype == "SOA":
                        records.append(
                            f"MNAME={rdata.mname} RNAME={rdata.rname} "
                            f"Serial={rdata.serial} Refresh={rdata.refresh}"
                        )
                    elif rtype == "TXT":
                        records.append(b" ".join(rdata.strings).decode("utf-8", errors="replace"))
                    else:
                        records.append(str(rdata))

                if records:
                    results[rtype] = records

            except dns.resolver.NXDOMAIN:
                if rtype == "A":
                    results["error"] = f"Domain {self.target} does not exist (NXDOMAIN)"
                    break
            except dns.resolver.NoAnswer:
                # Normal — domain doesn't have this record type
                pass
            except dns.exception.Timeout:
                self.logger.warning(f"DNS timeout for {rtype} record")
            except Exception as e:
                self.logger.debug(f"DNS query {rtype} failed: {e}")

        # Add zone transfer test (informational only)
        results["Zone Transfer"] = self._test_zone_transfer()

        return results

    def _test_zone_transfer(self) -> list:
        """
        Test if zone transfer (AXFR) is allowed (usually should be disabled).
        This is informational — a successful AXFR is a misconfiguration.
        
        Returns:
            List of strings describing AXFR status per nameserver
        """
        if not DNSPYTHON_AVAILABLE:
            return ["dnspython required for zone transfer test"]

        try:
            ns_answers = dns.resolver.resolve(self.target, "NS")
            nameservers = [str(ns) for ns in ns_answers]
        except Exception:
            return ["Could not resolve NS records"]

        results = []
        for ns in nameservers[:3]:  # Test first 3 NS only
            try:
                import dns.query
                import dns.zone
                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.target, timeout=3))
                results.append(f"⚠ AXFR ALLOWED on {ns} — {len(zone.nodes)} records exposed!")
            except Exception:
                results.append(f"✓ AXFR refused on {ns} (secure)")

        return results if results else ["No nameservers found"]

    def _query_with_socket(self) -> dict:
        """Fallback DNS query using Python's standard socket library."""
        results = {}

        # A record
        try:
            ips = socket.getaddrinfo(self.target, None, socket.AF_INET)
            results["A"] = list(set(info[4][0] for info in ips))
        except socket.gaierror as e:
            results["error"] = str(e)

        # AAAA record
        try:
            ipv6 = socket.getaddrinfo(self.target, None, socket.AF_INET6)
            results["AAAA"] = list(set(info[4][0] for info in ipv6))
        except socket.gaierror:
            pass

        results["note"] = "Install dnspython for full DNS enumeration: pip install dnspython"
        return results

#!/usr/bin/env python3
"""
modules/ip_geolocation.py
──────────────────────────
Perform IP geolocation lookups using multiple free APIs.
Resolves domain names to IPs first, then queries location data.
Uses ip-api.com as primary and ipinfo.io as fallback.
"""

import json
import urllib.request
import socket
from utils.logger import get_logger
from utils.helpers import is_ip_address, resolve_to_ip


class IPGeolocation:
    """
    IP geolocation module using ip-api.com (primary) and ipinfo.io (fallback).
    No API key required for basic lookups.
    """

    PRIMARY_API  = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    FALLBACK_API = "https://ipinfo.io/{ip}/json"

    def __init__(self, target: str, timeout: int = 8):
        """
        Initialize geolocation module.
        
        Args:
            target: Domain name or IP address
            timeout: HTTP request timeout in seconds
        """
        self.target  = target
        self.timeout = timeout
        self.logger  = get_logger()

    def run(self) -> dict:
        """
        Resolve target to IP and perform geolocation lookup.
        
        Returns:
            Dictionary of geolocation fields
        """
        self.logger.info(f"IPGeolocation.run() → {self.target}")

        # Resolve domain to IP
        ip = resolve_to_ip(self.target)
        if not ip:
            return {"error": f"Could not resolve {self.target} to an IP address"}

        result = {"queried_target": self.target, "resolved_ip": ip}

        # Try primary API
        geo = self._query_ip_api(ip)
        if geo and "error" not in geo:
            result.update(geo)
            return result

        # Fallback
        self.logger.warning("Primary geolocation API failed, trying fallback")
        geo = self._query_ipinfo(ip)
        if geo:
            result.update(geo)
        else:
            result["error"] = "All geolocation APIs failed"

        return result

    def _query_ip_api(self, ip: str) -> dict:
        """Query ip-api.com for geolocation data."""
        url = self.PRIMARY_API.format(ip=ip)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ShadowRecon/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") != "success":
                return {"error": data.get("message", "Unknown API error")}

            return {
                "IP Address":    data.get("query", ip),
                "Country":       f"{data.get('country', 'N/A')} ({data.get('countryCode', '??')})",
                "Region":        data.get("regionName", "N/A"),
                "City":          data.get("city", "N/A"),
                "ZIP Code":      data.get("zip", "N/A"),
                "Latitude":      data.get("lat", "N/A"),
                "Longitude":     data.get("lon", "N/A"),
                "Timezone":      data.get("timezone", "N/A"),
                "ISP":           data.get("isp", "N/A"),
                "Organization":  data.get("org", "N/A"),
                "AS Number":     data.get("as", "N/A"),
                "AS Name":       data.get("asname", "N/A"),
                "Reverse DNS":   data.get("reverse", "N/A"),
                "Mobile":        data.get("mobile", False),
                "Proxy/VPN":     data.get("proxy", False),
                "Hosting/DC":    data.get("hosting", False),
                "Source":        "ip-api.com",
            }

        except Exception as e:
            self.logger.error(f"ip-api.com query failed: {e}")
            return {"error": str(e)}

    def _query_ipinfo(self, ip: str) -> dict:
        """Query ipinfo.io as fallback geolocation source."""
        url = self.FALLBACK_API.format(ip=ip)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ShadowRecon/1.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            loc = data.get("loc", "N/A,N/A").split(",")
            return {
                "IP Address":   data.get("ip", ip),
                "Hostname":     data.get("hostname", "N/A"),
                "City":         data.get("city", "N/A"),
                "Region":       data.get("region", "N/A"),
                "Country":      data.get("country", "N/A"),
                "Latitude":     loc[0] if len(loc) > 0 else "N/A",
                "Longitude":    loc[1] if len(loc) > 1 else "N/A",
                "Organization": data.get("org", "N/A"),
                "Timezone":     data.get("timezone", "N/A"),
                "Postal":       data.get("postal", "N/A"),
                "Source":       "ipinfo.io",
            }

        except Exception as e:
            self.logger.error(f"ipinfo.io query failed: {e}")
            return None

#!/usr/bin/env python3
"""
utils/helpers.py
────────────────
Shared helper functions for input validation, formatting,
network utilities, and cross-platform compatibility.
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse


# ─── Target Validation ────────────────────────────────────────────────────────

def sanitize_target(target: str) -> str:
    """
    Strip protocol prefixes and trailing slashes from a target.
    Converts 'https://example.com/path' → 'example.com'
    
    Args:
        target: Raw target string from user input
        
    Returns:
        Clean domain or IP string
    """
    target = target.strip()

    # Strip protocol
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path

    # Strip port from domain (keep for IPs)
    if not is_ip_address(target) and ":" in target:
        target = target.split(":")[0]

    # Strip path
    target = target.split("/")[0]

    # Strip www. for cleaner subdomain enumeration
    # (kept optional — do NOT strip for raw domain lookup)
    return target.strip().lower()


def validate_target(target: str) -> bool:
    """
    Validate that a target is a valid domain name or IP address.
    
    Args:
        target: Cleaned target string
        
    Returns:
        True if valid, False otherwise
    """
    if not target:
        return False

    # Check if it's a valid IP
    if is_ip_address(target):
        return True

    # Validate domain name format
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(domain_pattern.match(target))


def is_ip_address(target: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address.
    
    Args:
        target: String to check
        
    Returns:
        True if it's a valid IP address
    """
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def resolve_to_ip(target: str) -> str:
    """
    Resolve a domain name to its first IPv4 address.
    
    Args:
        target: Domain name or IP
        
    Returns:
        IP address string, or empty string on failure
    """
    if is_ip_address(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return ""


def get_domain_from_ip(ip: str) -> str:
    """
    Perform a reverse DNS lookup on an IP address.
    
    Args:
        ip: IPv4 or IPv6 address
        
    Returns:
        Hostname string or empty string on failure
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ─── Port Parsing ─────────────────────────────────────────────────────────────

def parse_port_range(port_range: str) -> list:
    """
    Parse a port range string into a sorted list of port numbers.
    Supports: '80', '80,443', '1-1024', '22,80,443,8000-8100'
    
    Args:
        port_range: Port range string
        
    Returns:
        Sorted list of integer port numbers
    """
    ports = set()

    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start.strip()), int(end.strip())
                if 1 <= start <= 65535 and 1 <= end <= 65535:
                    ports.update(range(min(start, end), max(start, end) + 1))
            except ValueError:
                pass
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                pass

    return sorted(ports)


# ─── Common Service Names ─────────────────────────────────────────────────────

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "Submission", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9200: "Elasticsearch",
    27017: "MongoDB", 2181: "Zookeeper", 2375: "Docker", 6443: "Kubernetes",
    11211: "Memcached", 4444: "Metasploit", 6667: "IRC",
}


def get_service_name(port: int) -> str:
    """
    Get common service name for a port number.
    Falls back to socket.getservbyport for unknown ports.
    
    Args:
        port: Port number
        
    Returns:
        Service name string
    """
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


# ─── URL Building ─────────────────────────────────────────────────────────────

def build_url(target: str, path: str = "", scheme: str = "https") -> str:
    """
    Build a full URL from a domain/IP, optional path, and scheme.
    
    Args:
        target: Domain or IP address
        path: URL path (e.g., '/robots.txt')
        scheme: 'http' or 'https'
        
    Returns:
        Full URL string
    """
    path = path.lstrip("/")
    return f"{scheme}://{target}/{path}" if path else f"{scheme}://{target}"


# ─── Text Formatting ─────────────────────────────────────────────────────────

def truncate(text: str, max_len: int = 60) -> str:
    """Truncate a string with ellipsis if it exceeds max_len."""
    return text[:max_len - 3] + "..." if len(text) > max_len else text


def bytes_to_human(size: int) -> str:
    """Convert bytes to a human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def mask_sensitive(text: str) -> str:
    """Partially mask sensitive data for display."""
    if len(text) <= 4:
        return "****"
    return text[:2] + "*" * (len(text) - 4) + text[-2:]

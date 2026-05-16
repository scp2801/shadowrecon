#!/usr/bin/env python3
"""
modules/port_scanner.py
────────────────────────
Multi-threaded TCP port scanner with banner grabbing.
Resolves targets, scans port ranges, identifies services,
and attempts to grab service banners for fingerprinting.
"""

import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger
from utils.helpers import parse_port_range, get_service_name, resolve_to_ip
from utils.banner import print_open_port, progress_bar


class PortScanner:
    """
    High-speed TCP port scanner using ThreadPoolExecutor.
    Supports custom port ranges, banner grabbing, and progress display.
    """

    def __init__(self, target: str, port_range: str = "1-1024",
                 threads: int = 100, timeout: float = 1.0):
        """
        Initialize port scanner.
        
        Args:
            target: Domain name or IP address
            port_range: Port range string (e.g., '1-1024', '80,443,8080')
            threads: Maximum concurrent scan threads
            timeout: Per-port connection timeout in seconds
        """
        self.target     = target
        self.port_range = port_range
        self.threads    = threads
        self.timeout    = timeout
        self.logger     = get_logger()
        self._lock      = threading.Lock()

    def run(self) -> dict:
        """
        Execute the port scan and return structured results.
        
        Returns:
            Dictionary with open ports, stats, and scan metadata
        """
        self.logger.info(f"PortScanner.run() → {self.target} [{self.port_range}]")

        # Resolve target to IP
        ip = resolve_to_ip(self.target)
        if not ip:
            return {"error": f"Could not resolve {self.target} to an IP address"}

        ports = parse_port_range(self.port_range)
        if not ports:
            return {"error": f"Invalid port range: {self.port_range}"}

        total     = len(ports)
        open_ports = []
        checked   = 0

        self.logger.info(f"Scanning {total} ports on {ip} with {self.threads} threads")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port): port
                for port in ports
            }

            for future in as_completed(futures):
                checked += 1
                result = future.result()

                if result:
                    with self._lock:
                        open_ports.append(result)
                    print_open_port(
                        result["port"],
                        result["service"],
                        result.get("banner", "")
                    )

                # Update progress bar
                bar = progress_bar(
                    checked, total, width=35,
                    label=f"port {futures[future]} ({len(open_ports)} open)"
                )
                sys.stdout.write(bar)
                sys.stdout.flush()

        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])

        return {
            "Target IP":    ip,
            "Port Range":   self.port_range,
            "Total Scanned":total,
            "Open Ports":   len(open_ports),
            "Threads":      self.threads,
            "Timeout":      f"{self.timeout}s",
            "Results":      open_ports,
        }

    def _scan_port(self, ip: str, port: int) -> dict:
        """
        Attempt a TCP connection to a single port.
        On success, attempt banner grabbing.
        
        Args:
            ip: Resolved IP address string
            port: Port number to scan
            
        Returns:
            Dict with port info if open, else None
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))

                if result == 0:
                    service = get_service_name(port)
                    banner  = self._grab_banner(ip, port, service)
                    return {
                        "port":    port,
                        "state":   "open",
                        "service": service,
                        "banner":  banner,
                    }
        except Exception:
            pass
        return None

    def _grab_banner(self, ip: str, port: int, service: str) -> str:
        """
        Attempt to grab a service banner from an open port.
        Uses service-specific probes for common protocols.
        
        Args:
            ip: Target IP address
            port: Open port number
            service: Service name (for protocol-specific probes)
            
        Returns:
            Banner string (truncated to 100 chars), or empty string
        """
        probes = {
            "HTTP":  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            "HTTPS": b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            "FTP":   b"",       # FTP sends banner on connect
            "SMTP":  b"",       # SMTP sends banner on connect
            "SSH":   b"",       # SSH sends banner on connect
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(min(self.timeout * 1.5, 2.0))
                sock.connect((ip, port))

                probe = probes.get(service, b"")
                if probe:
                    sock.sendall(probe)

                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                # Clean up banner — remove control characters
                banner = " ".join(banner.split())
                return banner[:100]

        except Exception:
            return ""

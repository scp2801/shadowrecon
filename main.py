#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║              ShadowRecon - OSINT Reconnaissance Toolkit       ║
║              Version: 1.0.0                                   ║
║              Author: ShadowRecon Project                      ║
║              License: MIT                                     ║
║              [FOR EDUCATIONAL USE ONLY]                       ║
╚═══════════════════════════════════════════════════════════════╝

Entry point for ShadowRecon CLI reconnaissance toolkit.
Handles argument parsing, module dispatch, and output management.
"""

import argparse
import sys
import os
import json
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.banner import print_banner, print_section, print_result, print_error, print_info, print_success, print_warning
from utils.logger import setup_logger, get_logger
from utils.exporter import export_results
from utils.helpers import validate_target, is_ip_address, sanitize_target

from modules.whois_lookup import WhoisLookup
from modules.dns_lookup import DNSLookup
from modules.subdomain_finder import SubdomainFinder
from modules.ip_geolocation import IPGeolocation
from modules.http_headers import HTTPHeaders
from modules.port_scanner import PortScanner
from modules.reverse_dns import ReverseDNS
from modules.tech_detection import TechDetection
from modules.robots_checker import RobotsChecker
from modules.security_headers import SecurityHeaders

# ─── Version Info ─────────────────────────────────────────────
VERSION = "1.0.0"
RELEASE_DATE = "2025"
AUTHOR = "ShadowRecon Project"


def parse_arguments():
    """Parse command-line arguments with full help documentation."""
    parser = argparse.ArgumentParser(
        prog="shadowrecon",
        description="ShadowRecon - Professional OSINT Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Full scan:          python main.py -t example.com --all
  DNS only:           python main.py -t example.com --dns
  Port scan:          python main.py -t example.com --ports --port-range 1-1000
  Subdomain hunt:     python main.py -t example.com --subdomains
  Export results:     python main.py -t example.com --all --output results --format json
  Verbose mode:       python main.py -t example.com --all --verbose
  Multiple modules:   python main.py -t example.com --whois --dns --geo --headers

DISCLAIMER:
  This tool is for EDUCATIONAL and AUTHORIZED testing ONLY.
  Unauthorized scanning is illegal. Always get permission.
        """,
    )

    # ── Target ──────────────────────────────────────────────────
    parser.add_argument(
        "-t", "--target",
        metavar="TARGET",
        help="Target domain or IP address (e.g., example.com or 8.8.8.8)"
    )

    # ── Module Selection ─────────────────────────────────────────
    modules_group = parser.add_argument_group("Scan Modules")
    modules_group.add_argument("--all",         action="store_true", help="Run all reconnaissance modules")
    modules_group.add_argument("--whois",       action="store_true", help="Whois domain/IP lookup")
    modules_group.add_argument("--dns",         action="store_true", help="DNS records lookup (A, MX, NS, TXT, CNAME)")
    modules_group.add_argument("--subdomains",  action="store_true", help="Subdomain enumeration")
    modules_group.add_argument("--geo",         action="store_true", help="IP geolocation lookup")
    modules_group.add_argument("--headers",     action="store_true", help="HTTP response headers analysis")
    modules_group.add_argument("--ports",       action="store_true", help="Port scanner")
    modules_group.add_argument("--rdns",        action="store_true", help="Reverse DNS lookup")
    modules_group.add_argument("--tech",        action="store_true", help="Technology stack detection")
    modules_group.add_argument("--robots",      action="store_true", help="Robots.txt & sitemap checker")
    modules_group.add_argument("--secheaders",  action="store_true", help="Security headers audit")

    # ── Port Scanner Options ──────────────────────────────────────
    port_group = parser.add_argument_group("Port Scanner Options")
    port_group.add_argument(
        "--port-range", metavar="RANGE",
        default="1-1024",
        help="Port range to scan (default: 1-1024, e.g., 1-65535 or 80,443,8080)"
    )
    port_group.add_argument(
        "--threads", type=int, default=100,
        help="Number of threads for port scanning (default: 100)"
    )
    port_group.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )

    # ── Subdomain Options ─────────────────────────────────────────
    sub_group = parser.add_argument_group("Subdomain Options")
    sub_group.add_argument(
        "--wordlist", metavar="FILE",
        help="Custom wordlist for subdomain brute-forcing"
    )
    sub_group.add_argument(
        "--sub-threads", type=int, default=50,
        help="Threads for subdomain enumeration (default: 50)"
    )

    # ── Output Options ────────────────────────────────────────────
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output", "-o", metavar="FILENAME",
        help="Output filename (without extension, saved to output/ directory)"
    )
    output_group.add_argument(
        "--format", choices=["json", "txt", "both"], default="both",
        help="Export format: json, txt, or both (default: both)"
    )
    output_group.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output (useful for piping)"
    )

    # ── Misc Options ──────────────────────────────────────────────
    misc_group = parser.add_argument_group("Misc Options")
    misc_group.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose/debug output"
    )
    misc_group.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress banner and info messages"
    )
    misc_group.add_argument(
        "--version", action="version",
        version=f"ShadowRecon v{VERSION} | Released: {RELEASE_DATE}"
    )
    misc_group.add_argument(
        "--log", metavar="LOGFILE",
        help="Write logs to file (default: logs/shadowrecon.log)"
    )

    return parser.parse_args()


def run_module(name, func, results, verbose=False):
    """
    Execute a single reconnaissance module safely.
    Catches exceptions and stores results or error info.
    
    Args:
        name: Module display name
        func: Callable that returns result dict
        results: Shared results dictionary
        verbose: Enable verbose logging
    """
    logger = get_logger()
    try:
        logger.info(f"Starting module: {name}")
        start = time.time()
        data = func()
        elapsed = round(time.time() - start, 2)
        results[name] = {"status": "success", "data": data, "elapsed": elapsed}
        logger.info(f"Module '{name}' completed in {elapsed}s")
    except KeyboardInterrupt:
        results[name] = {"status": "interrupted", "data": None}
    except Exception as e:
        logger.error(f"Module '{name}' failed: {e}")
        results[name] = {"status": "error", "error": str(e), "data": None}
        if verbose:
            print_error(f"[{name}] {e}")


def display_results(module_name, result_data):
    """
    Pretty-print module results to terminal with cyberpunk formatting.
    
    Args:
        module_name: Name of the module for section header
        result_data: Dict containing status and data fields
    """
    status = result_data.get("status", "unknown")
    elapsed = result_data.get("elapsed", "?")

    print_section(f"{module_name}  [{elapsed}s]")

    if status == "error":
        print_error(f"Module failed: {result_data.get('error', 'Unknown error')}")
        return

    if status == "interrupted":
        print_warning("Module interrupted by user")
        return

    data = result_data.get("data", {})
    if not data:
        print_warning("No data returned")
        return

    # Recursively display nested results
    _render_data(data)


def _render_data(data, indent=0):
    """Recursively render result data with indentation."""
    pad = "  " * indent
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                print_result(f"{pad}{key}:")
                _render_data(value, indent + 1)
            else:
                print_result(f"{pad}{key}: {value}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _render_data(item, indent)
            else:
                print_result(f"{pad}• {item}")
    else:
        print_result(f"{pad}{data}")


def build_module_queue(args, target):
    """
    Build the list of (name, callable) tuples based on CLI flags.
    
    Args:
        args: Parsed argparse namespace
        target: Validated target string
        
    Returns:
        List of (module_name, callable) tuples
    """
    queue = []

    # Instantiate modules
    whois   = WhoisLookup(target)
    dns     = DNSLookup(target)
    subs    = SubdomainFinder(target, wordlist=args.wordlist, threads=args.sub_threads)
    geo     = IPGeolocation(target)
    http    = HTTPHeaders(target)
    ports   = PortScanner(target, port_range=args.port_range, threads=args.threads, timeout=args.timeout)
    rdns    = ReverseDNS(target)
    tech    = TechDetection(target)
    robots  = RobotsChecker(target)
    sechdr  = SecurityHeaders(target)

    module_map = {
        "whois":      ("Whois Lookup",          whois.run),
        "dns":        ("DNS Records",            dns.run),
        "subdomains": ("Subdomain Finder",       subs.run),
        "geo":        ("IP Geolocation",         geo.run),
        "headers":    ("HTTP Headers",           http.run),
        "ports":      ("Port Scanner",           ports.run),
        "rdns":       ("Reverse DNS",            rdns.run),
        "tech":       ("Technology Detection",   tech.run),
        "robots":     ("Robots.txt Checker",     robots.run),
        "secheaders": ("Security Headers Audit", sechdr.run),
    }

    if args.all:
        queue = [(display_name, func) for _, (display_name, func) in module_map.items()]
    else:
        for flag, (display_name, func) in module_map.items():
            if getattr(args, flag, False):
                queue.append((display_name, func))

    return queue


def main():
    """Main entry point — orchestrates all scanning operations."""
    args = parse_arguments()

    # ── Setup logging ──────────────────────────────────────────
    log_file = args.log or os.path.join(
        os.path.dirname(__file__), "logs", "shadowrecon.log"
    )
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    setup_logger(log_file, verbose=args.verbose)
    logger = get_logger()

    # ── Banner ─────────────────────────────────────────────────
    if not args.quiet:
        print_banner(VERSION)

    # ── Validate target ────────────────────────────────────────
    if not args.target:
        print_error("No target specified. Use -t <target> or --help for usage.")
        sys.exit(1)

    target = sanitize_target(args.target)
    if not validate_target(target):
        print_error(f"Invalid target: '{target}'. Provide a valid domain or IP.")
        sys.exit(1)

    print_info(f"Target     : {target}")
    print_info(f"Start Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Version    : ShadowRecon v{VERSION}")
    print("")

    # ── Build module queue ─────────────────────────────────────
    queue = build_module_queue(args, target)

    if not queue:
        print_warning("No modules selected. Use --all or specify individual modules.")
        print_info("Run 'python main.py --help' for usage information.")
        sys.exit(0)

    print_info(f"Modules    : {len(queue)} selected")
    print_info(f"Threads    : {args.threads} (port scan) / {args.sub_threads} (subdomains)")
    print("")

    # ── Execute modules ────────────────────────────────────────
    results = {}
    scan_start = time.time()

    # Run modules sequentially for clean output (each module uses internal threading)
    for module_name, module_func in queue:
        run_module(module_name, module_func, results, verbose=args.verbose)
        display_results(module_name, results[module_name])

    # ── Summary ────────────────────────────────────────────────
    total_elapsed = round(time.time() - scan_start, 2)
    success_count = sum(1 for r in results.values() if r["status"] == "success")
    error_count   = sum(1 for r in results.values() if r["status"] == "error")

    print("")
    print_section("Scan Summary")
    print_success(f"Completed  : {success_count}/{len(queue)} modules")
    if error_count:
        print_warning(f"Errors     : {error_count} module(s) failed")
    print_info(f"Total Time : {total_elapsed}s")
    print_info(f"Scan End   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Export results ─────────────────────────────────────────
    if args.output:
        output_dir = os.path.join(os.path.dirname(__file__), "output")
        os.makedirs(output_dir, exist_ok=True)
        export_path = os.path.join(output_dir, args.output)
        export_results(
            results=results,
            target=target,
            filepath=export_path,
            fmt=args.format,
            version=VERSION
        )

    logger.info(f"Scan completed for {target} in {total_elapsed}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")
        print_warning("Scan interrupted by user. Exiting...")
        sys.exit(0)

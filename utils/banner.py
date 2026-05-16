#!/usr/bin/env python3
"""
utils/banner.py
───────────────
Terminal output styling, colors, and ASCII banner system.
Provides cyberpunk-themed CLI aesthetics with ANSI color support.
Automatically detects Termux/Linux and adjusts accordingly.
"""

import sys
import os
import shutil
import platform

# ─── ANSI Color Codes ─────────────────────────────────────────────────────────

class Colors:
    """ANSI escape sequences for terminal colors and styles."""
    # Reset
    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"
    ITALIC      = "\033[3m"
    UNDERLINE   = "\033[4m"
    BLINK       = "\033[5m"

    # Foreground Colors
    BLACK       = "\033[30m"
    RED         = "\033[31m"
    GREEN       = "\033[32m"
    YELLOW      = "\033[33m"
    BLUE        = "\033[34m"
    MAGENTA     = "\033[35m"
    CYAN        = "\033[36m"
    WHITE       = "\033[37m"

    # Bright Foreground
    BRIGHT_RED      = "\033[91m"
    BRIGHT_GREEN    = "\033[92m"
    BRIGHT_YELLOW   = "\033[93m"
    BRIGHT_BLUE     = "\033[94m"
    BRIGHT_MAGENTA  = "\033[95m"
    BRIGHT_CYAN     = "\033[96m"
    BRIGHT_WHITE    = "\033[97m"

    # Background Colors
    BG_BLACK    = "\033[40m"
    BG_RED      = "\033[41m"
    BG_GREEN    = "\033[42m"
    BG_CYAN     = "\033[46m"

    # Cyberpunk Theme Aliases
    ACCENT      = "\033[96m"    # Bright Cyan — primary accent
    HIGHLIGHT   = "\033[95m"    # Bright Magenta — secondary accent
    SUCCESS     = "\033[92m"    # Bright Green
    WARNING     = "\033[93m"    # Bright Yellow
    ERROR       = "\033[91m"    # Bright Red
    INFO        = "\033[94m"    # Bright Blue
    MUTED       = "\033[2m"     # Dim
    SEPARATOR   = "\033[36m"    # Cyan


def _supports_color() -> bool:
    """Detect if the terminal supports ANSI color codes."""
    # Check NO_COLOR env var (standard)
    if os.environ.get("NO_COLOR"):
        return False
    # Check if stdout is a TTY
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    # Check platform
    if platform.system() == "Windows":
        return False
    return True


# Determine color support once at import time
_COLOR_SUPPORTED = _supports_color()


def c(color_code: str, text: str) -> str:
    """
    Apply an ANSI color code to text, with fallback for no-color terminals.
    
    Args:
        color_code: ANSI escape code from Colors class
        text: String to colorize
        
    Returns:
        Colored string if supported, plain text otherwise
    """
    if _COLOR_SUPPORTED:
        return f"{color_code}{text}{Colors.RESET}"
    return text


def _get_terminal_width() -> int:
    """Get terminal width, defaulting to 80 for Termux compatibility."""
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


# ─── ASCII Banner ─────────────────────────────────────────────────────────────

BANNER = r"""
 ██████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
╚█████╗ ███████║███████║██║  ██║██║   ██║██║ █╗ ██║
 ╚═══██╗██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
██████╔╝██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝"""

BANNER_COMPACT = r"""
 ____  _               _               ____
/ ___|| |__   __ _  __| | _____      _|  _ \ ___  ___ ___  _ __
\___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_) / _ \/ __/ _ \| '_ \
 ___) | | | | (_| | (_| | (_) \ V  V /|  _ <  __/ (_| (_) | | | |
|____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| \_\___|\___\___/|_| |_|"""


def print_banner(version: str = "1.0.0"):
    """
    Print the ShadowRecon ASCII banner with version and meta info.
    Auto-selects full or compact banner based on terminal width.
    
    Args:
        version: Tool version string
    """
    width = _get_terminal_width()
    sep = c(Colors.SEPARATOR, "═" * min(width, 70))

    # Choose banner based on terminal width
    banner_text = BANNER if width >= 70 else BANNER_COMPACT

    print(sep)
    # Print banner lines with gradient effect
    lines = banner_text.strip("\n").split("\n")
    for i, line in enumerate(lines):
        if i < len(lines) // 2:
            print(c(Colors.ACCENT, line))
        else:
            print(c(Colors.HIGHLIGHT, line))

    print("")
    print(c(Colors.BRIGHT_CYAN,    "  ┌─ OSINT Reconnaissance Toolkit"))
    print(c(Colors.BRIGHT_MAGENTA, f"  ├─ Version  : v{version}"))
    print(c(Colors.BRIGHT_BLUE,    "  ├─ Platform : Linux / Kali / Ubuntu / Termux"))
    print(c(Colors.BRIGHT_GREEN,   "  ├─ Purpose  : Ethical Security Research & Bug Bounty"))
    print(c(Colors.WARNING,        "  └─ ⚠ For authorized use and education ONLY"))
    print("")
    print(sep)
    print("")


# ─── Section / Output Helpers ─────────────────────────────────────────────────

def print_section(title: str):
    """Print a styled section header."""
    width = _get_terminal_width()
    bar   = "─" * min(width - 4, 66)
    print("")
    print(c(Colors.ACCENT, f"┌─[ ") + c(Colors.BOLD + Colors.BRIGHT_WHITE, title) + c(Colors.ACCENT, " ]"))
    print(c(Colors.SEPARATOR, f"│{bar}"))


def print_result(text: str):
    """Print a data result line."""
    print(c(Colors.SEPARATOR, "│ ") + c(Colors.BRIGHT_WHITE, str(text)))


def print_success(text: str):
    """Print a success message."""
    print(c(Colors.SUCCESS, "  [✓] ") + c(Colors.BRIGHT_WHITE, str(text)))


def print_error(text: str):
    """Print an error message."""
    print(c(Colors.ERROR, "  [✗] ") + c(Colors.BRIGHT_WHITE, str(text)), file=sys.stderr)


def print_warning(text: str):
    """Print a warning message."""
    print(c(Colors.WARNING, "  [!] ") + c(Colors.BRIGHT_WHITE, str(text)))


def print_info(text: str):
    """Print an informational message."""
    print(c(Colors.INFO, "  [»] ") + c(Colors.BRIGHT_WHITE, str(text)))


def print_debug(text: str):
    """Print a debug message (only when verbose)."""
    print(c(Colors.MUTED, f"  [~] {text}"))


def print_open_port(port: int, service: str, banner: str = ""):
    """Print an open port with highlight styling."""
    port_str  = c(Colors.SUCCESS, f"{port:>5}")
    svc_str   = c(Colors.ACCENT,  f"{service:<15}")
    banner_str = c(Colors.MUTED, banner[:50]) if banner else ""
    print(c(Colors.SEPARATOR, "│ ") + f"{port_str}  {svc_str}  {banner_str}")


def print_subdomain(subdomain: str, ip: str = ""):
    """Print a discovered subdomain."""
    sub_str = c(Colors.SUCCESS, subdomain)
    ip_str  = c(Colors.MUTED, f"  →  {ip}") if ip else ""
    print(c(Colors.SEPARATOR, "│ ") + f"  {sub_str}{ip_str}")


def print_kv(key: str, value: str, highlight: bool = False):
    """Print a key-value pair with optional value highlighting."""
    key_str = c(Colors.ACCENT, f"{key:<25}")
    val_color = Colors.BRIGHT_GREEN if highlight else Colors.BRIGHT_WHITE
    val_str = c(val_color, str(value))
    print(c(Colors.SEPARATOR, "│ ") + f"  {key_str} {val_str}")


def print_header_check(header: str, present: bool, value: str = ""):
    """Print a security header check result."""
    icon  = c(Colors.SUCCESS, "✓") if present else c(Colors.ERROR, "✗")
    color = Colors.BRIGHT_GREEN if present else Colors.BRIGHT_RED
    hdr   = c(color, f"{header:<35}")
    val   = c(Colors.MUTED, value[:40]) if value else ""
    print(c(Colors.SEPARATOR, "│ ") + f"  {icon}  {hdr} {val}")


def print_dns_record(record_type: str, value: str):
    """Print a DNS record entry."""
    type_str = c(Colors.HIGHLIGHT, f"{record_type:<8}")
    val_str  = c(Colors.BRIGHT_WHITE, value)
    print(c(Colors.SEPARATOR, "│ ") + f"  {type_str} {val_str}")


def progress_bar(current: int, total: int, width: int = 40, label: str = "") -> str:
    """
    Generate an ASCII progress bar string.
    
    Args:
        current: Current progress value
        total: Total maximum value
        width: Width of the progress bar in characters
        label: Optional label suffix
        
    Returns:
        Formatted progress bar string
    """
    if total == 0:
        pct = 100
    else:
        pct = int((current / total) * 100)

    filled = int(width * current / max(total, 1))
    bar    = "█" * filled + "░" * (width - filled)
    bar_colored = c(Colors.ACCENT, bar)
    pct_str = c(Colors.BRIGHT_WHITE, f"{pct:>3}%")

    return f"\r  {bar_colored} {pct_str}  {c(Colors.MUTED, label)}"


def spinner_chars() -> list:
    """Return spinner animation characters."""
    return ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

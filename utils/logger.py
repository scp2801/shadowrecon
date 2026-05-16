#!/usr/bin/env python3
"""
utils/logger.py
───────────────
Centralized logging setup for ShadowRecon.
Writes to both file and optionally stderr in verbose mode.
"""

import logging
import os
from datetime import datetime

_logger = None


def setup_logger(log_file: str, verbose: bool = False) -> logging.Logger:
    """
    Initialize and configure the global ShadowRecon logger.
    
    Args:
        log_file: Path to the log file
        verbose: If True, also output DEBUG level to stderr
        
    Returns:
        Configured Logger instance
    """
    global _logger

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger("shadowrecon")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # File handler — always write DEBUG+
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    # Console handler — only in verbose mode
    if verbose:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter("  [DEBUG] %(message)s"))
        logger.addHandler(ch)

    # Write session header to log file
    logger.info("=" * 60)
    logger.info(f"ShadowRecon Session Started: {datetime.now().isoformat()}")
    logger.info("=" * 60)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """
    Retrieve the global logger. Creates a null logger if not initialized.
    
    Returns:
        Logger instance
    """
    global _logger
    if _logger is None:
        # Fallback no-op logger if setup_logger wasn't called
        _logger = logging.getLogger("shadowrecon")
        _logger.addHandler(logging.NullHandler())
    return _logger

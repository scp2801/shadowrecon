#!/usr/bin/env python3
"""
utils/exporter.py
─────────────────
Export scan results to JSON and/or TXT files.
Handles nested result structures and pretty formatting.
"""

import json
import os
from datetime import datetime
from utils.banner import print_success, print_error, print_info


def export_results(results: dict, target: str, filepath: str, fmt: str = "both", version: str = "1.0.0"):
    """
    Export scan results to JSON and/or TXT format.
    
    Args:
        results: Dictionary of module_name -> result data
        target: Scanned target string
        filepath: Output file path without extension
        fmt: 'json', 'txt', or 'both'
        version: ShadowRecon version string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build metadata wrapper
    export_data = {
        "meta": {
            "tool":      "ShadowRecon",
            "version":   version,
            "target":    target,
            "timestamp": timestamp,
        },
        "results": {}
    }

    # Clean results for JSON serialization
    for module, result in results.items():
        export_data["results"][module] = {
            "status":  result.get("status", "unknown"),
            "elapsed": result.get("elapsed", 0),
            "data":    result.get("data", {}),
            "error":   result.get("error", None),
        }

    if fmt in ("json", "both"):
        _export_json(export_data, filepath)

    if fmt in ("txt", "both"):
        _export_txt(export_data, filepath)


def _export_json(data: dict, filepath: str):
    """Write results as formatted JSON."""
    json_path = f"{filepath}.json"
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str, ensure_ascii=False)
        print_success(f"JSON report saved: {json_path}")
    except IOError as e:
        print_error(f"Failed to write JSON: {e}")


def _export_txt(data: dict, filepath: str):
    """Write results as human-readable plain text."""
    txt_path = f"{filepath}.txt"
    try:
        with open(txt_path, "w", encoding="utf-8") as f:
            # Header
            f.write("=" * 70 + "\n")
            f.write("  SHADOWRECON — OSINT Reconnaissance Report\n")
            f.write("=" * 70 + "\n")
            meta = data.get("meta", {})
            f.write(f"  Tool      : {meta.get('tool')} v{meta.get('version')}\n")
            f.write(f"  Target    : {meta.get('target')}\n")
            f.write(f"  Timestamp : {meta.get('timestamp')}\n")
            f.write(f"  Disclaimer: For authorized, educational use only\n")
            f.write("=" * 70 + "\n\n")

            # Results
            for module_name, result in data.get("results", {}).items():
                f.write(f"{'─' * 70}\n")
                f.write(f"  MODULE: {module_name.upper()}\n")
                f.write(f"  Status : {result.get('status', 'unknown')}\n")
                f.write(f"  Elapsed: {result.get('elapsed', '?')}s\n")
                f.write(f"{'─' * 70}\n")

                if result.get("error"):
                    f.write(f"  ERROR: {result['error']}\n\n")
                    continue

                _write_dict_to_txt(f, result.get("data", {}))
                f.write("\n")

            # Footer
            f.write("=" * 70 + "\n")
            f.write("  END OF REPORT — ShadowRecon\n")
            f.write("=" * 70 + "\n")

        print_success(f"TXT  report saved: {txt_path}")
    except IOError as e:
        print_error(f"Failed to write TXT: {e}")


def _write_dict_to_txt(f, data, indent=0):
    """Recursively write a dict/list structure to a text file."""
    pad = "  " * (indent + 1)
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                f.write(f"{pad}{key}:\n")
                _write_dict_to_txt(f, value, indent + 1)
            else:
                f.write(f"{pad}{key}: {value}\n")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _write_dict_to_txt(f, item, indent)
            else:
                f.write(f"{pad}• {item}\n")
    else:
        f.write(f"{pad}{data}\n")

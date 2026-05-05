#!/usr/bin/env python3
"""
Demo script for pipguard MCP integration with Claude Code.

This demonstrates how pipguard integrates with Claude Code via the Model Context Protocol (MCP)
to automatically analyze package security before installation.

Run: python demo_mcp_integration.py
"""

import asyncio
import json
import sys
from datetime import datetime
from pipguard.mcp_server import call_tool


# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(title):
    """Print a formatted header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 90}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title.center(90)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 90}{Colors.ENDC}\n")


def print_section(title):
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}[>] {title}{Colors.ENDC}")
    print(f"{Colors.BLUE}{'-' * 85}{Colors.ENDC}")


def print_package_result(data):
    """Pretty print package analysis result."""
    status = data.get("status")

    if status == "not_found":
        print(f"  {Colors.YELLOW}[!] Package not found on PyPI{Colors.ENDC}")
        print(f"     {data.get('message')}")
        return

    if status == "error":
        print(f"  {Colors.RED}[X] Error: {data.get('message')}{Colors.ENDC}")
        return

    # Success case
    package = data.get("package")
    version = data.get("version")
    score = data.get("score")
    verdict = data.get("verdict")
    signals = data.get("signals", {})
    cves = data.get("cves", [])
    should_install = data.get("should_install")

    # Color verdict
    if verdict == "LOW":
        verdict_color = Colors.GREEN
        verdict_symbol = "[OK]"
    elif verdict == "MEDIUM":
        verdict_color = Colors.YELLOW
        verdict_symbol = "[!]"
    else:
        verdict_color = Colors.RED
        verdict_symbol = "[X]"

    print(f"  Package:  {Colors.BOLD}{package}{Colors.ENDC} v{version}")
    print(
        f"  Verdict:  {verdict_color}{verdict_symbol} {verdict} RISK{Colors.ENDC} (Score: {score})"
    )
    print(f"  Install:  {Colors.GREEN if should_install else Colors.RED}{'[OK] Yes' if should_install else '[X] No'}{Colors.ENDC}")

    if signals:
        print(f"  Signals:  {len(signals)} detected")
        for signal, weight in signals.items():
            print(f"    - {signal} ({weight})")

    if cves:
        print(f"  {Colors.RED}CVEs: {len(cves)} vulnerabilities{Colors.ENDC}")
        for cve in cves:
            print(f"    - {cve}")


async def demo(approve_high_risk=False):
    """Run the demo."""
    print_header("Package Security Analysis")

    # Checking requests
    print_section("Checking: requests")
    result = await call_tool("analyze_package", {"package_name": "requests"})
    data = json.loads(result.text)
    print_package_result(data)
    if data.get("should_install"):
        print(f"  >> {Colors.GREEN}Safe to install{Colors.ENDC}\n")

    # Checking urllib3
    print_section("Checking: urllib3")
    result = await call_tool("analyze_package", {"package_name": "urllib3"})
    data = json.loads(result.text)
    print_package_result(data)
    if data.get("should_install"):
        print(f"  >> {Colors.GREEN}Safe to install{Colors.ENDC}\n")

    # Checking a HIGH risk package
    print_section("Checking: scrapy")
    result = await call_tool("analyze_package", {"package_name": "scrapy"})
    data = json.loads(result.text)
    print_package_result(data)
    if not data.get("should_install") and data.get("status") == "success":
        print(f"  {Colors.RED}[!] HIGH/CRITICAL package detected{Colors.ENDC}")
        print(f"  User confirmation required before installation.\n")

        if approve_high_risk:
            print(f"  {Colors.YELLOW}>>> Install scrapy? (y/n): {Colors.GREEN}y{Colors.ENDC}")
            print(f"  {Colors.YELLOW}Installing scrapy (user approved HIGH RISK package)...{Colors.ENDC}\n")
        else:
            print(f"  {Colors.YELLOW}>>> Install scrapy? (y/n): {Colors.RED}n{Colors.ENDC}")
            print(f"\n  {Colors.RED}[X] Installation blocked by user{Colors.ENDC}")
            print_header("Task Complete - Agentic Flow Ended")
            return
    elif data.get("should_install"):
        print(f"  >> {Colors.GREEN}Safe to install{Colors.ENDC}\n")

    # Checking numpy
    print_section("Checking: numpy")
    result = await call_tool("analyze_package", {"package_name": "numpy"})
    data = json.loads(result.text)
    print_package_result(data)
    if data.get("should_install"):
        print(f"  >> {Colors.GREEN}Safe to install{Colors.ENDC}\n")

    print("\n")
    print("Results:")
    print("  [OK] requests v2.33.1 — LOW RISK")
    print("  [OK] urllib3 v2.6.3 — LOW RISK (2 signals)")
    print("  [OK] numpy v2.4.4 — LOW RISK (2 signals)")


if __name__ == "__main__":
    approve_high_risk = "--approve" in sys.argv
    try:
        asyncio.run(demo(approve_high_risk=approve_high_risk))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.ENDC}")
        sys.exit(1)

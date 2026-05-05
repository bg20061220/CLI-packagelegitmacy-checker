"""MCP server for pipguard — Claude Code integration."""
import asyncio
import json
import sys
from datetime import datetime
from mcp.server import Server
from mcp.types import Tool, TextContent

from pipguard.main import _analyze


def log(msg: str):
    """Log to stderr so it's visible in Claude Code's output."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[pipguard MCP {timestamp}] {msg}", file=sys.stderr, flush=True)


server = Server("pipguard")


@server.list_tools()
async def list_tools():
    """List available tools."""
    log("📋 Tool list requested by Claude Code")
    return [
        Tool(
            name="analyze_package",
            description="Analyzes a PyPI package for security risks. Returns score, verdict, signals, and CVE information.",
            inputSchema={
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Name of the PyPI package to analyze"
                    }
                },
                "required": ["package_name"]
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Execute a tool."""
    if name != "analyze_package":
        raise ValueError(f"Unknown tool: {name}")

    package_name = arguments.get("package_name")
    if not package_name:
        log("❌ analyze_package called with missing package_name")
        return TextContent(
            type="text",
            text=json.dumps({"status": "error", "message": "package_name is required"})
        )

    log(f"🔍 Analyzing package: {package_name}")

    try:
        result, cached = await _analyze(package_name, None, False)

        if result is None:
            log(f"⚠️  Package not found on PyPI: {package_name}")
            return TextContent(
                type="text",
                text=json.dumps({
                    "status": "not_found",
                    "package": package_name,
                    "message": f"Package '{package_name}' not found on PyPI"
                })
            )

        breakdown = result["breakdown"]
        vulns = result.get("vulns", [])

        verdict = breakdown["verdict"]
        score = breakdown["score"]
        signal_count = len(breakdown.get("signals", []))
        cve_count = len(vulns)

        msg_parts = [f"{verdict} RISK (score: {score})"]
        if cve_count > 0:
            msg_parts.append(f"{cve_count} CVE(s)")
        if signal_count > 0:
            msg_parts.append(f"{signal_count} signal(s)")

        emoji = "✅" if verdict in ("LOW", "MEDIUM") else "🚫"
        log(f"{emoji} {package_name}: {verdict} RISK (score: {score}) • {' • '.join(msg_parts)}")

        return TextContent(
            type="text",
            text=json.dumps({
                "status": "success",
                "package": package_name,
                "version": result["metadata"]["version"],
                "score": breakdown["score"],
                "verdict": breakdown["verdict"],
                "signals": breakdown.get("signals", []),
                "cves": [v.get("id") for v in vulns] if vulns else [],
                "should_install": verdict in ("LOW", "MEDIUM"),
                "message": " • ".join(msg_parts),
                "cached": cached
            })
        )
    except Exception as e:
        log(f"❌ Analysis failed for {package_name}: {str(e)}")
        return TextContent(
            type="text",
            text=json.dumps({
                "status": "error",
                "package": package_name,
                "message": f"Analysis failed: {str(e)}"
            })
        )


if __name__ == "__main__":
    server.run()

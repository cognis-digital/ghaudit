"""GHAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from ghaudit.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ghaudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-ghaudit[mcp]'")
        return 1
    app = FastMCP("ghaudit")

    @app.tool()
    def ghaudit_scan(target: str) -> str:
        """Audit a GitHub org's security posture (branch rules, 2FA, secrets) from an export. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

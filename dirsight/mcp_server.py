"""DIRSIGHT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from dirsight.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-dirsight[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-dirsight[mcp]'")
        return 1
    app = FastMCP("dirsight")

    @app.tool()
    def dirsight_scan(target: str) -> str:
        """Analyze web content-discovery output (ffuf/gobuster) into ranked endpoints. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

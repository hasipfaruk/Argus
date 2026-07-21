"""Model Context Protocol (MCP) server for Argus.

Exposes Argus as a tool that AI coding agents can call, so a scan runs
automatically after code is generated. See :mod:`argus.mcp.server`.
"""

from argus.mcp.server import handle_request, run_stdio

__all__ = ["handle_request", "run_stdio"]

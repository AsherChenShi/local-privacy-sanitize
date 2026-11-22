"""Synthetic structured results and a local stdio MCP server for native smoke tests."""

import json
from pathlib import Path
import sys


MCP_SERVER = "privacy-fixture"
MCP_TOOL = f"mcp__{MCP_SERVER}__sample"
OPAQUE_CREDENTIAL = "SYNTHETIC_INTEGRATION_CREDENTIAL"
CREDENTIAL_RESULT = {"credentials": {"access_token": OPAQUE_CREDENTIAL}}
METRIC_RESULT = {"token_count": 1234, "elapsed_ms": 250, "status": "SYNTHETIC_METRIC_OK"}


def mcp_tool_result(fixture, structured):
    text = fixture.read_text(encoding="utf-8")
    if structured:
        return {
            "content": [{"type": "text", "text": "Synthetic structured fixture"}],
            "structuredContent": json.loads(text),
        }
    return {"content": [{"type": "text", "text": text}]}


def run_mcp_stub(fixture, structured):
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            result = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": MCP_SERVER, "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": [{
                "name": "sample", "description": "Return a synthetic privacy fixture",
                "inputSchema": {"type": "object", "properties": {}},
            }]}
        elif method == "tools/call":
            result = mcp_tool_result(fixture, structured)
        else:
            result = {}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    run_mcp_stub(Path(sys.argv[1]), sys.argv[2] == "structured")

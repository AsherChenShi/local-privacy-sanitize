"""Protocol tests for the metadata-only signup MCP adapter."""

import io
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from signup_mcp import dispatch, serve


OPAQUE_ID = "abcdefghijklmnop" * 2
SECRET = "mcp-negative-control@example.invalid"


def call_request(name, arguments):
    return {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


def result(message):
    return json.loads(message["result"]["content"][0]["text"])


class SignupMcpTests(unittest.TestCase):
    def test_opaque_id_only_and_fixed_status(self):
        seen = []

        def broker(event):
            seen.append(event)
            if event["action"] == "prepare":
                return {"status": "pending", "request_id": OPAQUE_ID, "origin": SECRET, "message": SECRET}
            return {"status": "submitted", "email": SECRET, "page": SECRET}

        prepared = dispatch(call_request("prepare", {"url": "site_a"}), broker)
        completed = dispatch(call_request("execute", {"request_id": OPAQUE_ID}), broker)
        self.assertEqual(seen, [{"action": "prepare", "url": "site_a"},
                                {"action": "execute", "request_id": OPAQUE_ID}])
        self.assertEqual(result(prepared), {"status": "pending", "request_id": OPAQUE_ID})
        self.assertEqual(result(completed), {"status": "submitted"})
        self.assertNotIn(SECRET, json.dumps([prepared, completed]))

    def test_emails_in_model_tool_arguments_or_ids_never_echo_or_reach_broker(self):
        def broker(_event):
            self.fail("Invalid tool arguments reached the broker")

        for request in (
            call_request("prepare", {"url": f"https://127.0.0.1:9000/signup?email={SECRET}"}),
            call_request("prepare", {"url": "site_a", "email": SECRET}),
            call_request("execute", {"request_id": SECRET}),
            call_request("approve", {"request_id": OPAQUE_ID, "email": SECRET}),
        ):
            with self.subTest(tool=request["params"]["name"]):
                response = dispatch(request, broker)
                self.assertEqual(result(response), {"status": "denied"})
                self.assertNotIn(SECRET, json.dumps(response))
        response = dispatch({**call_request("prepare", {"url": "site_a"}), "id": SECRET}, broker)
        self.assertIsNone(response["id"])
        self.assertNotIn(SECRET, json.dumps(response))

    def test_unexpected_status_or_request_id_is_a_fixed_error(self):
        for reply in ({"status": SECRET}, {"status": "pending", "request_id": SECRET}):
            response = dispatch(call_request("prepare", {"url": "site_a"}), lambda _event: reply)
            self.assertEqual(result(response), {"status": "unavailable"})
            self.assertNotIn(SECRET, json.dumps(response))

    def test_stdio_lists_only_two_tools_and_discards_invalid_frames(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        raw = b"".join(json.dumps(item).encode() + b"\n" for item in requests)
        stdout = io.BytesIO()
        serve(io.BytesIO(raw + b"{" + SECRET.encode() + b"\n"), stdout, lambda _: self.fail())
        initialize, listing, invalid = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(initialize["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual({tool["name"] for tool in listing["result"]["tools"]}, {"prepare", "execute"})
        self.assertEqual(invalid["error"]["code"], -32700)
        self.assertNotIn(SECRET.encode(), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()

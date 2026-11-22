"""The human approval interface is absent from the MCP-facing transport."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
from threading import Thread
import unittest
from unittest.mock import Mock, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from signup_local import SignupAgentServer, local_console, parse_sites
finally:
    sys.path.pop(0)


ORIGIN = "https://127.0.0.1:9443"
PAGE = ORIGIN + "/signup"
REQUEST = "a" * 32
EMAIL = "local-approval-canary@example.invalid"


class ContractTests(unittest.TestCase):
    def test_console_confirmation_names_target_before_hidden_local_input(self):
        broker = Mock()
        scope = {"request_id": REQUEST, "origin": ORIGIN, "path": "/signup", "action": "/register",
                 "field": "email", "status": "pending"}
        broker.pending.return_value = [scope]
        broker.describe.return_value = scope
        broker.approve.return_value = {"status": "approved"}
        output = io.StringIO()
        with patch("builtins.input", side_effect=[REQUEST, "SUBMIT", "q"]), \
                patch("signup_local.getpass", return_value=EMAIL), redirect_stdout(output):
            local_console(broker)
        broker.approve.assert_called_once_with(REQUEST, EMAIL, submit=True)
        self.assertIn(ORIGIN, output.getvalue())
        self.assertIn("/register", output.getvalue())
        self.assertNotIn(EMAIL, output.getvalue())

    def test_aliases_cannot_enable_nonlocal_sites_or_elsewhere(self):
        self.assertEqual(parse_sites(["site_a=" + PAGE]), ({"site_a": PAGE}, {ORIGIN}))
        for spec in ("site_a=http://127.0.0.1:9443/signup", "site_a=https://example.com/signup",
                     "site_a=https://127.0.0.1:9443/signup?email=test", "site_a=https://127.0.0.1/signup"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                parse_sites([spec])

    def test_agent_socket_cannot_approve_and_requires_exact_request_shape(self):
        broker = Mock()
        broker.prepare.return_value = {"request_id": REQUEST, "status": "pending"}
        broker.execute.return_value = {"status": "denied"}
        with tempfile.TemporaryDirectory(prefix="signup-socket-test-", dir="/tmp") as folder:
            path = Path(folder) / "agent.sock"
            with SignupAgentServer(path, broker, sites={"site_a": PAGE}) as server:
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()

                def rpc(request):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(4)
                        client.connect(str(path))
                        client.sendall(json.dumps(request).encode("utf-8") + b"\n")
                        with client.makefile("rb") as stream:
                            return json.loads(stream.readline())

                try:
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(rpc({"action": "prepare", "url": "site_a"})["status"], "pending")
                    self.assertEqual(rpc({"action": "prepare", "url": PAGE})["status"], "denied")
                    self.assertEqual(rpc({"action": "approve", "request_id": REQUEST, "email": EMAIL})["status"], "denied")
                    self.assertEqual(rpc({"action": "execute", "request_id": REQUEST, "url": PAGE})["status"], "denied")
                    self.assertEqual(rpc({"action": "execute", "request_id": REQUEST})["status"], "denied")
                    broker.prepare.assert_called_once_with(PAGE)
                    broker.execute.assert_called_once_with(REQUEST)
                    broker.approve.assert_not_called()
                finally:
                    server.shutdown()
                    thread.join()
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()

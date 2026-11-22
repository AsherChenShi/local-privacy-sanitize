"""Two local HTTPS origins and disposable certificates for synthetic acceptance."""

from contextlib import contextmanager, ExitStack
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import subprocess
import tempfile
from threading import Thread
from urllib.parse import parse_qs


CERTIFICATE_CONFIG = """[req]
prompt = no
distinguished_name = dn
x509_extensions = server
[dn]
CN = Synthetic Signup Test
[server]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1
"""


def signup_form(action="/register"):
    return ("<!doctype html><html><head><title>Test registration</title></head><body>"
            '<form method="post" action="' + escape(action, quote=True) + '">'
            '<label for="email">Email</label><input id="email" type="email" name="email">'
            '<button type="submit">Register</button></form></body></html>')


class SignupSiteHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_body(self, status, body=b"", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self.server.requests.append(("GET", self.path))
        if self.path == "/redirect-form":
            self.send_body(302, headers=(("Location", self.server.other_origin + "/signup"),))
            return
        html = self.server.forms.get(self.path)
        if html is None:
            self.send_body(404)
            return
        self.send_body(200, html.encode("utf-8"))

    def do_POST(self):
        self.server.requests.append(("POST", self.path))
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 4096:
            self.send_body(400)
            return
        fields = parse_qs(self.rfile.read(size).decode("ascii"), strict_parsing=True, max_num_fields=4)
        if set(fields) != {"email"} or len(fields["email"]) != 1:
            self.send_body(400)
            return
        email = fields["email"][0]
        self.server.emails.append(email)
        if self.path == "/register":
            self.send_body(204)
        elif self.path == "/echo-register":
            self.send_body(200, ("Test address: " + email).encode())
        elif self.path == "/redirect-register":
            self.send_body(307, headers=(("Location", self.server.other_origin + "/register"),))
        else:
            self.send_body(404)


@contextmanager
def signup_sites():
    with tempfile.TemporaryDirectory(prefix="signup-sites-") as directory, ExitStack() as stack:
        root = Path(directory)
        key = root / "key.pem"
        cert = root / "test-ca.pem"
        config = root / "openssl.cnf"
        config.write_text(CERTIFICATE_CONFIG, encoding="utf-8")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-config", str(config)],
                       check=True, capture_output=True, timeout=20)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert), str(key))
        sites = []
        for _ in range(2):
            site = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), SignupSiteHandler))
            site.socket = tls.wrap_socket(site.socket, server_side=True)
            site.origin = f"https://127.0.0.1:{site.server_port}"
            site.form_url = site.origin + "/signup"
            site.forms = {"/signup": signup_form(), "/echo": signup_form("/echo-register"),
                          "/redirect-submit": signup_form("/redirect-register")}
            site.requests, site.emails = [], []
            sites.append(site)
        for site, other in (sites, list(reversed(sites))):
            site.other_origin = other.origin
            site.forms["/cross-form"] = signup_form(other.origin + "/register")
            thread = Thread(target=site.serve_forever, daemon=True)
            thread.start()
            stack.callback(thread.join)
            stack.callback(site.shutdown)
        yield [site.origin for site in sites], cert, *sites


if __name__ == "__main__":
    with signup_sites() as (_, ca, site_a, site_b):
        print(f"site_a={site_a.form_url}\nsite_b={site_b.form_url}\nTest CA {ca}", flush=True)
        try:
            input("Press Enter to stop the two local test sites.\n")
        except (EOFError, KeyboardInterrupt):
            pass

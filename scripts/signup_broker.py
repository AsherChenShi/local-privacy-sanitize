"""Local, synthetic-only broker for one-shot email form approval."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from html.parser import HTMLParser
from http.client import HTTPSConnection, HTTPException
import re
import secrets
import ssl
from threading import Lock
import time
from urllib.parse import urlencode


ORIGIN = re.compile(r"https://127\.0\.0\.1:([1-9][0-9]{0,4})")
URL = re.compile(r"(https://127\.0\.0\.1:[1-9][0-9]{0,4})(/[A-Za-z0-9._/-]{0,200})")
PATH = re.compile(r"/[A-Za-z0-9._/-]{0,200}")
REQUEST_ID = re.compile(r"[a-p]{32}")
ID_ALPHABET = str.maketrans("0123456789abcdef", "abcdefghijklmnop")
SYNTHETIC_EMAIL = re.compile(
    r"[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+invalid",
    re.I,
)
LIMIT = 32 * 1024
MAX_PENDING = 32
EMAIL_FIELD = "email"
PARENTS = {
    "html": {None}, "head": {"html"}, "title": {"head"}, "body": {"html"},
    "h1": {None, "body"}, "h2": {None, "body"}, "p": {None, "body", "form"},
    "meta": {"head"}, "form": {None, "body"}, "label": {"form"},
    "input": {"form", "label"}, "button": {"form"},
}


class Refused(ValueError):
    """Uninspectable input. Never use source content as the error."""


def valid_path(path):
    return bool(PATH.fullmatch(path) and "//" not in path and not {".", ".."}.intersection(path.split("/")))


def origin_port(origin):
    match = ORIGIN.fullmatch(origin) if isinstance(origin, str) else None
    if not match or not 1 <= int(match[1]) <= 65535:
        raise Refused("unsupported origin")
    return int(match[1])


class StaticForm(HTMLParser):
    """Recognize a narrow static form. Never execute source HTML or scripts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.action = None
        self.has_email = False
        self.has_button = False

    def handle_decl(self, declaration):
        if declaration.lower() != "doctype html" or self.stack:
            raise Refused("unsupported document type")

    def handle_pi(self, _data):
        raise Refused("unsupported document instruction")

    def unknown_decl(self, _data):
        raise Refused("unsupported declaration")

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if len(fields) != len(attrs):
            raise Refused("ambiguous tag")
        parent = self.stack[-1] if self.stack else None
        if parent not in PARENTS.get(tag, ()):
            raise Refused("unsupported markup")
        if tag == "form":
            action = fields.get("action")
            if (self.action is not None or set(fields) - {"action", "method", "enctype"}
                    or (fields.get("method") or "").lower() != "post"
                    or fields.get("enctype", "application/x-www-form-urlencoded") != "application/x-www-form-urlencoded"
                    or not isinstance(action, str) or not valid_path(action)):
                raise Refused("unsupported form")
            self.action = action
        elif tag == "input":
            if (self.has_email or set(fields) - {"type", "name", "id", "autocomplete", "required"}
                    or fields.get("type") != "email" or fields.get("name") != EMAIL_FIELD
                    or fields.get("id", EMAIL_FIELD) != EMAIL_FIELD
                    or fields.get("autocomplete", "email") != "email"):
                raise Refused("unsupported field")
            self.has_email = True
            return
        elif tag == "meta":
            if set(fields) != {"charset"} or (fields["charset"] or "").lower() != "utf-8":
                raise Refused("unsupported metadata")
            return
        elif tag == "button":
            if self.has_button or fields not in ({}, {"type": "submit"}):
                raise Refused("unsupported submitter")
            self.has_button = True
        elif tag == "label":
            if fields not in ({}, {"for": EMAIL_FIELD}):
                raise Refused("unsupported label")
        elif fields:
            raise Refused("unsupported markup")
        self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        if tag not in {"input", "meta"}:
            raise Refused("unsupported self-closing tag")
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            raise Refused("ambiguous document")
        self.stack.pop()

    def checked_action(self):
        self.close()
        if self.stack or self.action is None or not self.has_email:
            raise Refused("incomplete form")
        return self.action


@dataclass(frozen=True)
class StaticPage:
    origin: str
    port: int
    path: str
    action: str
    digest: bytes


@dataclass
class Challenge:
    page: StaticPage
    expires: float
    email: str | None = field(default=None, repr=False)
    submit: bool = False


class SignupBroker:
    """Model calls prepare and execute. A separate local UI calls approve."""

    def __init__(self, allowed_origins, cafile, *, browser=None, clock=time.monotonic, ttl=120):
        self.allowed_origins = frozenset(allowed_origins)
        if not self.allowed_origins or len(self.allowed_origins) > 8:
            raise Refused("unsupported origin configuration")
        for origin in self.allowed_origins:
            origin_port(origin)
        if not 0 < ttl <= 120:
            raise Refused("unsupported lifetime")
        self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self._tls.load_verify_locations(cafile=cafile)
        self._browser = browser
        self._clock = clock
        self._ttl = ttl
        self._lock = Lock()
        self._jobs = {}

    def _connection(self, port):
        # Numeric loopback, test CA only, and no proxy/redirect machinery.
        return HTTPSConnection("127.0.0.1", port, context=self._tls, timeout=3)

    def _fetch(self, origin, path):
        port = origin_port(origin)
        if origin not in self.allowed_origins or not valid_path(path):
            raise Refused("unsupported destination")
        connection = self._connection(port)
        try:
            connection.request("GET", path, headers={"Accept": "text/html"})
            response = connection.getresponse()
            if (response.status != 200 or response.getheader("Content-Type", "").partition(";")[0].strip() != "text/html"
                    or response.getheader("Content-Encoding") not in (None, "identity")):
                raise Refused("unsupported response")
            body = response.read(LIMIT + 1)
        finally:
            connection.close()
        if len(body) > LIMIT:
            raise Refused("document too large")
        parser = StaticForm()
        parser.feed(body.decode("utf-8", errors="strict"))
        return StaticPage(origin, port, path, parser.checked_action(), hashlib.sha256(body).digest())

    def _summary(self, request_id, job):
        return {
            "request_id": request_id, "origin": job.page.origin, "path": job.page.path,
            "action": job.page.action, "field": EMAIL_FIELD,
            "status": "approved" if job.email is not None else "pending",
        }

    def _purge_expired(self):
        now = self._clock()
        for request_id in [key for key, job in self._jobs.items() if now >= job.expires]:
            del self._jobs[request_id]

    def _lookup(self, request_id):
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            return None, "denied"
        job = self._jobs.get(request_id)
        if job is None:
            return None, "denied"
        if self._clock() >= job.expires:
            del self._jobs[request_id]
            return None, "expired"
        return job, None

    def prepare(self, url):
        match = URL.fullmatch(url) if isinstance(url, str) else None
        if not match or match[1] not in self.allowed_origins or not valid_path(match[2]):
            return {"status": "denied"}
        try:
            page = self._fetch(*match.groups())
        except (OSError, HTTPException, ValueError):
            return {"status": "denied"}
        with self._lock:
            self._purge_expired()
            if len(self._jobs) >= MAX_PENDING:
                return {"status": "denied"}
            request_id = secrets.token_hex(16).translate(ID_ALPHABET)
            while request_id in self._jobs:
                request_id = secrets.token_hex(16).translate(ID_ALPHABET)
            self._jobs[request_id] = Challenge(page, self._clock() + self._ttl)
        return {"request_id": request_id, "origin": page.origin, "field": EMAIL_FIELD, "status": "pending"}

    def describe(self, request_id):
        with self._lock:
            job, error = self._lookup(request_id)
            return self._summary(request_id, job) if job else {"status": error}

    def pending(self):
        with self._lock:
            self._purge_expired()
            return [self._summary(request_id, job) for request_id, job in self._jobs.items() if job.email is None]

    def approve(self, request_id, email, *, submit=False):
        if (type(submit) is not bool or not isinstance(email, str) or len(email) > 254
                or len(email.partition("@")[0]) > 64 or not SYNTHETIC_EMAIL.fullmatch(email)):
            return {"status": "denied"}
        with self._lock:
            job, error = self._lookup(request_id)
            if job is None or job.email is not None:
                return {"status": error or "denied"}
            job.email = email
            job.submit = submit
            job.expires = self._clock() + self._ttl
        return {"status": "approved"}

    def cancel(self, request_id):
        with self._lock:
            job, error = self._lookup(request_id)
            if job is None:
                return {"status": error}
            del self._jobs[request_id]
        return {"status": "cancelled"}

    def _submit(self, page, email):
        connection = self._connection(page.port)
        try:
            body = urlencode({EMAIL_FIELD: email}).encode("ascii")
            connection.request("POST", page.action, body=body,
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
            # Do not follow redirects, parse responses or echo untrusted content.
            return connection.getresponse().status
        finally:
            connection.close()

    def _form_matches(self, page):
        try:
            return self._fetch(page.origin, page.path) == page
        except (OSError, HTTPException, ValueError):
            return False

    def execute(self, request_id):
        with self._lock:
            job, error = self._lookup(request_id)
            if job is None or job.email is None:
                return {"status": error or "denied"}
            del self._jobs[request_id]

        if not self._form_matches(job.page):
            return {"status": "denied"}
        if self._clock() >= job.expires:
            return {"status": "expired"}

        try:
            if self._browser is None or self._browser(job.email) != job.email:
                return {"status": "unknown"}
            if not job.submit:
                return {"status": "filled"}
            if not self._form_matches(job.page):
                return {"status": "denied"}
            if self._clock() >= job.expires:
                return {"status": "expired"}
            return {"status": "submitted" if self._submit(job.page, job.email) == 204 else "unknown"}
        except Exception:
            # A failed or uncertain browser/POST operation is never retried
            # and its exception can include data that must stay local.
            return {"status": "unknown"}

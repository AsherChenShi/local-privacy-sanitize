"""Fill a synthetic email in a private, offline Chromium document.

The broker validates the real fixture and owns the HTTPS submission. This
worker never renders the site's HTML or drives an existing browser session.
"""

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
import select
import signal
import tempfile
import time


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.invalid")
_MAX_REPLY = 256 * 1024
_DOCUMENT = (
    '<!doctype html><meta charset="utf-8">'
    '<meta http-equiv="Content-Security-Policy" '
    'content="default-src \'none\'; base-uri \'none\'; form-action \'none\'">'
    '<label for="email">Email</label>'
    '<input type="email" id="email" name="email" autocomplete="off" required>'
)
_FIELD_VALUE = (
    "(() => {const f = document.getElementById('email');"
    "return location.href === 'about:blank' && f instanceof HTMLInputElement && "
    "document.querySelectorAll('input').length === 1 && f.type === 'email' && "
    "f.name === 'email' && f.validity.valid ? f.value : null;})()"
)


class BrowserError(ValueError):
    """A fixed browser failure string safe for a caller to handle."""


class _Pipe:
    def __init__(self, writer, reader, deadline):
        self.writer = writer
        self.reader = reader
        self.deadline = deadline
        self.buffer = bytearray()
        self.next_id = 0

    def _seconds_left(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BrowserError("BROWSER_TIMEOUT")
        return remaining

    def call(self, method, params=None, *, session=None):
        self.next_id += 1
        request = {"id": self.next_id, "method": method, "params": params or {}}
        if session is not None:
            request["sessionId"] = session
        output = memoryview(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\0")
        while output:
            _, ready, _ = select.select([], [self.writer], [], self._seconds_left())
            if not ready:
                raise BrowserError("BROWSER_TIMEOUT")
            output = output[os.write(self.writer, output):]
        while True:
            packet = self._receive()
            if packet.get("id") == self.next_id:
                result = packet.get("result")
                if "error" in packet or not isinstance(result, dict):
                    raise BrowserError("BROWSER_FAILED")
                return result

    def _receive(self):
        while True:
            self._seconds_left()
            end = self.buffer.find(b"\0")
            if end >= 0:
                data = bytes(self.buffer[:end])
                del self.buffer[:end + 1]
                result = json.loads(data)
                if not isinstance(result, dict):
                    raise BrowserError("BROWSER_FAILED")
                return result
            if len(self.buffer) >= _MAX_REPLY:
                raise BrowserError("BROWSER_FAILED")
            ready, _, _ = select.select([self.reader], [], [], self._seconds_left())
            if not ready:
                raise BrowserError("BROWSER_TIMEOUT")
            chunk = os.read(self.reader, min(4096, _MAX_REPLY - len(self.buffer)))
            if not chunk:
                raise BrowserError("BROWSER_FAILED")
            self.buffer.extend(chunk)


def _fill(pipe, email):
    context = pipe.call("Target.createBrowserContext", {"disposeOnDetach": True})["browserContextId"]
    target = pipe.call("Target.createTarget", {"url": "about:blank", "browserContextId": context})["targetId"]
    session = pipe.call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
    pipe.call("Network.enable", session=session)
    pipe.call("Network.setBlockedURLs", {"urls": ["*"]}, session=session)
    pipe.call("Network.emulateNetworkConditions", {
        "offline": True, "latency": 0, "downloadThroughput": 0, "uploadThroughput": 0,
    }, session=session)
    tree = pipe.call("Page.getFrameTree", session=session)["frameTree"]
    if tree.get("childFrames") or tree["frame"]["url"] != "about:blank":
        raise BrowserError("BROWSER_FAILED")
    pipe.call("Page.setDocumentContent", {"frameId": tree["frame"]["id"], "html": _DOCUMENT}, session=session)
    root = pipe.call("DOM.getDocument", {"depth": 0}, session=session)["root"]["nodeId"]
    field = pipe.call("DOM.querySelector", {"nodeId": root, "selector": "input#email[type=email][name=email]"},
                      session=session)["nodeId"]
    if not field:
        raise BrowserError("BROWSER_FAILED")
    pipe.call("DOM.focus", {"nodeId": field}, session=session)
    # The address is a typed value on the private pipe, never a script or argv.
    pipe.call("Input.insertText", {"text": email}, session=session)
    result = pipe.call("Runtime.evaluate", {"expression": _FIELD_VALUE, "returnByValue": True}, session=session)
    if "exceptionDetails" in result or result.get("result", {}).get("value") != email:
        raise BrowserError("BROWSER_FAILED")
    pipe.call("Target.disposeBrowserContext", {"browserContextId": context})
    return email


def _close_process(pid):
    if os.waitpid(pid, os.WNOHANG)[0] == pid:
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            return
        time.sleep(0.02)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)


def fill_email(email, *, browser_path, timeout=10):
    """Use a fresh private browser and return the verified .invalid value locally."""
    if not isinstance(email, str) or len(email) > 254 or not _EMAIL.fullmatch(email):
        raise BrowserError("INVALID_SYNTHETIC_EMAIL")
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        raise BrowserError("BROWSER_TIMEOUT")
    pid = None
    try:
        executable = Path(browser_path).resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise BrowserError("BROWSER_UNAVAILABLE")
        with (tempfile.TemporaryDirectory(prefix="signup-browser-") as profile,
              ExitStack() as parent_fds, ExitStack() as child_fds):
            stdin, writer = os.pipe()
            child_fds.callback(os.close, stdin)
            parent_fds.callback(os.close, writer)
            reader, stdout = os.pipe()
            parent_fds.callback(os.close, reader)
            child_fds.callback(os.close, stdout)
            null = os.open(os.devnull, os.O_RDWR)
            child_fds.callback(os.close, null)
            # Duplicate child endpoints above the reserved DevTools descriptors.
            descriptors = []
            for fd in (stdin, stdout, null):
                duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 5)
                child_fds.callback(os.close, duplicate)
                descriptors.append(duplicate)
            child_input, child_output, child_null = descriptors
            actions = [(os.POSIX_SPAWN_DUP2, child_null, target) for target in (0, 1, 2)]
            actions.extend(((os.POSIX_SPAWN_DUP2, child_input, 3), (os.POSIX_SPAWN_DUP2, child_output, 4)))
            arguments = [str(executable), "--headless=new", "--remote-debugging-pipe", f"--user-data-dir={profile}",
                         "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
                         "--disable-component-update", "--disable-sync", "--disable-extensions",
                         "--disable-breakpad", "--disable-crash-reporter", "--disable-logging",
                         "--host-resolver-rules=MAP * ~NOTFOUND", "about:blank"]
            deadline = time.monotonic() + timeout
            pid = os.posix_spawn(str(executable), arguments, {"PATH": os.defpath, "TMPDIR": profile},
                                 file_actions=actions, setpgroup=0)
            try:
                child_fds.close()
                return _fill(_Pipe(writer, reader, deadline), email)
            finally:
                _close_process(pid)
    except BrowserError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        code = "BROWSER_UNAVAILABLE" if pid is None else "BROWSER_FAILED"
        raise BrowserError(code) from None

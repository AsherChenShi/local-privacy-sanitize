#!/usr/bin/env python3
"""Offline candidate redaction for UTF-8 text, JSON and Markdown."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit

from structured_redaction import StructureError, json_parts, markdown_parts, markdown_text, splice

VERSION = "0.2.3"
MAX_BYTES = 2 * 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_MATCHES = 20000
ENTITY_TYPES = {"PERSON", "ORG", "LOCATION", "PROJECT", "ACCOUNT", "SENSITIVE"}
PLACEHOLDER = re.compile(r"\[(?:PERSON|ORG|LOCATION|PROJECT|ACCOUNT|SENSITIVE|URL|EMAIL|CNID|PHONE|SSN|SECRET|CARD|IP)_[0-9]{3,6}\]")
INVISIBLES = "\u200b\u200c\u200d\u2060\ufeff"
INPUT_FORMATS = {".txt": "text", ".log": "text", ".json": "json", ".md": "markdown"}
ARTIFACTS = {"text": "sanitized.txt", "json": "sanitized.json", "markdown": "sanitized.md"}


class Rejected(Exception):
    """Only fixed error codes may cross the CLI boundary."""


@dataclass(frozen=True)
class Entity:
    kind: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    kind: str
    identity: str
    priority: int = 0


def normalize(text: str, positions: list[int] | None = None) -> tuple[str, dict]:
    result = []
    changes = Counter()
    for index, char in enumerate(text):
        if char in INVISIBLES:
            changes["removed_invisible"] += 1
            continue
        if unicodedata.category(char).startswith("C") and char not in "\n\r\t":
            raise Rejected("UNSUPPORTED_CONTROL_CHARACTER")
        number = ord(char)
        if 0xFF01 <= number <= 0xFF5E and char not in "，；！？（）":
            char = chr(number - 0xFEE0)
            changes["fullwidth_ascii"] += 1
        elif char == "\u3000":
            char = " "
            changes["fullwidth_space"] += 1
        result.append(char)
        if positions is not None:
            positions.append(index)
    return "".join(result), dict(changes)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse_policy(data: str) -> tuple[Entity, ...]:
    try:
        obj = json.loads(data, object_pairs_hook=_unique_object)
    except (Rejected, ValueError, TypeError, RecursionError):
        raise Rejected("INVALID_POLICY") from None
    if not isinstance(obj, dict) or set(obj) != {"entities"}:
        raise Rejected("INVALID_POLICY")
    groups = obj["entities"]
    if not isinstance(groups, list) or len(groups) > 200:
        raise Rejected("INVALID_POLICY")
    entities = []
    seen = set()
    for group in groups:
        if not isinstance(group, dict) or set(group) != {"type", "values"}:
            raise Rejected("INVALID_POLICY")
        kind, values = group["type"], group["values"]
        if not isinstance(kind, str) or kind not in ENTITY_TYPES:
            raise Rejected("INVALID_POLICY")
        if not isinstance(values, list) or not 1 <= len(values) <= 20:
            raise Rejected("INVALID_POLICY")
        aliases = []
        for value in values:
            if not isinstance(value, str):
                raise Rejected("INVALID_POLICY")
            value, _ = normalize(value)
            if (not 2 <= len(value) <= 200 or value != value.strip()
                    or any(c in value for c in "\n\r\t") or PLACEHOLDER.search(value)
                    or value in seen):
                raise Rejected("INVALID_POLICY")
            seen.add(value)
            aliases.append(value)
        entities.append(Entity(kind, tuple(aliases)))
    return tuple(entities)


# Rules are deliberately conservative. Detection coverage is stated in the report.
URL_START = re.compile(
    r"(?<![A-Za-z0-9_])(?:https?|ftp|sftp|ssh|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://",
    re.I,
)
URL_DELIMITERS = "<>\"'`，。；！？）"
URL_BODY = re.compile(r"[^\s" + re.escape(URL_DELIMITERS) + "]+")
MARKDOWN_LINK_START = re.compile(r"(?<!\\)\[[^\[\]\r\n]*\]\([ \t]*\Z")
RULES = [
    ("EMAIL", re.compile(r"(?<![A-Za-z0-9_.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63}(?![A-Za-z0-9-])"), 80),
    ("CNID", re.compile(r"(?<![A-Za-z0-9])\d{17}[\dXx](?![A-Za-z0-9])"), 85),
    ("PHONE", re.compile(r"(?<![A-Za-z0-9])(?:\+?86[ \t-]*)?1[3-9](?:[ \t-]?\d){9}(?![A-Za-z0-9])"), 80),
    ("SSN", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), 70),
    ("SECRET", re.compile(r"(?<![A-Za-z0-9_-])(?:sk-(?:(?:proj|ant)-)?|gh[pousr]_|github_pat_)[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_-])"), 100),
    ("SECRET", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 100),
    ("SECRET", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), 100),
    ("SECRET", re.compile(r"\bBearer[ \t]+(?P<value>[A-Za-z0-9._~+/-]+={0,2})", re.I), 100),
    ("ACCOUNT", re.compile(r"(?:银行卡|卡号|账号|账户|工号|证件号)[\"']?[ \t]*[:=：][ \t]*[\"']?(?P<value>[A-Za-z0-9][A-Za-z0-9_-]{2,})"), 60),
]
SECRET_NAMES = (r"api[_ -]?key|private[_ -]?key|(?:access|refresh|auth|service)[_ -]?token|"
                r"client[_ -]?secret|password|passwd|secret|密码|口令|密钥|令牌")
AUTH_HEADERS = r"(?:proxy[-_ ])?authorization|(?:set[-_ ])?cookie"
SECRET_FIELD = re.compile(rf"(?:{SECRET_NAMES}|{AUTH_HEADERS})", re.I)
SECRET_LABEL = rf"(?:\b(?:{SECRET_NAMES})\b|密码|口令|密钥|令牌)[\"']?[ \t]*[:=：][ \t]*"
CREDENTIAL = re.compile(SECRET_LABEL + r"(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s\[\]\"',;，；。}]+)", re.I)
RULES.append(("SECRET", CREDENTIAL, 100))
RULES.append(("SECRET", re.compile(rf"^[ \t]*(?:{AUTH_HEADERS})[ \t]*:[ \t]*(?P<value>[^\s][^\r\n]*)",
                                   re.I | re.M), 100))
QUOTED_SECRET_HEADER = re.compile(SECRET_LABEL + r"[\"']", re.I)
PEM = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----[\s\S]*?-----END \1-----")
PEM_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
IPV4 = re.compile(r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_]|\.\d)")
IPV6 = re.compile(r"(?<![A-Za-z0-9_:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Za-z0-9_:])")

DOC_PATHS = {
    "docs.github.com": ("/",),
    "learn.chatgpt.com": ("/docs",),
    "developers.openai.com": ("/api/docs", "/codex", "/docs", "/plugins", "/cookbook"),
    "platform.openai.com": ("/docs",),
    "help.openai.com": ("/en",),
    "code.claude.com": ("/docs",),
    "docs.anthropic.com": ("/en",),
    "docs.claude.com": ("/en",),
    "platform.claude.com": ("/docs",),
    "docs.python.org": ("/",),
    "developer.mozilla.org": ("/",),
    "learn.microsoft.com": ("/",),
    "genai.owasp.org": ("/llmrisk",),
    "csrc.nist.gov": ("/pubs",),
    "presidio.dataprivacystack.org": ("/",),
}
GITHUB_RESOURCE = {
    "actions", "blob", "blame", "branches", "commit", "commits", "compare",
    "contributors", "discussions", "forks", "issues", "network", "pull", "pulls",
    "releases", "security", "stargazers", "tags", "tree", "wiki",
}
GITHUB_API_RESOURCE = GITHUB_RESOURCE | {
    "assignees", "collaborators", "comments", "contents", "deployments", "downloads",
    "git", "languages", "license", "milestones", "readme", "stats", "subscribers",
}
GITHUB_NONPUBLIC = {
    "account", "apps", "auth", "code", "codespaces", "dashboard", "enterprise",
    "enterprises", "installations", "join", "login", "logout", "new",
    "notifications", "oauth", "orgs", "password_reset", "search", "session",
    "sessions", "settings", "signup", "sponsors", "user", "user-attachments",
}
QUERY_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,47}")
DOC_QUERY = {
    "api-version", "lang", "locale", "site_variant", "surface",
    "translationFallback", "trk", "version", "view",
}
GITHUB_QUERY = {
    "head_sha": re.compile(r"[0-9a-fA-F]{7,64}"),
    "page": re.compile(r"[1-9][0-9]{0,5}"),
    "per_page": re.compile(r"(?:[1-9][0-9]?|100)"),
    "plain": re.compile(r"[01]"),
    "sha": re.compile(r"[0-9a-fA-F]{7,64}"),
    "tab": re.compile(r"(?:readme|readme-ov-file|MIT-1-ov-file|Apache-2\.0-1-ov-file)"),
}
URL_SECRET_SEGMENTS = re.compile(
    r"(?:access[-_]?token|refresh[-_]?token|api[-_]?key|client[-_]?secret|"
    r"password|passwd|secret|signature|sig|signed|token)", re.I,
)
BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
URL_SECRET_PATTERNS = tuple(pattern for kind, pattern, _ in RULES if kind in ("SECRET", "EMAIL"))
URL_PII_PATTERNS = tuple(pattern for kind, pattern, _ in RULES if kind in ("PHONE", "CNID", "SSN"))
GITHUB_NAME = re.compile(r"[A-Za-z0-9_.-]+")
GITHUB_API_TEMPLATE = re.compile(
    r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:git/refs|git/commits|commits)\{/sha\}"
)
GITHUB_RUN_URL = re.compile(
    r"(?i:https://(?:github\.com/|api\.github\.com/repos/))"
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/(?P<id>[1-9][0-9]{0,11})/?(?=[?#]|\Z)"
)


def _markdown_url_end(text, body_start):
    nesting = 0
    escaped = False
    for end in range(body_start, len(text)):
        char = text[end]
        if char.isspace() or char in URL_DELIMITERS:
            return end
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "(":
            nesting += 1
        elif char == ")":
            if not nesting:
                return end
            nesting -= 1
    return len(text)


def _url_spans(text):
    cursor = 0
    while start := URL_START.search(text, cursor):
        # Bound the search for an inline Markdown label. The ordinary path keeps
        # the conservative URL extent, including a trailing parenthesis.
        if MARKDOWN_LINK_START.search(text[max(0, start.start() - 512):start.start()]):
            cursor = _markdown_url_end(text, start.end())
        else:
            body = URL_BODY.match(text, start.end())
            cursor = body.end() if body else start.end()
        if cursor > start.end():
            yield start.start(), cursor


def github_public_path(host, path):
    segments = path.strip("/").split("/") if path.strip("/") else []
    if host == "avatars.githubusercontent.com":
        return re.fullmatch(r"/u/[0-9]+/?", path) is not None
    if host == "raw.githubusercontent.com":
        return len(segments) >= 4 and all(GITHUB_NAME.fullmatch(item) for item in segments[:2])
    if host == "api.github.com":
        if GITHUB_API_TEMPLATE.fullmatch(path):
            return True
        if segments[:1] == ["repos"]:
            if len(segments) < 3 or not all(GITHUB_NAME.fullmatch(item) for item in segments[1:3]):
                return False
            resource = segments[3:]
            if len(resource) > 1 and resource[0] == "actions":
                return resource[1] in ("artifacts", "jobs", "runs", "workflows")
            return not resource or resource[0] in GITHUB_API_RESOURCE
        return (len(segments) >= 2 and segments[0] in ("users", "orgs")
                and GITHUB_NAME.fullmatch(segments[1]) is not None
                and (len(segments) == 2 or segments[2] in (
                    "events", "followers", "following", "gists", "orgs", "public_members",
                    "received_events", "repos", "starred", "subscriptions")))
    if not segments:
        return True
    if segments[0].lower() in GITHUB_NONPUBLIC or not GITHUB_NAME.fullmatch(segments[0]):
        return False
    if len(segments) == 1:
        return True
    return (GITHUB_NAME.fullmatch(segments[1]) is not None
            and (len(segments) == 2 or segments[2] in GITHUB_RESOURCE))


def public_url_candidate(url):
    # Parse a Markdown or prose URL without consuming its closing punctuation.
    url = url.rstrip(".,!)]")
    if len(url) > 4096 or BAD_ESCAPE.search(url) or "\\" in url:
        return False
    try:
        parts = urlsplit(url)
        authority = parts.netloc.lower()
        if parts.scheme != "https" or authority != parts.hostname or ";" in parts.query:
            return False  # Exact authority: no credentials, ports, or host suffix tricks.
        path = unquote(parts.path, errors="strict") or "/"
        fragment = unquote(parts.fragment, errors="strict")
        query = (parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                           max_num_fields=12, errors="strict") if parts.query else [])
    except (UnicodeError, ValueError):
        return False

    if (any(c.isspace() or unicodedata.category(c).startswith("C") for c in path)
            or re.search(r"[%?#;=&@:\\]", path)
            or "//" in path or re.search(r"%2f", parts.path, re.I)
            or set(path.split("/")) & {".", ".."}
            or any(URL_SECRET_SEGMENTS.fullmatch(s) for s in path.rstrip("/").split("/")[:-1])
            or (fragment and not re.fullmatch(r"[\w.\-/]{1,200}", fragment))):
        return False
    # Detect known secrets and emails even when URL-escaped in an otherwise public path.
    if any(rule.search(value) for value in (path, fragment, *(value for _, value in query))
           for rule in URL_SECRET_PATTERNS):
        return False

    # Plain-text rules see the original URL. Repeat the relevant checks when
    # percent-encoding or form-query decoding can conceal sensitive characters.
    encoded_values = []
    if "%" in parts.path:
        encoded_values.append(path)
    if "%" in parts.fragment:
        encoded_values.append(fragment)
    if "%" in parts.query or "+" in parts.query:
        encoded_values.extend(value for _, value in query)
    if any(_decoded_url_pii(value) for value in encoded_values):
        return False

    if authority in DOC_PATHS:
        if not any(prefix == "/" or path == prefix or path.startswith(prefix + "/")
                   for prefix in DOC_PATHS[authority]):
            return False
        permitted = dict.fromkeys(DOC_QUERY, QUERY_SLUG)
    elif authority in {"github.com", "api.github.com", "raw.githubusercontent.com", "avatars.githubusercontent.com"}:
        if not github_public_path(authority, path):
            return False
        permitted = ({"v": re.compile(r"[1-9][0-9]?")} if authority == "avatars.githubusercontent.com"
                     else GITHUB_QUERY if authority in {"github.com", "api.github.com"} else {})
    else:
        return False
    if ("{" in path or "}" in path) and not (
            authority == "api.github.com" and GITHUB_API_TEMPLATE.fullmatch(path)):
        return False

    return (len({key for key, _ in query}) == len(query)
            and all(key in permitted and permitted[key].fullmatch(value) for key, value in query))


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        value = digit * 2 if i % 2 else digit
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def _decoded_url_pii(value):
    try:
        value, _ = normalize(value)
    except Rejected:
        return True
    return (any(pattern.search(value) for pattern in URL_SECRET_PATTERNS + URL_PII_PATTERNS)
            or any(_luhn(match.group()) for match in CARD.finditer(value))
            or any(_valid_ip(match.group()) for match in IPV4.finditer(value)))


def _valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def find_matches(text: str, entities: tuple[Entity, ...] = (), *, placeholder_source=None) -> list[Match]:
    candidates = []
    def add(match):
        if len(candidates) >= MAX_MATCHES:
            raise Rejected("TOO_MANY_MATCHES")
        candidates.append(match)

    run_ids = set()
    for start, end in _url_spans(text):
        url = text[start:end]
        if not public_url_candidate(url):
            add(Match(start, end, "URL", url, 90))
            continue
        run = GITHUB_RUN_URL.match(url.rstrip(".,!)]"))
        if run:
            run_ids.add((start + run.start("id"), start + run.end("id")))

    credential_ends = {}
    for match in CREDENTIAL.finditer(text):
        if len(credential_ends) >= MAX_MATCHES:
            raise Rejected("TOO_MANY_MATCHES")
        credential_ends[match.start()] = match.end()
    for header in QUOTED_SECRET_HEADER.finditer(text):
        if credential_ends.get(header.start(), -1) < header.end():
            raise Rejected("INCOMPLETE_QUOTED_SECRET")
    pem_starts = set()
    for match in PEM.finditer(text):
        pem_starts.add(match.start())
        add(Match(*match.span(), "SECRET", match.group(), 110))
    for header in PEM_HEADER.finditer(text):
        if header.start() not in pem_starts:
            raise Rejected("INCOMPLETE_PRIVATE_KEY")
    for kind, pattern, priority in RULES:
        for match in pattern.finditer(text):
            span = match.span("value") if "value" in match.re.groupindex else match.span()
            value = text[span[0]:span[1]]
            if pattern is CREDENTIAL and placeholder_source is not None and value[:1] in ('"', "'"):
                if PLACEHOLDER.fullmatch(placeholder_source[span[0] + 1:span[1] - 1]):
                    continue
            if kind == "PHONE":
                if span in run_ids:
                    continue
                value = re.sub(r"[^0-9]", "", value)[-11:]
            elif kind == "EMAIL":
                local, domain = value.rsplit("@", 1)
                value = local + "@" + domain.casefold()
            elif kind == "CNID":
                value = value.upper()
            add(Match(*span, kind, value, priority))
    for match in CARD.finditer(text):
        if _luhn(match.group()):
            value = re.sub(r"\D", "", match.group())
            add(Match(*match.span(), "CARD", value, 65))
    for pattern in (IPV4, IPV6):
        for match in pattern.finditer(text):
            value = _valid_ip(match.group())
            if value is not None:
                add(Match(*match.span(), "IP", value, 50))
    for group_id, entity in enumerate(entities):
        for value in entity.values:
            # Literal and case-sensitive. Short aliases are intentionally explicit.
            for match in re.finditer(re.escape(value), text):
                add(Match(*match.span(), entity.kind, f"entity:{group_id}", 20))
    return candidates


def _merge_overlaps(matches: list[Match], text: str) -> list[Match]:
    """Never leave the tail of a partially overlapping sensitive span visible."""
    groups = []
    group_end = -1
    for match in sorted(matches, key=lambda m: (m.start, -m.end, -m.priority)):
        if groups and match.start < group_end:
            groups[-1].append(match)
        else:
            groups.append([match])
        group_end = max(group_end, match.end)
    merged = []
    for group in groups:
        start, end = min(m.start for m in group), max(m.end for m in group)
        covering = [m for m in group if m.start == start and m.end == end]
        if covering:
            merged.append(max(covering, key=lambda m: m.priority))
        else:
            merged.append(Match(start, end, "SENSITIVE", text[start:end], 120))
    return merged


def matches_with_placeholders(text, entities):
    candidate = PLACEHOLDER.sub(lambda match: " " * len(match.group()), text)
    return find_matches(candidate, entities, placeholder_source=text)


class Redaction:
    def __init__(self, entities, *, allow_placeholders=False):
        self.entities = entities
        self.allow_placeholders = allow_placeholders
        self.identities = {}
        self.counters = Counter()
        self.occurrences = Counter()
        self.count = 0

    def replacement(self, kind, identity):
        self.count += 1
        if self.count > MAX_MATCHES:
            raise Rejected("TOO_MANY_MATCHES")
        key = (kind, identity)
        if key not in self.identities:
            self.counters[kind] += 1
            self.identities[key] = f"[{kind}_{self.counters[kind]:03d}]"
        self.occurrences[kind] += 1
        return self.identities[key]

    def matches(self, text):
        if self.allow_placeholders:
            return matches_with_placeholders(text, self.entities)
        if PLACEHOLDER.search(text):
            raise Rejected("RESERVED_PLACEHOLDER_IN_INPUT")
        return find_matches(text, self.entities)

    def text(self, original, *, preserve_lines=False):
        positions = []
        text, _ = normalize(original, positions)
        replacements = []
        for match in _merge_overlaps(self.matches(text), text):
            start, end = positions[match.start], positions[match.end - 1] + 1
            if preserve_lines and any(char in original[start:end] for char in "\r\n"):
                raise Rejected("AMBIGUOUS_MARKDOWN_RANGE")
            replacements.append((start, end, self.replacement(match.kind, match.identity)))
        return splice(original, replacements)

    def json(self, source):
        parts, shape = json_parts(source)
        replacements = []
        for part in parts:
            value, _ = normalize(part.value)
            field = part.field is not None and SECRET_FIELD.fullmatch(normalize(part.field)[0].strip())
            if part.kind == "json_key":
                if PLACEHOLDER.search(value) or self.matches(value):
                    raise Rejected("SENSITIVE_JSON_KEY")
            elif part.kind in ("json_scalar", "json_container"):
                if (field and value not in ("", "null", "true", "false")) or self.matches(value):
                    raise Rejected("SENSITIVE_NON_STRING_JSON_VALUE")
            else:
                if not self.allow_placeholders and PLACEHOLDER.search(value):
                    raise Rejected("RESERVED_PLACEHOLDER_IN_INPUT")
                if field and credential_value_present(part.value):
                    replacement = self.replacement("SECRET", value)
                else:
                    replacement = self.text(part.value)
                if replacement != part.value:
                    replacements.append((part.start, part.end, json.dumps(replacement, ensure_ascii=False)))
        output = splice(source, replacements)
        if replacements and json_parts(output)[1] != shape:
            raise Rejected("JSON_STRUCTURE_CHANGED")
        return output

    def markdown(self, source):
        parts, shape = markdown_parts(source)
        replacements = []
        for part in parts:
            original = source[part.start:part.end]
            if part.kind == "json":
                updated = self.json(original)
            elif part.kind in ("link", "autolink"):
                value, _ = normalize(markdown_text(original))
                if self.matches(value):
                    marker = self.replacement("URL", value)[1:-1]
                    if part.kind == "autolink":
                        updated = f"redacted:{marker}"
                    else:
                        updated = f"#redacted-{marker.lower().replace('_', '-')}"
                else:
                    updated = original
            elif part.kind == "markup":
                if self.matches(normalize(original)[0]):
                    raise Rejected("SENSITIVE_MARKDOWN_MARKUP")
                updated = original
            else:
                contents = original.rstrip(" \t")
                updated = self.text(contents, preserve_lines=True) + original[len(contents):]
                if part.kind == "text":
                    rendered = markdown_text(updated)
                    if rendered != updated and self.matches(normalize(rendered)[0]):
                        raise Rejected("AMBIGUOUS_MARKDOWN_RANGE")
            if updated != original:
                replacements.append((part.start, part.end, updated))
        output = splice(source, replacements)
        if replacements and markdown_parts(output)[1] != shape:
            raise Rejected("MARKDOWN_STRUCTURE_CHANGED")
        return output

    def run(self, source, format):
        try:
            return {"text": self.text, "json": self.json, "markdown": self.markdown}[format](source)
        except StructureError as error:
            raise Rejected(str(error)) from None


def sanitize(text: str, entities: tuple[Entity, ...] = (), *, format="text") -> tuple[str, dict]:
    normalized, changes = normalize(text)
    if PLACEHOLDER.search(normalized):
        raise Rejected("RESERVED_PLACEHOLDER_IN_INPUT")
    redaction = Redaction(entities)
    output = redaction.run(text, format)
    if format == "text":
        if scan_kind(output, entities):
            raise Rejected("RESIDUAL_KNOWN_MATCH")
    else:
        reviewed = Redaction(entities, allow_placeholders=True)
        if reviewed.run(output, format) != output:
            raise Rejected("RESIDUAL_KNOWN_MATCH")
        if format == "markdown" and scan_kind(output, entities):
            raise Rejected("RESIDUAL_KNOWN_MATCH")
    report = {
        "version": VERSION,
        "status": "REVIEW_REQUIRED",
        "format": format,
        "artifact": ARTIFACTS[format],
        "occurrences": dict(sorted(redaction.occurrences.items())),
        "unique_entities": dict(sorted(redaction.counters.items())),
        "configured_entity_groups": len(entities),
        "normalization": changes,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "coverage": "structured_rules_and_explicit_literals_only",
        "warnings": ["UNCONFIGURED_NAMES_AND_CONTEXT_MAY_REMAIN", "NOT_AN_UPLOAD_INTERCEPTOR"],
    }
    # The identity map exists in this process only.
    return output, report


def credential_value_present(value):
    if isinstance(value, str):
        text, _ = normalize(value)
        text = text.strip()
        return bool(text) and not PLACEHOLDER.fullmatch(text)
    if isinstance(value, (list, dict)):
        return bool(value)
    return value is not None and not isinstance(value, bool)


def scan_kind(value, entities=(), *, parse_text=True, tool_content=True):
    """Return the first fixed classification found in a hook value, without its contents."""
    if isinstance(value, dict):
        if tool_content and value.get("type") in ("image", "audio", "resource", "resource_link", "binary"):
            raise Rejected("UNSUPPORTED_TOOL_CONTENT")
        for key, child in value.items():
            normalized, _ = normalize(key)
            if SECRET_FIELD.fullmatch(normalized.strip()) and credential_value_present(child):
                return "SECRET"
            kind = (scan_kind(key, entities, parse_text=False)
                    or scan_kind(child, entities, parse_text=parse_text, tool_content=tool_content))
            if kind:
                return kind
        return None
    if isinstance(value, list):
        for child in value:
            kind = scan_kind(child, entities, parse_text=parse_text, tool_content=tool_content)
            if kind:
                return kind
        return None
    if value is None or isinstance(value, bool):
        return None
    text, _ = normalize(str(value))
    matches = matches_with_placeholders(text, entities)
    if matches:
        return matches[0].kind
    return scan_json_text(text, entities) if parse_text else None


def scan_json_text(text, entities):
    stripped = text.strip()
    if not ((stripped.startswith("{") and stripped.endswith("}"))
            or (stripped.startswith("[") and stripped.endswith("]"))):
        return None
    try:
        value = json.loads(stripped, object_pairs_hook=_unique_object)
    except json.JSONDecodeError:
        return None
    return scan_kind(value, entities, parse_text=False, tool_content=False)


def scan_value(value, entities=()):
    return scan_kind(value, entities) is not None


def read_local(path: Path, limit: int, suffixes: set[str]) -> str:
    if path.suffix.lower() not in suffixes:
        raise Rejected("UNSUPPORTED_FILE_TYPE")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise Rejected("REGULAR_FILE_REQUIRED")
        if info.st_size > limit:
            raise Rejected("FILE_TOO_LARGE")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise Rejected("FILE_TOO_LARGE")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Rejected("UTF8_REQUIRED") from None


def write_bundle(directory: Path, output: str, report: dict, *, format="text") -> None:
    """Fresh directory only. Private permissions; exclusive, no-follow file opens."""
    os.mkdir(directory, mode=0o700)
    dir_fd = None
    created = []
    try:
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
        for name, content in (
            (ARTIFACTS[format], output),
            ("report.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n"),
        ):
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
            created.append(name)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
                stream.write(content)
    except BaseException:
        if dir_fd is not None:
            for name in created:
                os.unlink(name, dir_fd=dir_fd)
        os.rmdir(directory)
        raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise Rejected("INVALID_ARGUMENTS")


def main(argv=None) -> int:
    parser = SafeParser(prog="local-privacy-sanitize", description=__doc__)
    parser.add_argument("command", choices=("sanitize", "check"))
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--format", choices=tuple(ARTIFACTS),
                        help="Explicit format for a .txt or .log file")
    try:
        args = parser.parse_args(argv)
        if os.name != "posix":
            raise Rejected("UNSUPPORTED_PLATFORM")
        if (args.command == "sanitize") != (args.out_dir is not None):
            raise Rejected("INVALID_ARGUMENTS")
        entities = parse_policy(read_local(args.policy, MAX_POLICY_BYTES, {".json"})) if args.policy else ()
        source = read_local(args.input, MAX_BYTES, set(INPUT_FORMATS))
        inferred = INPUT_FORMATS[args.input.suffix.lower()]
        if args.format and inferred not in ("text", args.format):
            raise Rejected("FORMAT_EXTENSION_MISMATCH")
        format = args.format or inferred
        if args.command == "sanitize":
            output, report = sanitize(source, entities, format=format)
            write_bundle(args.out_dir, output, report, format=format)
            print(json.dumps({"status": report["status"], "artifact": report["artifact"],
                              "occurrences": report["occurrences"]}))
            return 0
        normalized, _ = normalize(source)
        if format == "text":
            matches = _merge_overlaps(matches_with_placeholders(normalized, entities), normalized)
            occurrences = Counter(match.kind for match in matches)
            structured_match = scan_json_text(normalized, entities) if not matches else None
        else:
            redaction = Redaction(entities, allow_placeholders=True)
            redaction.run(source, format)
            occurrences = redaction.occurrences
            structured_match = scan_kind(source, entities) if format == "markdown" and not occurrences else None
        found = bool(occurrences or structured_match)
        result = {"structured_match": structured_match} if structured_match else {}
        print(json.dumps({"status": "KNOWN_MATCHES_FOUND" if found else "NO_KNOWN_MATCHES",
                          "occurrences": dict(occurrences), "review_required": True, **result}))
        return 3 if found else 0
    except Rejected as error:
        print(json.dumps({"status": "BLOCKED", "code": str(error)}), file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError):
        # Exception messages can contain filenames, policy values and other PII.
        print(json.dumps({"status": "BLOCKED", "code": "LOCAL_IO_OR_DATA_ERROR"}), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({"status": "BLOCKED", "code": "INTERNAL_ERROR"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

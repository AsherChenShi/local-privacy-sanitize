#!/usr/bin/env python3
"""Offline candidate redaction for UTF-8 plain text. Not an upload interceptor."""
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

VERSION = "0.1.0"
MAX_BYTES = 2 * 1024 * 1024
MAX_POLICY_BYTES = 256 * 1024
MAX_MATCHES = 20000
ENTITY_TYPES = {"PERSON", "ORG", "LOCATION", "PROJECT", "ACCOUNT", "SENSITIVE"}
PLACEHOLDER = re.compile(r"\[(?:PERSON|ORG|LOCATION|PROJECT|ACCOUNT|SENSITIVE|URL|EMAIL|CNID|PHONE|SSN|SECRET|CARD|IP)_[0-9]{3,6}\]")
INVISIBLES = "\u200b\u200c\u200d\u2060\ufeff"
TEXT_SUFFIXES = {".txt", ".md", ".log"}


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
            raise Rejected("INVALID_POLICY")
        result[key] = value
    return result


def parse_policy(data: str) -> tuple[Entity, ...]:
    try:
        obj = json.loads(data, object_pairs_hook=_unique_object)
    except (ValueError, TypeError, RecursionError):
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
RULES = [
    ("URL", re.compile(r"(?<![A-Za-z0-9_])(?:https?|ftp|sftp|ssh|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s<>\"'，。；！？）]+", re.I), 90),
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
SECRET_LABEL = r"(?:\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|passwd|secret)\b|密码|口令|密钥|令牌)[\"']?[ \t]*[:=：][ \t]*"
CREDENTIAL = re.compile(SECRET_LABEL + r"(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s\[\]\"',;，；。}]+)", re.I)
RULES.append(("SECRET", CREDENTIAL, 100))
QUOTED_SECRET_HEADER = re.compile(SECRET_LABEL + r"[\"']", re.I)
PEM = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----[\s\S]*?-----END \1-----")
PEM_HEADER = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
IPV4 = re.compile(r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_]|\.\d)")
IPV6 = re.compile(r"(?<![A-Za-z0-9_:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Za-z0-9_:])")


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        value = digit * 2 if i % 2 else digit
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def find_matches(text: str, entities: tuple[Entity, ...] = ()) -> list[Match]:
    candidates = []
    def add(match):
        if len(candidates) >= MAX_MATCHES:
            raise Rejected("TOO_MANY_MATCHES")
        candidates.append(match)

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
            if kind == "PHONE":
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
            try:
                value = str(ipaddress.ip_address(match.group()))
            except ValueError:
                continue
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


def sanitize(text: str, entities: tuple[Entity, ...] = ()) -> tuple[str, dict]:
    original = text
    positions = []
    text, changes = normalize(text, positions)
    if PLACEHOLDER.search(text):
        raise Rejected("RESERVED_PLACEHOLDER_IN_INPUT")
    matches = _merge_overlaps(find_matches(text, entities), text)
    identities = {}
    counters = Counter()
    occurrences = Counter()
    parts = []
    cursor = 0
    for match in matches:
        key = (match.kind, match.identity)
        if key not in identities:
            counters[match.kind] += 1
            identities[key] = f"[{match.kind}_{counters[match.kind]:03d}]"
        start, end = positions[match.start], positions[match.end - 1] + 1
        parts.extend((original[cursor:start], identities[key]))
        cursor = end
        occurrences[match.kind] += 1
    parts.append(original[cursor:])
    output = "".join(parts)
    # Scan all remaining text, not only the spans selected in the first pass.
    residual, _ = normalize(output)
    residual = PLACEHOLDER.sub(lambda m: " " * len(m.group()), residual)
    if find_matches(residual, entities):
        raise Rejected("RESIDUAL_KNOWN_MATCH")
    report = {
        "version": VERSION,
        "status": "REVIEW_REQUIRED",
        "occurrences": dict(sorted(occurrences.items())),
        "unique_entities": dict(sorted(counters.items())),
        "configured_entity_groups": len(entities),
        "normalization": changes,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "coverage": "structured_rules_and_explicit_literals_only",
        "warnings": ["UNCONFIGURED_NAMES_AND_CONTEXT_MAY_REMAIN", "NOT_AN_UPLOAD_INTERCEPTOR"],
    }
    # identities is transient; neither original values nor a reversal map is exported.
    return output, report


def scan_value(value, entities=()):
    """Check text in a JSON value for known matches without exposing the value."""
    if isinstance(value, dict):
        if value.get("type") in ("image", "audio", "resource"):
            raise ValueError("unsupported tool content")
        return any(scan_value(key, entities) or scan_value(child, entities)
                   for key, child in value.items())
    if isinstance(value, list):
        return any(scan_value(child, entities) for child in value)
    if value is None or isinstance(value, bool):
        return False
    text, _ = normalize(str(value))
    candidate = PLACEHOLDER.sub(lambda match: " " * len(match.group()), text)
    return bool(find_matches(candidate, entities))


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


def write_bundle(directory: Path, output: str, report: dict) -> None:
    """Fresh directory only. Private permissions; exclusive, no-follow file opens."""
    os.mkdir(directory, mode=0o700)
    dir_fd = None
    created = []
    try:
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
        for name, content in (
            ("sanitized.txt", output),
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
    try:
        args = parser.parse_args(argv)
        if os.name != "posix":
            raise Rejected("UNSUPPORTED_PLATFORM")
        if (args.command == "sanitize") != (args.out_dir is not None):
            raise Rejected("INVALID_ARGUMENTS")
        entities = parse_policy(read_local(args.policy, MAX_POLICY_BYTES, {".json"})) if args.policy else ()
        source = read_local(args.input, MAX_BYTES, TEXT_SUFFIXES)
        if args.command == "sanitize":
            output, report = sanitize(source, entities)
            write_bundle(args.out_dir, output, report)
            print(json.dumps({"status": report["status"], "occurrences": report["occurrences"]}))
            return 0
        normalized, _ = normalize(source)
        # check accepts generated placeholders, but never interprets them as approval.
        normalized = PLACEHOLDER.sub(lambda m: " " * len(m.group()), normalized)
        matches = _merge_overlaps(find_matches(normalized, entities), normalized)
        print(json.dumps({"status": "KNOWN_MATCHES_FOUND" if matches else "NO_KNOWN_MATCHES",
                          "occurrences": dict(Counter(m.kind for m in matches)),
                          "review_required": True}))
        return 3 if matches else 0
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

"""Local ordinary-type selection and a narrow set of review-only hints."""
from bisect import bisect_right
import json
from pathlib import Path
import re

from structured_redaction import json_parts, markdown_parts


ORDINARY_TYPES = frozenset({"PERSON", "ORG", "LOCATION", "PROJECT"})
POLICY_LIMIT = 4096
LABELS = {
    "客户姓名": "PERSON", "收件人": "PERSON", "联系人": "PERSON",
    "住址": "LOCATION", "收货地址": "LOCATION", "客户地址": "LOCATION",
    "内部项目": "PROJECT", "customer name": "PERSON", "contact name": "PERSON",
    "recipient": "PERSON", "home address": "LOCATION", "shipping address": "LOCATION",
    "internal project": "PROJECT", "shippingaddress": "LOCATION", "contact_name": "PERSON",
}
PLACEHOLDER_ONLY = re.compile(r"\[(?:PERSON|ORG|LOCATION|PROJECT|ACCOUNT|SENSITIVE|URL|EMAIL|CNID|PHONE|SSN|SECRET|CARD|IP)_[0-9]{3,6}\]")
EMPTY_VALUES = {"", "-", "—", "--", "…", "...", "无", "不适用", "未填写", "未知", "n/a", "none", "unknown", "redacted"}
LINE_START = re.compile(r"\r\n|\r|\n")
LABEL_PATTERN = "|".join(re.escape(label) for label in LABELS)
LABELED_LINE = re.compile(
    r"(?:^|(?<=\r))[ \t]*(?:[-*+][ \t]+)?(?:\*\*)?(?P<label>" + LABEL_PATTERN
    + r")(?:\*\*)?[ \t]*[:：](?:\*\*)?[ \t]*(?P<value>[^\r\n]*)", re.I | re.M | re.ASCII
)


class ReviewPolicyError(ValueError):
    """The policy is unreadable or attempts to select unsupported categories."""


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReviewPolicyError("INVALID_REVIEW_POLICY")
        result[key] = value
    return result


def parse_review_policy(text):
    try:
        data = json.loads(text, object_pairs_hook=_unique_fields)
    except (ValueError, RecursionError):
        raise ReviewPolicyError("INVALID_REVIEW_POLICY") from None
    if not isinstance(data, dict) or set(data) != {"ordinary_types"}:
        raise ReviewPolicyError("INVALID_REVIEW_POLICY")
    return ordinary_type_selection(data["ordinary_types"])


def ordinary_type_selection(chosen):
    if (not isinstance(chosen, list) or len(chosen) > len(ORDINARY_TYPES)
            or any(type(kind) is not str or kind not in ORDINARY_TYPES for kind in chosen)
            or len(set(chosen)) != len(chosen)):
        raise ReviewPolicyError("INVALID_REVIEW_POLICY")
    return frozenset(chosen)


def default_policy_path():
    return Path.home() / ".config" / "local-privacy-sanitize" / "review-policy.local.json"


def load_review_policy(path=None, *, read_local):
    source = default_policy_path() if path is None else Path(path).expanduser()
    try:
        text = read_local(source, POLICY_LIMIT, {".json"})
    except FileNotFoundError:
        if path is None:
            return ORDINARY_TYPES
        raise ReviewPolicyError("INVALID_REVIEW_POLICY") from None
    except Exception:
        # The shared bounded reader may report a path or format failure.
        raise ReviewPolicyError("INVALID_REVIEW_POLICY") from None
    return parse_review_policy(text)


def select_entities(entities, ordinary_types):
    omitted = ORDINARY_TYPES - ordinary_types
    return tuple(entity for entity in entities if entity.kind not in omitted)


def hook_entities(entities, *, read_local):
    if not entities:
        return entities
    try:
        return select_entities(entities, load_review_policy(read_local=read_local))
    except ReviewPolicyError:
        # Invalid configuration cannot turn off any existing category.
        return entities


def _has_value(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
        value = value[1:-1].strip()
    return value.casefold() not in EMPTY_VALUES and PLACEHOLDER_ONLY.fullmatch(value) is None


def _json_doubts(source, offset=0):
    parts, _ = json_parts(source)
    for part in parts:
        if part.kind == "json_string" and part.field:
            kind = LABELS.get(part.field.strip().casefold())
            if kind and _has_value(part.value):
                yield part.start + offset + 1, part.end + offset - 1, kind


def _doubt_ranges(candidate, format):
    if format == "json":
        yield from _json_doubts(candidate)
        return
    if format == "markdown":
        parts, _ = markdown_parts(candidate)
        fences = [part for part in parts if part.kind in ("code", "json")]
        for part in fences:
            if part.kind == "json":
                yield from _json_doubts(candidate[part.start:part.end], part.start)
    else:
        fences = []
    opens = [part.start for part in fences]
    for match in LABELED_LINE.finditer(candidate):
        fence = bisect_right(opens, match.start()) - 1
        if fence >= 0 and match.start() < fences[fence].end:
            continue
        value = match.group("value")
        if _has_value(value):
            start = match.start("value")
            yield start, start + len(value.rstrip()), LABELS[match.group("label").casefold()]


def find_doubts(candidate, format):
    """Return only grouped coordinates and a fixed reason, never the value."""
    starts = [0, *(match.end() for match in LINE_START.finditer(candidate))]
    rows = {}
    for start, end, kind in sorted(_doubt_ranges(candidate, format)):
        line = bisect_right(starts, start)
        group = (line, kind)
        if group in rows:
            # Keep all grouped values covered when the browser masks the row.
            rows[group]["end"] = max(end, rows[group]["end"])
        else:
            rows[group] = {"line": line, "column": start - starts[line - 1] + 1,
                           "start": start, "end": end, "kind": kind, "reason": "UNMASKED_LABELED_VALUE"}
    return list(rows.values())

"""Source spans for strict JSON and common Markdown structures."""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from html import unescape
import json
import re


class StructureError(Exception):
    """A fixed error code without source text."""


@dataclass(frozen=True)
class Part:
    start: int
    end: int
    kind: str
    value: str = ""
    field: str | None = None


JSON_SPACE = re.compile(r"[ \t\r\n]*")
JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
FENCE = re.compile(r" {0,3}(`{3,}|~{3,})([^\r\n]*)")
LINE = re.compile(r"[^\r\n]*(?:\r\n|\n|\r|$)")
INLINE_SPACE = re.compile(r"[ \t]*")
TABLE_DASHES = re.compile(r"[ \t]*:?-{1,}:?[ \t]*")
MARKDOWN_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
AUTO_LINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]+)>")
BLOCK_MARKER = re.compile(r" {0,3}(?:#{1,6}[ \t]|[-+*][ \t]|[0-9]{1,9}[.)][ \t]|>[ \t]?)")


class JsonSpans:
    def __init__(self, source):
        self.source = source
        self.parts = []
        self.structure = []

    def parse(self):
        end = self.value(0, None, 0)
        if self.skip(end) != len(self.source):
            raise StructureError("INVALID_JSON")
        return self.parts, self.structure

    def skip(self, position):
        return JSON_SPACE.match(self.source, position).end()

    def kind_at(self, position):
        return self.source[position:position + 1]

    def string(self, position):
        try:
            return json.decoder.scanstring(self.source, position + 1)
        except (ValueError, UnicodeError):
            raise StructureError("INVALID_JSON") from None

    def add_part(self, part, marker):
        if len(self.parts) >= 100000:
            raise StructureError("TOO_MANY_FORMAT_TOKENS")
        self.parts.append(part)
        self.structure.append(marker)

    def value(self, position, field, depth):
        if depth > 100:
            raise StructureError("JSON_TOO_DEEP")
        start = self.skip(position)
        char = self.kind_at(start)
        if char == '"':
            value, end = self.string(start)
            self.add_part(Part(start, end, "json_string", value, field), ("string",))
            return end
        if char in ("{", "["):
            return self.container(start, field, depth, char)
        number = JSON_NUMBER.match(self.source, start)
        if number:
            end = number.end()
        else:
            literal = next((word for word in ("true", "false", "null") if self.source.startswith(word, start)), None)
            if literal is None:
                raise StructureError("INVALID_JSON")
            end = start + len(literal)
        value = self.source[start:end]
        self.add_part(Part(start, end, "json_scalar", value, field), ("scalar", value))
        return end

    def container(self, start, field, depth, char):
        close = "}" if char == "{" else "]"
        position = self.skip(start + 1)
        empty = self.kind_at(position) == close
        self.add_part(Part(start, start + 1, "json_container", "" if empty else char, field), (char,))
        seen = set()
        if not empty:
            while True:
                key = None
                if char == "{":
                    if self.kind_at(position) != '"':
                        raise StructureError("INVALID_JSON")
                    key, end = self.string(position)
                    if key in seen:
                        raise StructureError("DUPLICATE_JSON_KEY")
                    seen.add(key)
                    self.add_part(Part(position, end, "json_key", key), ("key", key))
                    position = self.skip(end)
                    if self.kind_at(position) != ":":
                        raise StructureError("INVALID_JSON")
                    position += 1
                position = self.skip(self.value(position, key, depth + 1))
                if self.kind_at(position) == close:
                    break
                if self.kind_at(position) != ",":
                    raise StructureError("INVALID_JSON")
                position = self.skip(position + 1)
        self.structure.append((close,))
        return position + 1


def json_parts(source):
    return JsonSpans(source).parse()


def json_string_offsets(token, decoded):
    """Map decoded character boundaries to source offsets in a parsed string."""
    offsets = []
    index = 1
    end = len(token) - 1
    while index < end:
        offsets.append(index)
        if token[index] != "\\":
            index += 1
        elif token[index + 1] != "u":
            index += 2
        else:
            character = int(token[index + 2:index + 6], 16)
            index += 6
            if (0xD800 <= character <= 0xDBFF and token.startswith("\\u", index)
                    and 0xDC00 <= int(token[index + 2:index + 6], 16) <= 0xDFFF):
                index += 6
    if len(offsets) != len(decoded) or index != end:
        raise StructureError("JSON_POSITION_MAPPING_FAILED")
    return offsets + [end]


def pipes(line):
    indices = []
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            indices.append(index)
    return indices


def cells(row, boundaries):
    values = [row[start + 1:end] for start, end in zip([-1] + boundaries, boundaries + [len(row)])]
    if boundaries and not values[0].strip():
        values.pop(0)
    if boundaries and values and not values[-1].strip():
        values.pop()
    return values


def is_table_header(row, delimiter):
    if "|" not in row or "|" not in delimiter:
        return False
    row_pipes, delim_pipes = pipes(row), pipes(delimiter)
    if not row_pipes or not delim_pipes:
        return False
    format_cells = cells(delimiter, delim_pipes)
    return (bool(format_cells) and len(cells(row, row_pipes)) == len(format_cells)
            and all(TABLE_DASHES.fullmatch(cell) for cell in format_cells))


def link_destination(row, start):
    """Return the destination span and closing location of a same-line inline link."""
    start = INLINE_SPACE.match(row, start).end()
    if row[start:start + 1] == "<":
        end = start + 1
        while end < len(row) and row[end] not in "<> \t":
            end += 2 if row[end] == "\\" and end + 1 < len(row) else 1
        if row[end:end + 1] != ">":
            return None
        dest = start + 1, end
        end += 1
    else:
        end = start
        depth = 0
        while end < len(row) and row[end] not in " \t":
            char = row[end]
            if char == "\\" and end + 1 < len(row):
                end += 2
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                if not depth:
                    break
                depth -= 1
            end += 1
        if depth:
            return None
        dest = start, end
    after = INLINE_SPACE.match(row, end).end()
    title = None
    if after > end and row[after:after + 1] in ('"', "'", "("):
        quote = ")" if row[after] == "(" else row[after]
        title_start = after + 1
        cursor = title_start
        while cursor < len(row) and row[cursor] != quote:
            cursor += 2 if row[cursor] == "\\" and cursor + 1 < len(row) else 1
        if cursor >= len(row):
            return None
        title = title_start, cursor
        after = INLINE_SPACE.match(row, cursor + 1).end()
    if row[after:after + 1] != ")":
        return None
    return dest, title, after + 1


def inline_parts(row, offset):
    """Split only validated syntactic delimiters from text, links and titles."""
    tokens = []
    structure = []
    labels = []
    backticks = {}
    for match in re.finditer(r"`+", row):
        size = match.end() - match.start()
        backticks.setdefault(size, []).append(match.start())
    cursor = 0
    while cursor < len(row):
        char = row[cursor]
        if char == "\\" and cursor + 1 < len(row):
            cursor += 2
            continue
        if char == "`":
            end = cursor
            while row[end:end + 1] == "`":
                end += 1
            size = end - cursor
            positions = backticks.get(size, [])
            later = bisect_right(positions, cursor)
            closed = later < len(positions)
            tokens.append((cursor, end, "marker"))
            structure.append(("code", size, closed))
            if closed:
                end = positions[later] + size
                tokens.append((end - size, end, "marker"))
            cursor = end
            continue
        if char == "[":
            labels.append(cursor)
        elif char == "]" and labels:
            opening = labels.pop()
            if row[cursor + 1:cursor + 2] == "(":
                link = link_destination(row, cursor + 2)
                if link is None:
                    raise StructureError("AMBIGUOUS_MARKDOWN_LINK")
                (start, end), title, after = link
                tokens += [(opening, opening + 1, "marker"), (cursor, start, "marker"), (start, end, "link")]
                if title:
                    tokens += [(end, title[0], "marker"), (*title, "text"), (title[1], after, "marker")]
                else:
                    tokens.append((end, after, "marker"))
                structure.append(("link", row[cursor:start], row[end:title[0] if title else after],
                                  row[title[1]:after] if title else ""))
                cursor = after
                continue
        elif char == "<" and (link := AUTO_LINK.match(row, cursor)):
            start, end = link.span(1)
            tokens += [(cursor, start, "marker"), (start, end, "autolink"), (end, end + 1, "marker")]
            structure.append(("autolink",))
            cursor = end + 1
            continue
        cursor += 1

    parts = []
    cursor = 0
    for start, end, kind in sorted(tokens):
        if start < cursor:
            raise StructureError("AMBIGUOUS_MARKDOWN_LINK")
        if start > cursor:
            parts.append(Part(offset + cursor, offset + start, "text"))
        if kind != "marker" and end > start:
            parts.append(Part(offset + start, offset + end, kind))
        cursor = end
    if cursor < len(row):
        parts.append(Part(offset + cursor, offset + len(row), "text"))
    return parts, structure


def markdown_parts(source):
    lines = [(match.start(), match.group().rstrip("\r\n"), match.end())
             for match in LINE.finditer(source) if match.start() < match.end()]
    parts = []
    structure = []
    index = 0
    in_table = False
    while index < len(lines):
        start, row, end = lines[index]
        fence = FENCE.fullmatch(row)
        if fence:
            in_table = False
            marker, info = fence.groups()
            if marker[0] == "`" and "`" in info:
                raise StructureError("AMBIGUOUS_MARKDOWN_FENCE")
            closing = re.compile(r" {0,3}" + marker[0] + "{" + str(len(marker)) + r",}[ \t]*")
            close = index + 1
            while close < len(lines) and not closing.fullmatch(lines[close][1]):
                close += 1
            if close >= len(lines):
                raise StructureError("UNCLOSED_MARKDOWN_FENCE")
            kind = "json" if info.strip().lower().split(maxsplit=1)[:1] == ["json"] else "code"
            parts.append(Part(start + fence.start(2), start + fence.end(2), "markup"))
            parts.append(Part(end, lines[close][0], kind))
            structure.append(("fence", row, lines[close][1], kind))
            index = close + 1
            continue

        next_line = lines[index + 1][1] if index + 1 < len(lines) else ""
        starts_table = is_table_header(row, next_line)
        separators = pipes(row) if in_table or starts_table else []
        if in_table and (not row.strip() or BLOCK_MARKER.match(row)):
            in_table = False
            separators = []
        flags = []
        for cell_start, cell_end in zip([0] + [p + 1 for p in separators], separators + [len(row)]):
            cell = row[cell_start:cell_end]
            marker = BLOCK_MARKER.match(cell) if not separators else None
            prefix = marker.group() if marker else ""
            cell_parts, cell_flags = inline_parts(cell[len(prefix):], start + cell_start + len(prefix))
            parts.extend(cell_parts)
            flags.append((prefix, tuple(cell_flags)))
        trailing_space = row[len(row.rstrip(" \t")):]
        structure.append(("row", len(separators), trailing_space, tuple(flags)))
        if starts_table:
            structure.append(("table-delimiter", next_line))
            in_table = True
            index += 1
        index += 1
    return parts, structure


def markdown_text(text):
    """Decode common rendered escapes for secondary residual checking."""
    return unescape(MARKDOWN_ESCAPE.sub(r"\1", text))


def splice(source, replacements):
    parts = []
    cursor = 0
    for start, end, value in replacements:
        parts.extend((source[cursor:start], value))
        cursor = end
    parts.append(source[cursor:])
    return "".join(parts)

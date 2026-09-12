"""Stdlib-only YAML-subset reader shared by the ai-data-security evaluators.

Supported: block mappings, block sequences, plain/quoted scalars, single-level flow lists
`[a, b]` and flow mappings `{k: v}`, block scalars (`|`, `>`, with chomping indicators; their text
is kept but never interpreted), `#` comments, a leading `---` document marker. Everything else
(anchors, aliases, tags, nested flow collections, multi-document files, tabs for indentation,
unmatched quotes or brackets, mixed list/map blocks) raises ValueError so the caller fails closed
to UNKNOWN instead of guessing. Never returns a partial parse.
"""

import re

_BLOCK_SCALAR = re.compile(r"^[|>][-+]?\d?$")


def _strip_comment(raw):
    """Cut a trailing ` #comment`, but not inside quotes."""
    if raw.lstrip().startswith("#"):
        return ""
    quote = None
    for i, ch in enumerate(raw):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and i > 0 and raw[i - 1] in (" ", "\t"):
            return raw[:i]
    return raw


def _scalar(s):
    s = s.strip()
    if not s:
        return ""
    if s[0] in ("&", "*", "!"):
        raise ValueError("anchors, aliases, and tags are not supported")
    if s[0] in ("'", '"'):
        if len(s) < 2 or s[-1] != s[0]:
            raise ValueError("unmatched quote")
        inner = s[1:-1]
        if s[0] == '"':
            # the double-quoted escapes that matter for statements: \n \t \\ \" (others kept literally)
            inner = re.sub(r"\\([nt\\\"])", lambda m: {"n": "\n", "t": "\t", "\\": "\\", '"': '"'}[m.group(1)], inner)
        else:
            inner = inner.replace("''", "'")
        return inner
    if s[0] == "[":
        if s[-1] != "]":
            raise ValueError("unmatched [")
        inner = s[1:-1].strip()
        if any(ch in inner for ch in "[]{}"):
            raise ValueError("nested flow collections are not supported")
        return [_scalar(x) for x in inner.split(",")] if inner else []
    if s[0] == "{":
        if s[-1] != "}":
            raise ValueError("unmatched {")
        inner = s[1:-1].strip()
        if any(ch in inner for ch in "[]{}"):
            raise ValueError("nested flow collections are not supported")
        out = {}
        for part in inner.split(",") if inner else []:
            k, sep, v = part.partition(":")
            if not sep:
                raise ValueError("flow mapping entry without ':'")
            out[k.strip().strip("'\"")] = _scalar(v)
        return out
    if s[0] in ("]", "}"):
        raise ValueError("unmatched bracket")
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", "none"):
        return None
    return s


def yaml_subset_load(text):
    lines = []
    for raw in text.splitlines():
        if raw.strip() == "---" and not lines:
            continue
        if raw.strip() in ("---", "..."):
            raise ValueError("multi-document YAML is not supported")
        indent_ws = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in indent_ws:
            raise ValueError("tab indentation")
        stripped = _strip_comment(raw)
        if stripped.strip():
            lines.append((len(indent_ws), stripped.rstrip()))

    def block_scalar(idx, indent):
        """Consume the lines of a `|`/`>` scalar (all deeper than `indent`)."""
        parts = []
        while idx < len(lines) and lines[idx][0] > indent:
            parts.append(lines[idx][1].strip())
            idx += 1
        return "\n".join(parts), idx

    def value_after(key_indent, val, idx):
        """Value for `key: <val>` at line idx (already consumed): scalar, block scalar, or child block."""
        v = val.strip()
        if _BLOCK_SCALAR.match(v):
            return block_scalar(idx + 1, key_indent)
        if v:
            return _scalar(v), idx + 1
        if idx + 1 < len(lines) and lines[idx + 1][0] > key_indent:
            return parse_block(idx + 1, lines[idx + 1][0])
        return None, idx + 1

    def parse_block(idx, indent):
        result = None
        while idx < len(lines):
            ind, line = lines[idx]
            if ind < indent:
                break
            if ind > indent:
                raise ValueError("unexpected indent")
            body = line.strip()
            if body == "-" or body.startswith("- "):
                if result is None:
                    result = []
                if not isinstance(result, list):
                    raise ValueError("mixed list/map")
                item = body[1:].strip()
                if not item:
                    # "-" alone: the item is the following deeper block
                    if idx + 1 < len(lines) and lines[idx + 1][0] > ind:
                        sub, idx = parse_block(idx + 1, lines[idx + 1][0])
                        result.append(sub)
                    else:
                        result.append(None)
                        idx += 1
                    continue
                key, sep, val = item.partition(":")
                if sep and not item.startswith(("'", '"', "[", "{")) and (val == "" or val.startswith(" ")):
                    # list item that is a mapping; continuation keys align with the item's inner indent
                    inner = ind + 2
                    child = {}
                    child[key.strip().strip("'\"")], idx = value_after(ind, val, idx)
                    while idx < len(lines) and lines[idx][0] == inner and not lines[idx][1].strip().startswith("- "):
                        k2, sep2, v2 = lines[idx][1].strip().partition(":")
                        if not sep2 or k2.strip().startswith(("'", '"', "[", "{")) and not k2.strip().endswith(("'", '"')):
                            raise ValueError("expected key")
                        child[k2.strip().strip("'\"")], idx = value_after(inner, v2, idx)
                    result.append(child)
                    continue
                result.append(_scalar(item))
                idx += 1
                continue
            if result is None:
                result = {}
            if not isinstance(result, dict):
                raise ValueError("mixed list/map")
            key, sep, val = body.partition(":")
            if not sep or (val and not val.startswith(" ")):
                raise ValueError("expected key")
            result[key.strip().strip("'\"")], idx = value_after(ind, val, idx)
        return result, idx

    if not lines:
        return {}
    try:
        value, end = parse_block(0, lines[0][0])
    except (IndexError, RecursionError):
        raise ValueError("unsupported YAML shape")
    if end != len(lines):
        raise ValueError("trailing content at an unexpected indent")
    return value if value is not None else {}

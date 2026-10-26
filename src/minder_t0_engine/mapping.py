"""Response mapping for declarative plugins: JMESPath and XML->JSON.

JMESPath (provisional, Q-T7) is non-Turing-complete: no recursion, no loops,
no assignment, so evaluation is bounded by the size of its input, which the
engine caps. A few pure helper functions are added (case, trimming, split,
replace, substrings, arithmetic, object entries, a computed-key lookup);
none performs I/O.

XML is parsed with ``defusedxml`` (no DTDs, entities or external references)
into plain JSON: namespaces are dropped to local names (or, with
``namespaces: keep``, kept as ``{uri}local`` or a declared ``prefix:local``),
attributes become ``@name`` keys, mixed text becomes ``#text``, a repeated
child becomes a list and a leaf element becomes its text. Use JMESPath's
``to_array()`` where a child may occur once or many times.

A body that does not decode as its declared format raises :class:`ParseError`
(``error.kind: parse``); its message never quotes the body.
"""

import json
import math
from typing import Any, Dict, List, Mapping, Optional

import defusedxml.ElementTree as DET
import jmespath
from jmespath import exceptions as jp_exc
from jmespath import functions as jp_fn
from jmespath.parser import ParsedResult

from .errors import ManifestError, MappingError, ParseError

#: Deepest XML nesting accepted (parsing recurses once per level).
MAX_XML_DEPTH = 64

#: Most items ``chars()`` / ``words()`` return; a longer input fails the
#: mapping instead of amplifying one string into a huge list.
MAX_LIST_ITEMS = 10_000


def _index(value: Any) -> int:
    """A ``substr`` index: an integral number (``2`` or ``2.0``); never a
    bool, NaN, infinity or fraction. Python slicing clamps any magnitude, so
    a huge or negative index costs nothing."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("substr index must be a number")
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            raise ValueError("substr index must be an integer")
        return int(value)
    return value


class _Functions(jp_fn.Functions):
    """Pure helpers on top of the JMESPath built-ins."""

    @jp_fn.signature({"types": ["string"]})
    def _func_upper(self, s: str) -> str:
        return s.upper()

    @jp_fn.signature({"types": ["string"]})
    def _func_lower(self, s: str) -> str:
        return s.lower()

    @jp_fn.signature({"types": ["string"]})
    def _func_trim(self, s: str) -> str:
        return s.strip()

    @jp_fn.signature({"types": ["string"]}, {"types": ["string"]})
    def _func_split(self, s: str, sep: str) -> List[str]:
        if not sep:
            return [s]
        return [p.strip() for p in s.split(sep) if p.strip()]

    @jp_fn.signature(
        {"types": ["string"]}, {"types": ["string"]}, {"types": ["string"]}
    )
    def _func_replace(self, s: str, old: str, new: str) -> str:
        return s.replace(old, new) if old else s

    # jmespath's variadic marker means "one or more" and type-checks only the
    # first, so the optional end index is validated by _index() here.
    @jp_fn.signature({"types": ["string"]}, {"types": ["number"], "variadic": True})
    def _func_substr(self, s: str, start: Any, *end: Any) -> str:
        """``substr(s, start, end?)``: ``s[start:end]`` with Python slice
        semantics on code points (negative indices count from the end,
        out-of-range ones clamp)."""
        if len(end) > 1:
            raise ValueError("substr takes 2 or 3 arguments")
        stop = _index(end[0]) if end else None
        return s[_index(start) : stop]

    @jp_fn.signature({"types": ["string"]})
    def _func_chars(self, s: str) -> List[str]:
        """The code points of ``s``, each a one-character string (Python's
        ``list(s)``)."""
        if len(s) > MAX_LIST_ITEMS:
            raise ValueError("chars input too long")
        return list(s)

    @jp_fn.signature({"types": ["string"]})
    def _func_words(self, s: str) -> List[str]:
        """``s`` split on runs of any whitespace, none empty (Python's
        ``s.split()``): ``join(' ', words(s))`` collapses whitespace."""
        parts = s.split()
        if len(parts) > MAX_LIST_ITEMS:
            raise ValueError("words output too long")
        return parts

    @jp_fn.signature({"types": ["number"]}, {"types": ["number"]})
    def _func_multiply(self, a: float, b: float) -> float:
        return a * b

    @jp_fn.signature({"types": ["number"]}, {"types": ["number"]})
    def _func_divide(self, a: float, b: float) -> Optional[float]:
        return None if b == 0 else a / b

    @jp_fn.signature({"types": ["number"]}, {"types": ["number"]})
    def _func_round(self, a: float, digits: float) -> float:
        return round(a, max(0, min(int(digits), 12)))

    @jp_fn.signature({"types": ["object"]})
    def _func_entries(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{"key": k, "value": v} for k, v in obj.items()]

    @jp_fn.signature({"types": ["object"]}, {"types": ["string"]})
    def _func_get(self, obj: Dict[str, Any], key: str) -> Any:
        """``obj[key]`` for a key computed at run time (``get(steps.r.rates,
        upper(params.to))``), or null when absent."""
        return obj.get(key)

    @jp_fn.signature({"types": ["string"]})
    def _func_parse_number(self, s: str) -> Optional[float]:
        try:
            value = float(s.strip())
        except ValueError:
            return None
        return value if value == value and abs(value) != float("inf") else None


_OPTIONS = jmespath.Options(custom_functions=_Functions())


def compile_expr(expr: str, where: str) -> ParsedResult:
    """Compile a JMESPath expression at manifest load."""
    if not isinstance(expr, str) or not expr.strip():
        raise ManifestError(f"{where}: must be a non-empty JMESPath expression")
    try:
        return jmespath.compile(expr)
    except jp_exc.JMESPathError as e:
        raise ManifestError(f"{where}: invalid JMESPath ({type(e).__name__})") from None


def search(compiled: ParsedResult, data: Any) -> Any:
    try:
        return compiled.search(data, options=_OPTIONS)
    except jp_exc.JMESPathError as e:
        raise MappingError(f"mapping failed ({type(e).__name__})") from None
    except (TypeError, ValueError, OverflowError):
        raise MappingError("mapping failed") from None


def _local(tag: Any) -> str:
    name = str(tag)
    if name.startswith("{"):
        name = name.split("}", 1)[-1]
    return name.split(":", 1)[-1]


class _Names:
    """How XML element and attribute names become JSON keys."""

    def __init__(self, keep: bool, prefixes: Optional[Mapping[str, str]]) -> None:
        self.keep = keep
        self.prefixes = dict(prefixes or {})  # namespace URI -> prefix

    def __call__(self, tag: Any) -> str:
        if not self.keep:
            return _local(tag)
        name = str(tag)
        if name.startswith("{") and "}" in name:
            uri, local = name[1:].split("}", 1)
            prefix = self.prefixes.get(uri)
            return f"{prefix}:{local}" if prefix else name
        return name


def _element(elem: Any, depth: int, names: _Names) -> Any:
    if depth > MAX_XML_DEPTH:
        raise ParseError("XML nested too deeply")
    obj: Dict[str, Any] = {}
    for key, value in elem.attrib.items():
        obj[f"@{names(key)}"] = value
    children: Dict[str, List[Any]] = {}
    for child in elem:
        if not isinstance(child.tag, str):
            continue  # comments and processing instructions
        children.setdefault(names(child.tag), []).append(
            _element(child, depth + 1, names)
        )
    for name, values in children.items():
        # Attribute keys start with "@", which no element name can.
        obj[name] = values[0] if len(values) == 1 else values
    text = (elem.text or "").strip()
    if not obj:
        return text
    if text:
        obj["#text"] = text
    return obj


def xml_to_json(
    content: bytes,
    namespaces: str = "drop",
    prefixes: Optional[Mapping[str, str]] = None,
) -> Any:
    """``{root_name: value}`` for an XML document; raises ParseError.

    With ``namespaces="keep"`` a namespaced name is keyed ``prefix:local``
    when its URI is in ``prefixes`` (URI -> prefix), else ``{uri}local``;
    a name in no namespace stays bare. The default drops namespaces."""
    try:
        root = DET.fromstring(content, forbid_dtd=True)
    except Exception as e:  # ParseError, defusedxml's Forbidden* and friends
        raise ParseError(f"response is not acceptable XML ({type(e).__name__})")
    names = _Names(namespaces == "keep", prefixes)
    return {names(root.tag): _element(root, 0, names)}


def parse_body(
    content: bytes,
    fmt: str,
    encoding: str = "utf-8",
    *,
    empty_body: str = "null",
    namespaces: str = "drop",
    prefixes: Optional[Mapping[str, str]] = None,
) -> Any:
    """Decode a response body as its declared format (json, xml or text).

    An empty or whitespace-only body maps to null for JSON (``""`` for text,
    a ParseError for XML) unless ``empty_body="error"``, which makes it a
    ParseError for every format."""
    if empty_body == "error" and not content.strip():
        raise ParseError("response body is empty")
    if fmt == "xml":
        return xml_to_json(content, namespaces, prefixes)
    if fmt == "text":
        return content.decode(encoding or "utf-8", errors="replace")
    if not content.strip():
        return None
    try:
        return json.loads(content)
    except ValueError:
        raise ParseError("response is not valid JSON") from None

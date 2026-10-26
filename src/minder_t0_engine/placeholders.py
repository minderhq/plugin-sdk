"""Minimal placeholder substitution for declarative requests.

This is deliberately **not** a template language: a placeholder is ``{path}``
where ``path`` is a dotted reference (``params.topic``, ``config.WIKI_LANG``,
``item.key``, ``steps.search.0.id``, ``vars.base``) into the invocation
context. There are no expressions, filters, conditionals or loops (a value
that needs one is a declared ``vars`` entry, a JMESPath mapping over params
and config). ``{{`` and ``}}`` are literal braces.

Every substituted value is encoded for the URL component it lands in:

- ``HOST_LABEL``: a whole DNS label only, ``[a-z0-9-]``, 1-63 characters. The
  resulting host is still checked against the plugin's egress allowlist. A
  host placeholder (and only a host placeholder) may declare a fallback label,
  ``{config.WIKI_LANG|en}``: the fallback must itself be a valid label (checked
  at load) and replaces a value that is missing, empty or not a valid label, so
  a bad config value degrades to the declared label instead of failing. It
  never loosens the check: the value is either a whole valid label or unused.
- ``PATH``: percent-encoded with nothing kept (``/``, ``?``, ``#`` and ``%``
  become escapes); ``.`` and ``..`` are encoded too, so a value can never
  add a path segment or walk up one.
- ``QUERY`` / ``FORM``: the raw string, which httpx encodes as a parameter
  value.
- ``HEADER``: the raw string; CR, LF and other control characters are refused.
- ``JSON``: a string leaf; a leaf that is exactly one placeholder keeps the
  value's JSON type.

The context never holds a secret (the engine injects auth itself), so no
placeholder can read one.
"""

import re
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import quote

from .errors import ManifestError, MappingError

#: The roots a placeholder may reference. ``vars`` are an operation's
#: declared values, mapped from its params and config before its steps.
ROOTS = frozenset({"params", "config", "item", "steps", "vars"})

HOST_LABEL = "host"
PATH = "path"
QUERY = "query"
FORM = "form"
HEADER = "header"
JSON = "json"

_SEGMENT = r"(?:[A-Za-z_][A-Za-z0-9_\-]*|[0-9]+)"
_REF = re.compile(rf"^{_SEGMENT}(?:\.{_SEGMENT})*$")
_TOKEN = re.compile(r"\{\{|\}\}|\{([^{}]*)\}|[{}]")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "MISSING"


#: A reference that does not resolve (or resolves to null).
MISSING: Any = _Missing()


@dataclass(frozen=True)
class Ref:
    """One placeholder: its dotted path, split."""

    path: Tuple[str, ...]
    #: A host placeholder's declared fallback label (``{config.X|en}``).
    default: Optional[str] = None

    @property
    def root(self) -> str:
        return self.path[0]

    def __str__(self) -> str:
        return ".".join(self.path)


Part = Union[str, Ref]


@dataclass(frozen=True)
class Template:
    """A parsed template string: literal text and references, in order."""

    parts: Tuple[Part, ...]

    @property
    def refs(self) -> List[Ref]:
        return [p for p in self.parts if isinstance(p, Ref)]

    @property
    def single(self) -> Optional[Ref]:
        """The reference when the template is exactly one placeholder."""
        if len(self.parts) == 1 and isinstance(self.parts[0], Ref):
            return self.parts[0]
        return None

    @property
    def is_literal(self) -> bool:
        return not self.refs

    def literal(self) -> str:
        return "".join(p for p in self.parts if isinstance(p, str))


def parse(text: str, where: str, allow_default: bool = False) -> Template:
    """Parse ``text``; raises :class:`ManifestError` naming ``where``.

    ``allow_default`` admits a ``{ref|label}`` fallback (host labels only)."""
    if not isinstance(text, str):
        raise ManifestError(f"{where}: must be a string")
    parts: List[Part] = []
    buf: List[str] = []
    pos = 0
    for m in _TOKEN.finditer(text):
        buf.append(text[pos : m.start()])
        pos = m.end()
        token = m.group(0)
        if token == "{{":
            buf.append("{")
        elif token == "}}":
            buf.append("}")
        elif m.group(1) is None:
            raise ManifestError(f"{where}: unbalanced '{token}' (use '{token * 2}')")
        else:
            ref = m.group(1).strip()
            default: Optional[str] = None
            if allow_default and "|" in ref:
                ref, _, fallback = (x.strip() for x in ref.partition("|"))
                if not _LABEL.match(fallback):
                    raise ManifestError(
                        f"{where}: a host placeholder's fallback must be a "
                        "lower-case DNS label"
                    )
                default = fallback
            if not _REF.match(ref):
                raise ManifestError(
                    f"{where}: '{{{m.group(1)}}}' is not a dotted reference "
                    "(no expressions in placeholders)"
                )
            segments = tuple(ref.split("."))
            if segments[0] not in ROOTS:
                raise ManifestError(
                    f"{where}: placeholder root {segments[0]!r} is not one of "
                    f"{sorted(ROOTS)}"
                )
            if buf and "".join(buf):
                parts.append("".join(buf))
            buf = []
            parts.append(Ref(segments, default))
    buf.append(text[pos:])
    if "".join(buf):
        parts.append("".join(buf))
    return Template(tuple(parts))


def lookup(context: Mapping[str, Any], ref: Ref) -> Any:
    """The value ``ref`` names in ``context``, or :data:`MISSING`."""
    value: Any = context
    for seg in ref.path:
        if isinstance(value, Mapping):
            if seg not in value:
                return MISSING
            value = value[seg]
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            if not seg.isdigit() or int(seg) >= len(value):
                return MISSING
            value = value[int(seg)]
        else:
            return MISSING
    return MISSING if value is None else value


def _scalar(value: Any, ref: Ref) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    raise MappingError(f"placeholder {{{ref}}} is not a scalar value")


def literal_text(value: Any) -> str:
    """A manifest's non-string literal (a query value ``10`` or ``true``) as
    the text it is sent as."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _encode(value: str, ref: Ref, component: str) -> str:
    if component == HOST_LABEL:
        label = value.strip().lower()
        if not _LABEL.match(label):
            raise MappingError(f"placeholder {{{ref}}} is not a valid host label")
        return label
    if component == PATH:
        if value in (".", ".."):
            return value.replace(".", "%2E")
        return quote(value, safe="")
    if component == HEADER and _CONTROL.search(value):
        raise MappingError(f"placeholder {{{ref}}} has control characters")
    return value


def _host_label_or_default(value: Any, ref: Ref, default: str) -> str:
    """``value`` as a host label, or the reference's declared fallback when
    it is missing, not a scalar or not a valid label."""
    if value is MISSING or isinstance(value, bool):
        return default
    try:
        return _encode(_scalar(value, ref), ref, HOST_LABEL)
    except MappingError:
        return default


def render(
    template: Template, context: Mapping[str, Any], component: str
) -> Optional[str]:
    """Render ``template`` as a string for ``component``.

    Returns None when the template is exactly one placeholder that is missing
    (the caller drops an optional query parameter, header or JSON key). A
    missing reference inside a larger string is an error, and so is any
    missing reference in a host or a path."""
    out: List[str] = []
    for part in template.parts:
        if isinstance(part, str):
            out.append(part)
            continue
        value = lookup(context, part)
        if component == HOST_LABEL and part.default is not None:
            out.append(_host_label_or_default(value, part, part.default))
            continue
        if value is MISSING:
            if template.single is not None and component not in (HOST_LABEL, PATH):
                return None
            raise MappingError(f"placeholder {{{part}}} has no value")
        out.append(_encode(_scalar(value, part), part, component))
    return "".join(out)


def render_json(template: Template, context: Mapping[str, Any]) -> Any:
    """A JSON body leaf: a lone placeholder keeps its value's type (MISSING if
    absent, so the caller drops the key); otherwise a rendered string."""
    single = template.single
    if single is not None:
        return lookup(context, single)
    return render(template, context, JSON)

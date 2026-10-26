"""Credentials embedded in a URL's userinfo (``user:pass@host``).

A URL like ``https://x-access-token:<token>@github.com/org/repo`` carries a
secret in its authority. It must never be stored, returned or logged. These two
stdlib-only helpers are the single rule for that, shared by the marketplace
catalog (``repository_url`` / screenshot URLs) and the plugin registry's git
install guard:

- :func:`has_userinfo` says whether a URL carries userinfo. Use it to reject
  input.
- :func:`strip_userinfo` removes it and leaves everything else as given. Use it
  to sanitise a stored value on read, in a backfill, or before logging.

The check is deliberately **conservative**: URL parsers disagree on where the
authority ends, and an attacker can use that. Python's ``urlsplit`` ends it at
the first ``/``, ``?`` or ``#``, while browsers (the WHATWG URL standard) also
end it at ``\\`` for http(s), and accept ``https:\\\\host`` or ``https:host`` as
``https://host``. So here the authority starts after ``scheme:`` plus any run of
``/`` and ``\\`` (for the WHATWG special schemes; other schemes need a literal
``//``), and ends at the first ``/``, ``?`` or ``#``. A backslash therefore does
not end it, which catches ``https://github.com\\@evil.com``. Any ``@`` in that
span, or a percent-encoded ``%40``, counts as userinfo.

ASCII tab and newline are removed and leading/trailing C0 controls and spaces
are trimmed first, as a browser does, so they can't hide an ``@``.

A protocol-relative ``//u:tok@host/x`` (or ``\\\\host``) has its authority
right after the leading slashes and is treated exactly like a schemed URL.

Any other value with no usable ``scheme://`` is checked as a **scheme-less** URL, so
``x-access-token:<token>@github.com/org/repo`` or ``user@github.com/org/repo``
is caught too. Its authority is everything up to the first ``/``, ``?`` or
``#`` (again not ``\\``). It counts as userinfo when that span has no
whitespace, holds an ``@`` (or ``%40``), and either the part before the ``@``
has a ``:`` (``user:token``) or a path, query or fragment follows. That keeps a bare e-mail address
(``dev@example.com``), ``mailto:`` and free text from being treated as a URL,
and an ``@`` in a path (``github.com/o/r@v1``) is never in the authority.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

# WHATWG "special" schemes: their authority may follow any run of / or \.
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "file"})
# Schemes whose ``scheme:x@y`` is not a credential (``mailto:dev@example.com``).
_NON_HIERARCHICAL_SCHEMES = frozenset(
    {"mailto", "urn", "xmpp", "sip", "sips", "im", "pres", "news", "tel", "data"}
)
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")
_AUTHORITY_END = re.compile(r"[/?#]")
_WHITESPACE = re.compile(r"\s")
_PROTOCOL_RELATIVE = frozenset({"//", "\\\\", "/\\", "\\/"})
_TAB_NEWLINE = str.maketrans("", "", "\t\n\r")
_C0_AND_SPACE = "".join(chr(c) for c in range(0x21))
_ENCODED_AT = "%40"


def _split(url: str) -> Optional[Tuple[Optional[str], str, str]]:
    """``(scheme, authority, tail)`` of a URL, else ``None``.

    ``scheme`` is ``""`` for a protocol-relative URL (``//host/...``) and
    ``None`` for a scheme-less one. ``tail`` is everything after the authority
    (path, query, fragment)."""
    normalized = url.translate(_TAB_NEWLINE).strip(_C0_AND_SPACE)
    if normalized[:2] in _PROTOCOL_RELATIVE:
        # "//u:tok@host/x" (or a backslash form, which a browser reads the same
        # way against an http(s) base): an authority exactly like a schemed URL.
        rest = normalized.lstrip("/\\")
        end = _AUTHORITY_END.search(rest)
        cut = end.start() if end else len(rest)
        return "", rest[:cut], rest[cut:]
    match = _SCHEME.match(normalized)
    if match is not None:
        scheme = match.group()[:-1]
        rest = normalized[match.end() :]
        if scheme.lower() in _SPECIAL_SCHEMES:
            rest = rest.lstrip("/\\")
        elif rest.startswith("//"):
            rest = rest[2:]
        else:
            rest = ""  # no authority; may still be scheme-less (see below)
        if rest:
            end = _AUTHORITY_END.search(rest)
            cut = end.start() if end else len(rest)
            return scheme, rest[:cut], rest[cut:]
        if scheme.lower() in _NON_HIERARCHICAL_SCHEMES:
            return None
    return _split_schemeless(normalized)


def _split_schemeless(value: str) -> Optional[Tuple[Optional[str], str, str]]:
    """``(None, authority, tail)`` when ``value`` looks like a scheme-less URL
    with userinfo (``user:token@host/...``), else ``None``."""
    end = _AUTHORITY_END.search(value)
    cut = end.start() if end else len(value)
    authority, tail = value[:cut], value[cut:]
    userinfo_end = _userinfo_end(authority)
    if userinfo_end == 0 or _WHITESPACE.search(authority):
        return None
    if ":" in authority[:userinfo_end] or tail:
        return None, authority, tail
    return None  # a bare "name@domain": an e-mail address, not a URL


def _userinfo_end(authority: str) -> int:
    """Index just past the userinfo in ``authority`` (0 when there is none)."""
    at = authority.rfind("@")
    encoded = authority.lower().rfind(_ENCODED_AT)
    return max(at + 1 if at >= 0 else 0, encoded + 3 if encoded >= 0 else 0)


def has_userinfo(url: object) -> bool:
    """True if ``url`` is a string whose authority carries userinfo, in any form:
    ``user@``, ``user:pass@``, ``:token@``, an empty ``@``, ``%40``, the
    backslash trick, a protocol-relative ``//user:token@host`` or a scheme-less
    ``user:token@host/...``. Non-strings, e-mail
    addresses and URLs without an authority are False."""
    if not isinstance(url, str):
        return False
    parts = _split(url)
    return parts is not None and _userinfo_end(parts[1]) > 0


def strip_userinfo(url: str) -> str:
    """``url`` without its userinfo. Never raises.

    A URL without userinfo is returned unchanged, character for character, so
    this is idempotent and safe to apply to every value. When userinfo is
    removed, the result is rebuilt as ``scheme://host...`` with the path, query
    and fragment kept as given."""
    parts = _split(url) if isinstance(url, str) else None
    if parts is None:
        return url
    scheme, authority, tail = parts
    end = _userinfo_end(authority)
    if end == 0:
        return url
    if scheme is None:
        prefix = ""  # scheme-less
    elif scheme == "":
        prefix = "//"  # protocol-relative
    else:
        prefix = f"{scheme}://"
    return f"{prefix}{authority[end:]}{tail}"


__all__ = ["has_userinfo", "strip_userinfo"]

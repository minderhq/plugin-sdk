"""Tool effect classes: what an ``AI_TOOLS`` entry does when it is called.

Minder runs a ``read`` tool straight away and pauses a tool that changes or
sends data until the user approves the call. Each ``AI_TOOLS`` entry (the
AI-callable surface of one of the plugin's ``ACTIONS``) therefore declares what
it does. Every field is optional in this release; an undeclared tool is
classified by Minder from its name, method and arguments, and a tool it cannot
classify is treated as ``write``.

``effect`` (str)
    One of :data:`EFFECTS`, least to most consequential:

    * ``read``: no side effects (lookups, searches, calculations);
    * ``write``: changes data inside the user's own systems (create, update);
    * ``send``: data leaves to a third party or a recipient (a message, an
      email, a webhook, a publish);
    * ``destructive``: deletes, or changes something irreversibly (including
      moving money).

    Declare the most consequential thing the tool can do.

``idempotent`` (bool)
    Calling the tool twice with the same arguments has the same effect as
    calling it once.

``sensitivity`` (str, per argument, inside ``parameters.properties``)
    What an argument carries: ``recipient`` (who receives data), ``url`` (a
    URL the tool connects to), ``amount`` (money or a quantity),
    ``free_text`` (text written by the model), or ``bound:<attr>`` (the value
    must equal the named attribute of the current user, e.g.
    ``bound:email``). Minder strips it from the schema it hands to the model.
    A tool-level ``sensitivities`` mapping (``{"<arg>": "<sensitivity>"}``)
    is accepted as an alternative.

``hosts`` (list of str)
    The egress hosts the tool may reach (``api.example.com``, or
    ``*.example.com`` for any subdomain).

``check_plugin`` reports invalid values as errors (:func:`tool_effect_errors`);
:func:`tool_effect_warnings` (via ``check_plugin_warnings``) reports a missing
``effect`` and a declaration that strong evidence contradicts.
:func:`mcp_annotations` maps an effect to MCP tool annotations.
"""

import re
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple, TypedDict

from .declarations import is_host_pattern

__all__ = [
    "Effect",
    "READ",
    "WRITE",
    "SEND",
    "DESTRUCTIVE",
    "EFFECTS",
    "SENSITIVITIES",
    "BOUND_PREFIX",
    "AIToolSpec",
    "is_valid_sensitivity",
    "suggest_effect",
    "tool_effect_errors",
    "tool_effect_warnings",
    "mcp_annotations",
    "tool_annotations",
]

Effect = Literal["read", "write", "send", "destructive"]

READ: Effect = "read"
WRITE: Effect = "write"
SEND: Effect = "send"
DESTRUCTIVE: Effect = "destructive"

#: Effect classes, least to most consequential.
EFFECTS: Tuple[str, ...] = (READ, WRITE, SEND, DESTRUCTIVE)
_RANK = {effect: rank for rank, effect in enumerate(EFFECTS)}

#: Per-argument sensitivities (plus ``bound:<attr>``, see :data:`BOUND_PREFIX`).
SENSITIVITIES: Tuple[str, ...] = ("recipient", "url", "amount", "free_text")
BOUND_PREFIX = "bound:"


class AIToolSpec(TypedDict, total=False):
    """One ``AI_TOOLS`` entry. ``name`` and ``action`` are required by
    ``check_plugin``; the rest is optional."""

    name: str
    description: str
    parameters: Dict[str, Any]
    action: str
    method: str
    effect: Effect
    idempotent: bool
    hosts: List[str]
    sensitivities: Dict[str, str]


def is_valid_sensitivity(value: Any) -> bool:
    """``recipient`` / ``url`` / ``amount`` / ``free_text`` / ``bound:<attr>``."""
    if not isinstance(value, str):
        return False
    if value.startswith(BOUND_PREFIX):
        return len(value) > len(BOUND_PREFIX)
    return value in SENSITIVITIES


def _stricter(*effects: Optional[str]) -> Optional[str]:
    present = [e for e in effects if e in _RANK]
    return max(present, key=_RANK.__getitem__) if present else None


def _properties(tool: Mapping[str, Any]) -> Dict[str, Any]:
    params = tool.get("parameters")
    props = params.get("properties") if isinstance(params, dict) else None
    return props if isinstance(props, dict) else {}


def _sensitivity_sources(tool: Mapping[str, Any]) -> List[Tuple[str, Any]]:
    sources: List[Tuple[str, Any]] = []
    declared = tool.get("sensitivities")
    if isinstance(declared, dict):
        sources += [(str(k), v) for k, v in declared.items()]
    for arg, spec in _properties(tool).items():
        if isinstance(spec, dict) and "sensitivity" in spec:
            sources.append((str(arg), spec["sensitivity"]))
    return sources


# ── evidence rules (deterministic; the strong rules Minder applies) ──────────

#: Verb -> effect, matched against the tokens of the tool and action names.
#: The leading token decides when it is a known verb ("get_update_status" is a
#: read); otherwise the first known verb later in the name does
#: ("crm_contact_update"), except the words in :data:`_LEADING_ONLY`.
_NAME_VERBS: Dict[str, str] = {
    **dict.fromkeys(
        (
            "delete",
            "remove",
            "destroy",
            "drop",
            "purge",
            "wipe",
            "erase",
            "revoke",
            "terminate",
            "truncate",
            "uninstall",
            # Money leaves the account and can't be pulled back.
            "pay",
            "transfer",
            "charge",
            "withdraw",
            "refund",
        ),
        DESTRUCTIVE,
    ),
    **dict.fromkeys(
        (
            "send",
            "notify",
            "publish",
            "broadcast",
            "tweet",
            "reply",
            "forward",
            "post",
            "email",
            "mail",
            "message",
            "sms",
            "invite",
            "share",
            "push",
        ),
        SEND,
    ),
    **dict.fromkeys(
        (
            "create",
            "add",
            "update",
            "set",
            "edit",
            "modify",
            "write",
            "insert",
            "upsert",
            "save",
            "put",
            "patch",
            "enable",
            "disable",
            "start",
            "stop",
            "restart",
            "reload",
            "apply",
            "assign",
            "move",
            "rename",
            "upload",
            "import",
            "sync",
            "register",
            "configure",
            "toggle",
            "approve",
            "reject",
            "close",
            "open",
            "archive",
            "restore",
            "submit",
            "book",
            "order",
            "schedule",
            "trigger",
            "run",
            "execute",
            "install",
            "reset",
            "mark",
            "change",
            "clear",
        ),
        WRITE,
    ),
    **dict.fromkeys(
        (
            "get",
            "list",
            "search",
            "find",
            "read",
            "fetch",
            "query",
            "lookup",
            "show",
            "describe",
            "check",
            "count",
            "view",
            "analyze",
            "analyse",
            "ask",
            "summarize",
            "summarise",
            "explain",
            "inspect",
            "compare",
            "calculate",
            "forecast",
            "predict",
            "recommend",
            "retrieve",
            "browse",
            "preview",
            "ping",
        ),
        READ,
    ),
}

#: Verbs that are also common nouns or adjectives ("ticket_email",
#: "order_status"); they count only as the leading token.
_LEADING_ONLY = frozenset(
    {
        "post",
        "email",
        "mail",
        "message",
        "sms",
        "invite",
        "share",
        "push",
        "put",
        "start",
        "stop",
        "move",
        "sync",
        "close",
        "open",
        "book",
        "order",
        "schedule",
        "trigger",
        "run",
        "mark",
        "change",
        "clear",
        "set",
        "transfer",
        "charge",
        "refund",
        "drop",
        "reply",
        "forward",
        "restore",
        "archive",
        "count",
        "check",
        "view",
        "preview",
        "forecast",
    }
    | {verb for verb, effect in _NAME_VERBS.items() if effect == READ}
)

#: HTTP methods that decide the class on their own. ``POST`` / ``PUT`` /
#: ``PATCH`` are weak (every action defaults to ``POST``), so they never
#: contradict a declaration.
_STRONG_METHODS: Dict[str, str] = {
    "GET": READ,
    "HEAD": READ,
    "OPTIONS": READ,
    "DELETE": DESTRUCTIVE,
}

#: Argument names that only ever carry a recipient or an outbound target.
_STRONG_ARGUMENTS: Dict[str, str] = dict.fromkeys(
    (
        "to",
        "recipient",
        "recipients",
        "cc",
        "bcc",
        "destination",
        "webhook",
        "webhook_url",
        "callback",
        "callback_url",
    ),
    SEND,
)

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^a-z0-9]+")


def _name_verb(name: Any) -> Optional[str]:
    if not isinstance(name, str):
        return None
    tokens = [t for t in _SPLIT.split(_CAMEL.sub("_", name).lower()) if t]
    if not tokens:
        return None
    if tokens[0] in _NAME_VERBS:
        return tokens[0]
    for token in tokens[1:]:
        if token in _NAME_VERBS and token not in _LEADING_ONLY:
            return token
    return None


def _strong_evidence(tool: Mapping[str, Any]) -> List[Tuple[str, str]]:
    """``(signal, effect)`` for every strong rule that fires, in a stable
    order. Strong evidence decides the suggested class and can contradict a
    declaration."""
    evidence: List[Tuple[str, str]] = []
    method = tool.get("method")
    method = method.upper() if isinstance(method, str) and method else "POST"
    if method in _STRONG_METHODS:
        evidence.append((f"method {method}", _STRONG_METHODS[method]))
    names = [("tool name", tool.get("name"))]
    if tool.get("action") != tool.get("name"):
        names.append(("action", tool.get("action")))
    for label, name in names:
        verb = _name_verb(name)
        if verb is not None:
            evidence.append((f"{label} verb {verb!r}", _NAME_VERBS[verb]))
    for arg in sorted(_properties(tool)):
        effect = _STRONG_ARGUMENTS.get(arg.lower())
        if effect:
            evidence.append((f"argument {arg!r}", effect))
    for arg, value in sorted(_sensitivity_sources(tool)):
        if value == "recipient":
            evidence.append((f"argument {arg!r} sensitivity 'recipient'", SEND))
    return evidence


def suggest_effect(tool: Mapping[str, Any]) -> Optional[str]:
    """The class strong evidence suggests for ``tool`` (the most consequential
    one), or ``None`` when no strong rule fires."""
    return _stricter(*(effect for _signal, effect in _strong_evidence(tool)))


# ── checks ───────────────────────────────────────────────────────────────────


def _tools(plugin: Any) -> List[Mapping[str, Any]]:
    return [t for t in getattr(plugin, "AI_TOOLS", []) or [] if isinstance(t, dict)]


def tool_effect_errors(plugin: Any) -> List[str]:
    """Invalid effect declarations on the plugin's ``AI_TOOLS`` (empty: ok).
    Absent fields are not errors."""
    errors: List[str] = []
    for tool in _tools(plugin):
        name = tool.get("name", "<unnamed>")
        effect = tool.get("effect")
        if effect is not None and effect not in _RANK:
            errors.append(
                f"tool {name!r} effect {effect!r} must be one of {', '.join(EFFECTS)}"
            )
        idempotent = tool.get("idempotent")
        if idempotent is not None and not isinstance(idempotent, bool):
            errors.append(f"tool {name!r} 'idempotent' must be a bool")
        declared = tool.get("sensitivities")
        if declared is not None and not isinstance(declared, dict):
            errors.append(f"tool {name!r} 'sensitivities' must map argument names")
        for arg, value in _sensitivity_sources(tool):
            if not is_valid_sensitivity(value):
                errors.append(
                    f"tool {name!r} argument {arg!r} sensitivity {value!r} must be "
                    f"one of {', '.join(SENSITIVITIES)} or {BOUND_PREFIX}<attr>"
                )
        hosts = tool.get("hosts")
        if hosts is not None:
            if not isinstance(hosts, (list, tuple)):
                errors.append(f"tool {name!r} 'hosts' must be a list of host names")
            else:
                for host in hosts:
                    if not is_host_pattern(host):
                        errors.append(
                            f"tool {name!r} host {host!r} must be a lowercase host "
                            "name or *.domain pattern (no scheme, port or path)"
                        )
    return errors


def tool_effect_warnings(plugin: Any) -> List[str]:
    """Non-fatal findings on the plugin's ``AI_TOOLS``: a tool without
    ``effect``, a sensitivity on an argument the schema doesn't define, and a
    declared ``effect`` that strong evidence contradicts (evidence stricter
    than the declaration, e.g. ``read`` with a ``recipient`` argument, or a
    ``send_*`` / ``delete_*`` tool declared ``read``)."""
    warnings: List[str] = []
    for tool in _tools(plugin):
        name = tool.get("name", "<unnamed>")
        effect = tool.get("effect")
        if effect is None:
            warnings.append(
                f"tool {name!r} declares no 'effect' ({', '.join(EFFECTS)}); "
                "Minder will infer one and treats a tool it cannot classify as "
                "'write' (needs user approval)"
            )
        props = _properties(tool)
        declared = tool.get("sensitivities")
        if isinstance(declared, dict):
            for arg in declared:
                if arg not in props:
                    warnings.append(
                        f"tool {name!r} declares a sensitivity for {arg!r}, "
                        "which is not one of its parameters"
                    )
        if effect not in _RANK:
            continue
        for signal, evidence in _strong_evidence(tool):
            if _RANK[evidence] > _RANK[effect]:
                warnings.append(
                    f"tool {name!r} is declared {effect!r} but its {signal} "
                    f"suggests {evidence!r}; Minder flags the contradiction and "
                    f"may treat it as {evidence!r}"
                )
    return warnings


# ── MCP tool annotations ─────────────────────────────────────────────────────

_MCP_ANNOTATIONS: Dict[str, Dict[str, bool]] = {
    READ: {"readOnlyHint": True, "destructiveHint": False},
    WRITE: {"readOnlyHint": False, "destructiveHint": False},
    SEND: {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
    DESTRUCTIVE: {"readOnlyHint": False, "destructiveHint": True},
}


def mcp_annotations(
    effect: Optional[str], idempotent: Optional[bool] = None
) -> Dict[str, bool]:
    """MCP tool annotations (``readOnlyHint``, ``destructiveHint``,
    ``openWorldHint``, ``idempotentHint``) for an effect class.

    ``None`` (undeclared) gives no effect hints, so MCP clients fall back to
    their conservative defaults. An unknown effect raises ``ValueError``."""
    if effect is None:
        hints: Dict[str, bool] = {}
    elif effect in _MCP_ANNOTATIONS:
        hints = dict(_MCP_ANNOTATIONS[effect])
    else:
        raise ValueError(f"unknown effect {effect!r}; expected one of {EFFECTS}")
    if idempotent is not None:
        hints["idempotentHint"] = bool(idempotent)
    return hints


def tool_annotations(tool: Mapping[str, Any]) -> Dict[str, bool]:
    """:func:`mcp_annotations` for one ``AI_TOOLS`` entry."""
    idempotent = tool.get("idempotent")
    return mcp_annotations(
        tool.get("effect"), idempotent if isinstance(idempotent, bool) else None
    )

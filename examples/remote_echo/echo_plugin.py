"""A minimal remote (T4) plugin: one chat tool, served by ``minder-plugin serve``.

The plugin code is ordinary ``PluginBase`` code; nothing in it knows it runs
remotely. ``echo`` is the chat tool. ``greeting`` shows a platform callback:
``self.ctx.secrets.get`` becomes a signed ``POST <minder>/v1/plugin-callbacks/
secrets.read`` carrying the invocation's grant.

Run it (see README.md in this directory)::

    pip install 'minder-plugin-sdk[serve]'
    export MINDER_PLUGIN_INSTALLATION_KEY=...   # base64 of the 32-byte seed
    minder-plugin serve examples/remote_echo/echo_plugin.py \\
        --minder-url https://minder.example \\
        --public-authority echo.example --installation-id <id> --port 8080
"""

from typing import Any, Dict

from minder_plugin_sdk import CapabilityError, PluginBase, PluginMetadata

__all__ = ["RemoteEchoPlugin"]

MAX_TEXT = 2000


class RemoteEchoPlugin(PluginBase):
    CONTRACT_VERSION = 2
    CAPABILITIES = ["actions", "ai-tools"]

    ACTIONS = frozenset({"echo", "greeting"})
    READ_ONLY_ACTIONS = frozenset({"echo", "greeting"})

    AI_TOOLS = [
        {
            "name": "echo",
            "description": "Repeat the given text back, optionally in capitals.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "maxLength": MAX_TEXT},
                    "shout": {"type": "boolean"},
                },
                "required": ["text"],
            },
            "action": "echo",
            "effect": "read",
            "idempotent": True,
        },
    ]

    async def register(self) -> PluginMetadata:
        return PluginMetadata(
            name="remote-echo",
            version="0.1.0",
            description="Echo text back: the smallest remote (T4) plugin.",
            author="minderhq",
            capabilities=["actions", "ai-tools"],
        )

    async def echo(self, text: str, shout: bool = False) -> Dict[str, Any]:
        text = str(text)[:MAX_TEXT]
        return {"text": text.upper() if shout else text}

    async def greeting(self) -> Dict[str, Any]:
        """Reads this installation's GREETING secret through a callback."""
        try:
            value = await self.ctx.secrets.get("GREETING")
        except CapabilityError as exc:
            # Denied, unavailable or invalid: degrade instead of failing.
            return {"greeting": "hello", "source": "default", "reason": exc.reason}
        if not value:
            return {"greeting": "hello", "source": "default"}
        return {"greeting": value, "source": "secret"}

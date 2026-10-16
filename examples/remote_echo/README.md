# `remote_echo`: the smallest remote (T4) plugin

A remote plugin runs on your own infrastructure. Minder calls it with signed
HTTP requests, and the plugin calls Minder back through signed, grant-scoped
callbacks. `echo_plugin.py` is plain `PluginBase` code; `minder-plugin serve`
adds the remote contract around it.

| Name | Kind | What it does |
|---|---|---|
| `echo` | chat tool (`AI_TOOLS`) and action | Returns `{"text": ...}`, in capitals with `shout: true`. |
| `greeting` | action | Reads the `GREETING` secret through `self.ctx.secrets.get` (a signed callback to Minder). Falls back to `"hello"`. |

## Run it

```bash
pip install 'minder-plugin-sdk[serve]'

# The installation key signs the plugin's callbacks: base64 of a 32-byte
# Ed25519 seed. Keep it in a secret store; never pass it as a flag.
export MINDER_PLUGIN_INSTALLATION_KEY="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"

minder-plugin serve examples/remote_echo/echo_plugin.py \
    --minder-url https://minder.example \
    --public-authority echo.example \
    --host 127.0.0.1 --port 8080
```

`--public-authority` is the host in the installation's endpoint
(`https://echo.example`). Every signature covers it, so a request Minder signed
for another plugin is refused here.

On startup the command prints the key's `keyid`, which is the RFC 7638
thumbprint Minder knows the key by. Put a TLS-terminating reverse proxy in
front, because Minder only calls `https` origins. If the proxy mounts the app
below `/`, pass the external prefix with `--path-prefix /prefix`, because the
signature covers the path Minder addressed.

The server exposes two routes:

- `POST /minder/v1/invoke` is Minder's signed invocation. For example, an
  envelope with `"kind": "tool", "target": "echo", "kwargs": {"text": "hi"}`
  gets the answer `{"ok": true, "invocation_id": "...", "result": {"text": "hi"}}`.
- `GET /minder/v1/health` is a signed liveness probe.

An unsigned, stale, replayed or tampered request gets a `401` with
`error.code = "invalid_signature"` and a stable `error.reason`. See
[`docs/t4/verifying-minder-signatures.md`](../../docs/t4/verifying-minder-signatures.md)
for the full profile.

## Test it without Minder

`tests/test_t4_server.py` drives this plugin with requests signed by a test
key, including a callback answered by a stub Minder.

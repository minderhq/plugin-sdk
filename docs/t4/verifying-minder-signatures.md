# Verifying Minder's signature (any language)

A remote (T4) plugin runs on your own infrastructure. Minder calls it with
`POST <endpoint>/minder/v1/invoke`, and the plugin calls Minder back with
`POST <callback_base>/v1/plugin-callbacks/<capability>`. Both directions use
one profile of **RFC 9421 HTTP Message Signatures** with Ed25519.

In Python, `minder-plugin serve` does all of this for you (see the
[README](../../README.md#remote-plugins-t4-minder-plugin-serve)). This guide
is for authors writing a T4 server in another language. It gives the exact
bytes to rebuild and the checks to run, in order. Each step is shown with
`openssl` and with Python.

## The profile

| | |
|---|---|
| Algorithm | Ed25519 (`alg="ed25519"`), one signature labelled `sig1` |
| Covered components, in order | `"@method"`, `"@authority"`, `"@path"`, `"@query"`, `"content-digest"`, then `"authorization"` when the request has an `Authorization` header |
| Parameters, in order | `created`, `nonce`, `keyid`, `alg` |
| `keyid` | the key's RFC 7638 JWK thumbprint (the JWK's `kid`) |
| Body digest | `Content-Digest: sha-256=:<base64 of SHA-256(body)>:` (RFC 9530), also for an empty body |
| Freshness | accept only if `now - created <= 300` and `created - now <= 10` (seconds) |
| Replay | each `nonce` once per `keyid`, remembered until the wall-clock time `created + 300 + 10` |
| Minder's keys | `GET https://<minder>/.well-known/minder/plugin-jwks.json` |

The component values are as follows:

- `@method` is the method in upper case, e.g. `POST`.
- `@authority` is **your own** public host as Minder addressed it: lowercase,
  with the default port (443 for `https`) dropped (RFC 9421 section 2.2.3).
  Take it from your configuration, never from the request's `Host` header,
  which the sender controls. This stops a request Minder signed for a
  different plugin from being replayed against yours. The host is ASCII (a
  reg-name, or a bracketed IPv6 literal without a zone id), and the port is
  1-65535. Refuse anything else.
- `@path` is the path Minder addressed, e.g. `/minder/v1/invoke`. If a reverse
  proxy strips a prefix, use the external path. The simplest strict choice is
  the route constant you serve, not the raw path you received, so an alias
  of the route (`//minder/v1/invoke`, percent-encoded segments) can never
  match. `minder-plugin serve` does this.
- `@query` is `?` followed by the raw query string, exactly as it appears in
  the request target. When there is no query it is just `?` (RFC 9421
  section 2.2.7).
- `content-digest` and `authorization` are the header values, with
  leading and trailing whitespace removed.

## The signature base

The signature base is one line per covered component, in the order
`Signature-Input` lists them, then the `@signature-params` line. Lines are
joined with a single `\n`, and there is **no trailing newline**:

```text
"@method": POST
"@authority": plugin.example
"@path": /minder/v1/invoke
"@query": ?
"content-digest": sha-256=:xRvKti6W+PtgF9Y23lHwIaKdIYLgTM19w3E/OHnfu74=:
"@signature-params": ("@method" "@authority" "@path" "@query" "content-digest");created=1760000000;nonce="doc-example-nonce-0001";keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519"
```

The `@signature-params` value is the `Signature-Input` member's value after
`sig1=`, byte for byte. Re-serialise it rather than copying it: it must be
the inner list exactly as the profile writes it.

## Worked example

This request was signed with the RFC 9421 Appendix B.1.4 test key, a
published key that must never be trusted in production:

```http
POST /minder/v1/invoke HTTP/1.1
Host: plugin.example
Content-Type: application/json
Content-Digest: sha-256=:xRvKti6W+PtgF9Y23lHwIaKdIYLgTM19w3E/OHnfu74=:
Signature-Input: sig1=("@method" "@authority" "@path" "@query" "content-digest");created=1760000000;nonce="doc-example-nonce-0001";keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519"
Signature: sig1=:oJiRs+dW1y+4cAvc6OQrlTt3ZTCpmlZK7obteGjbLmVrC7U4GQJLZflwdMqEUPsNIkt5LuqZyYg57LPSytMxBw==:

{"contract":"minder.t4/v1","invocation_id":"inv-0001","kind":"tool","target":"echo","kwargs":{"text":"hello"}}
```

The key appears in the key set as:

```json
{"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
 "kid": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", "use": "sig"}
```

### With `openssl` (3.x) and a POSIX shell

Save the body, without a trailing newline, as `body.json`. Then run:

```bash
# 1. The digest must equal the Content-Digest header.
printf 'sha-256=:%s:\n' "$(openssl dgst -sha256 -binary body.json | base64)"

# 2. Rebuild the signature base (no trailing newline).
PARAMS='("@method" "@authority" "@path" "@query" "content-digest");created=1760000000;nonce="doc-example-nonce-0001";keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519"'
printf '"@method": POST\n"@authority": plugin.example\n"@path": /minder/v1/invoke\n"@query": ?\n"content-digest": sha-256=:xRvKti6W+PtgF9Y23lHwIaKdIYLgTM19w3E/OHnfu74=:\n"@signature-params": %s' "$PARAMS" > base.txt

# 3. Turn the JWK's x (base64url, 32 bytes) into a PEM public key:
#    the fixed Ed25519 SubjectPublicKeyInfo prefix, then the raw key.
X='JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs'
{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
  printf '%s=' "$X" | tr '_-' '/+' | base64 -d; } > pub.der
openssl pkey -pubin -inform DER -in pub.der -out pub.pem

# 4. Decode the signature (between the colons) and verify.
printf '%s' 'oJiRs+dW1y+4cAvc6OQrlTt3ZTCpmlZK7obteGjbLmVrC7U4GQJLZflwdMqEUPsNIkt5LuqZyYg57LPSytMxBw==' | base64 -d > sig.bin
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in base.txt -sigfile sig.bin
# -> Signature Verified Successfully
```

### With Python (`cryptography` only)

```python
import base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

body = b'{"contract":"minder.t4/v1","invocation_id":"inv-0001","kind":"tool","target":"echo","kwargs":{"text":"hello"}}'
digest = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
params = ('("@method" "@authority" "@path" "@query" "content-digest");created=1760000000;'
          'nonce="doc-example-nonce-0001";keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";'
          'alg="ed25519"')
base = "\n".join([
    '"@method": POST',
    '"@authority": plugin.example',   # YOUR configured authority
    '"@path": /minder/v1/invoke',
    '"@query": ?',
    f'"content-digest": {digest}',
    f'"@signature-params": {params}',
]).encode()
x = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x + "="))
key.verify(base64.b64decode("oJiRs+dW1y+4cAvc6OQrlTt3ZTCpmlZK7obteGjbLmVrC7U4GQJLZflwdMqEUPsNIkt5LuqZyYg57LPSytMxBw=="), base)
```

## The checks, in order

Refuse the request (`401`) at the first failure:

1. **Parse the headers.** `Signature-Input` and `Signature` must both have a
   `sig1` member. Reject:
   - a duplicate key;
   - a component outside the six above;
   - a component with parameters;
   - any parameter other than `created`, `nonce`, `keyid` and `alg`;
   - a signature that isn't 64 bytes.
2. **Coverage.** `@method`, `@authority`, `@path`, `@query` and
   `content-digest` must all be covered. If the request has an
   `Authorization` header, `authorization` must be covered too.
3. **Algorithm.** `alg` must be `"ed25519"`.
4. **Freshness.** `created` is a unix time. Check that
   `now - created <= 300` and `created - now <= 10`.
5. **Key.** Look `keyid` up in Minder's key set (below). If it is unknown,
   refetch once (Minder may have rotated its key), but never more than about
   once every 30 s, so that random `keyid`s can't make you hammer Minder.
6. **Digest.** Recompute the SHA-256 of the exact body bytes, and compare it
   with `Content-Digest`'s `sha-256` member in constant time.
7. **Signature.** Rebuild the base as above, using **your** authority and the
   request's path and raw query, then verify it with Ed25519.
8. **Replay.** Only now record `(keyid, nonce)`, set to expire at the
   wall-clock time `created + 300 + 10`. If the pair was already there,
   refuse it.
   Recording only after the signature verifies means a forger can't use up
   real nonces. An absolute expiry, rather than a TTL on a monotonic clock,
   means a clock step can't make the store forget a nonce while its signature
   is still fresh. With several replicas, use a shared store such as Redis
   `SET <keyid>:<nonce> 1 NX EXAT <created+310>`.
9. **Installation.** Parse the (now authenticated) envelope, and check that
   its `installation_id` is your own installation's id. If it isn't, refuse
   it (`403`).

## Minder's key set

`GET https://<minder>/.well-known/minder/plugin-jwks.json` returns a JWKS
document (`{"keys": [...]}`) of OKP/Ed25519 public keys, sent with
`Cache-Control: public, max-age=300`. Use a key only if all of these hold:

- `kty` is `OKP` and `crv` is `Ed25519`;
- `x` is base64url of 32 bytes;
- there is no `d` member;
- `kid` equals the key's thumbprint, which is the base64url SHA-256 of
  `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` (with exactly that member order
  and no whitespace).

Fetch the key set over `https`, and don't follow redirects. A `503` from
the endpoint means "try again later", not "no keys".

## Signing your callbacks

Callbacks use the same profile, signed with your **installation key** (the
Ed25519 key registered for the installation). Each callback also carries the
grant from the invocation:

```http
POST /v1/plugin-callbacks/secrets.read HTTP/1.1
Host: minder.example
Authorization: Bearer <grant from the invocation>
Content-Type: application/json
Content-Digest: sha-256=:...:
Signature-Input: sig1=("@method" "@authority" "@path" "@query" "content-digest" "authorization");created=...;nonce="...";keyid="<your key's thumbprint>";alg="ed25519"
Signature: sig1=:...:
```

The callback's components take these values:

- `@authority` is Minder's host, taken from `callback_base`.
- `@path` includes any path prefix in `callback_base`.
- `@query` is `?`.
- `authorization` is covered, so a leaked grant can't be reused with another
  signature.

Use a fresh random `nonce` (at least 16 base64url characters) for every
request.

## Test vectors

[`tests/fixtures/rfc9421_t4_vectors.json`](../../tests/fixtures/rfc9421_t4_vectors.json)
holds the profile's shared test vectors: the key, each request, the expected
signature base, and the expected headers. Ed25519 signatures are
deterministic, so a correct implementation reproduces every `Signature`
exactly. Verify each case with `now = created`.

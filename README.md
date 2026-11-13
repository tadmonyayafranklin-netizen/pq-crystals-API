# Kyber KEM REST API & Web UI

A stateless HTTP API wrapping the Kyber post-quantum key encapsulation
mechanism implementations in this repository (`ref/` and `avx2/`),
plus a browser-based web platform for key management, key exchange,
and encrypted messaging demos. Built with FastAPI; all key material is
hex-encoded.

## Prerequisites

1. Build the shared libraries (from the repository root):

   ```sh
   make -C ref shared
   make -C avx2 shared    # optional; requires an AVX2-capable CPU.
                          # Note: the avx2 Makefile uses -march=native, so the
                          # resulting .so only runs on CPUs like the build host.
   ```

2. Build the `randombytes` shim used by the shared libraries:

   ```sh
   cc -shared -fPIC -O2 -Iref ref/randombytes.c -o api/librandombytes.so
   ```

3. Install Python dependencies:

   ```sh
   python3 -m venv api/.venv
   api/.venv/bin/pip install -r api/requirements.txt
   ```

## Running

```sh
api/.venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Interactive API docs (OpenAPI/Swagger UI) are served at `http://localhost:8000/docs`.
The web platform is served at `http://localhost:8000/ui` (`/` redirects there).

## Web UI

The platform (`api/static/`) is a static single-page app that talks to the
REST API entirely from the browser — no server-side state is added.

- **Keypairs** — generate keypairs for any impl/algorithm, save them as
  named profiles in `localStorage`, import/export as JSON or raw `.bin`.
- **Key Exchange** — encapsulate to a peer's public key and decapsulate a
  received ciphertext with your secret key; verifies that the shared
  secrets match. Works across implementations (e.g. `avx2` → `ref`).
- **Secure Channel** — derives an AES-256-GCM key from a KEM shared secret
  via HKDF-SHA256 (Web Crypto) and encrypts/decrypts messages, demoing
  end-to-end encryption on top of the key exchange.
- **API Explorer** — send arbitrary API requests from the browser and
  inspect responses or generated `curl` commands.

## Endpoints

All KEM endpoints follow the pattern `/api/v1/{impl}/{alg}/...` where

- `impl` is `ref` (portable reference) or `avx2` (x86-64 optimized), and
- `alg` is `512`, `768`, or `1024` (Kyber512 / Kyber768 / Kyber1024).

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness probe + available implementations |
| GET | `/api/v1/parameters` | Supported algorithms and byte sizes |
| POST | `/api/v1/{impl}/{alg}/keypair` | Generate a keypair |
| POST | `/api/v1/{impl}/{alg}/encapsulate` | Encapsulate a shared secret to a public key |
| POST | `/api/v1/{impl}/{alg}/decapsulate` | Decapsulate a ciphertext with a secret key |

The API is **stateless**: secret keys are never stored server-side. Callers
must persist secret keys themselves and pass them back for decapsulation.
Keys produced by one implementation can be used with the other
(e.g. encapsulate with `avx2`, decapsulate with `ref`).

### Examples

Generate a keypair:

```sh
curl -X POST http://localhost:8000/api/v1/ref/512/keypair
```

```json
{
  "algorithm": "Kyber512",
  "implementation": "ref",
  "public_key": "e310...",
  "secret_key": "1a2b..."
}
```

Encapsulate to a public key:

```sh
curl -X POST http://localhost:8000/api/v1/ref/512/encapsulate \
  -H 'Content-Type: application/json' \
  -d '{"public_key": "<hex public key>"}'
```

```json
{
  "algorithm": "Kyber512",
  "implementation": "ref",
  "ciphertext": "9f...",
  "shared_secret": "ab..."
}
```

Decapsulate a ciphertext:

```sh
curl -X POST http://localhost:8000/api/v1/ref/512/decapsulate \
  -H 'Content-Type: application/json' \
  -d '{"ciphertext": "<hex ciphertext>", "secret_key": "<hex secret key>"}'
```

```json
{
  "algorithm": "Kyber512",
  "implementation": "ref",
  "shared_secret": "ab..."
}
```

## Parameter sets

| Algorithm | Secret key | Public key | Ciphertext | Shared secret |
|---|---|---|---|---|
| Kyber512 | 1632 B | 800 B | 768 B | 32 B |
| Kyber768 | 2400 B | 1184 B | 1088 B | 32 B |
| Kyber1024 | 3168 B | 1568 B | 1568 B | 32 B |

## Files

- `main.py` — FastAPI application, endpoint definitions, and static UI mount
- `kyber.py` — ctypes bindings for the Kyber shared libraries
- `static/index.html`, `static/styles.css`, `static/app.js` — web platform frontend
- `librandombytes.so` — compiled `randombytes` shim (build artifact)
- `requirements.txt` — Python dependencies

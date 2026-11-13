"""FastAPI REST API for the Kyber post-quantum KEM.

Stateless endpoints wrapping the reference (ref/) and AVX2-optimized (avx2/)
implementations shipped in this repository.

Run with:
    uvicorn api.main:app --reload
"""

from typing import Annotated

import pathlib

from fastapi import FastAPI, HTTPException, Path, Query
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.kyber import (
    ALGORITHMS,
    PARAMS,
    KyberError,
    available_impls,
    get_impl,
    hex_decode,
    hex_encode,
)

app = FastAPI(
    title="Kyber KEM API",
    description=(
        "Post-quantum key encapsulation mechanism API based on the "
        "[pq-crystals/kyber](https://github.com/pq-crystals/kyber) implementation. "
        "All keys and ciphertexts are hex-encoded byte strings. The API is "
        "stateless: callers are responsible for storing secret keys."
    ),
    version="1.0.0",
)

ImplName = Annotated[str, Path(pattern="^(ref|avx2)$", description="Implementation: 'ref' or 'avx2'")]
Alg = Annotated[int, Path(description="Security parameter set")]


class KeypairResponse(BaseModel):
    algorithm: str
    implementation: str
    public_key: str = Field(description="Hex-encoded public key")
    secret_key: str = Field(description="Hex-encoded secret key")


class EncapsulateRequest(BaseModel):
    public_key: str = Field(description="Hex-encoded public key")


class EncapsulateResponse(BaseModel):
    algorithm: str
    implementation: str
    ciphertext: str = Field(description="Hex-encoded ciphertext")
    shared_secret: str = Field(description="Hex-encoded shared secret")


class DecapsulateRequest(BaseModel):
    ciphertext: str = Field(description="Hex-encoded ciphertext")
    secret_key: str = Field(description="Hex-encoded secret key")


class DecapsulateResponse(BaseModel):
    algorithm: str
    implementation: str
    shared_secret: str = Field(description="Hex-encoded shared secret")


def _impl(impl: str, alg: int):
    if alg not in PARAMS:
        raise HTTPException(status_code=404, detail=f"unsupported algorithm: Kyber{alg}")
    if impl not in available_impls() or alg not in available_impls()[impl]:
        raise HTTPException(status_code=404, detail=f"implementation '{impl}' not available for Kyber{alg}")
    try:
        return get_impl(impl, alg)
    except (FileNotFoundError, OSError) as e:
        raise HTTPException(status_code=503, detail=f"could not load Kyber library: {e}")


STATIC_DIR = pathlib.Path(__file__).resolve().parent / "static"
if STATIC_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")


@app.get("/", include_in_schema=False)
def root():
    if STATIC_DIR.is_dir():
        return RedirectResponse(url="/ui")
    return RedirectResponse(url="/docs")


@app.get("/health")
def health():
    return {"status": "ok", "implementations": available_impls()}


@app.get("/api/v1/parameters")
def parameters(impl: str | None = Query(None, pattern="^(ref|avx2)$")):
    """List supported algorithms and byte sizes for keys and ciphertexts."""
    impls = available_impls()
    impl_filter = [impl] if impl else list(impls)
    return {
        name: {
            "kyber_algorithms": [
                {
                    "id": alg,
                    "name": ALGORITHMS[alg],
                    "secret_key_bytes": PARAMS[alg][0],
                    "public_key_bytes": PARAMS[alg][1],
                    "ciphertext_bytes": PARAMS[alg][2],
                    "shared_secret_bytes": PARAMS[alg][3],
                }
                for alg in impls.get(name, [])
            ]
        }
        for name in impl_filter
        if name in impls
    }


@app.post("/api/v1/{impl}/{alg}/keypair", response_model=KeypairResponse)
def keypair(impl: ImplName, alg: Alg):
    """Generate a new Kyber keypair. Store the secret key securely."""
    k = _impl(impl, alg)
    try:
        pk, sk = k.keypair()
    except KyberError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return KeypairResponse(
        algorithm=ALGORITHMS[alg], implementation=impl,
        public_key=hex_encode(pk), secret_key=hex_encode(sk),
    )


@app.post("/api/v1/{impl}/{alg}/encapsulate", response_model=EncapsulateResponse)
def encapsulate(impl: ImplName, alg: Alg, body: EncapsulateRequest):
    """Encapsulate a shared secret to the given public key."""
    k = _impl(impl, alg)
    try:
        pk = hex_decode(body.public_key, k.pk_bytes, "public_key")
        ct, ss = k.encapsulate(pk)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except KyberError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return EncapsulateResponse(
        algorithm=ALGORITHMS[alg], implementation=impl,
        ciphertext=hex_encode(ct), shared_secret=hex_encode(ss),
    )


@app.post("/api/v1/{impl}/{alg}/decapsulate", response_model=DecapsulateResponse)
def decapsulate(impl: ImplName, alg: Alg, body: DecapsulateRequest):
    """Decapsulate a ciphertext with the corresponding secret key."""
    k = _impl(impl, alg)
    try:
        ct = hex_decode(body.ciphertext, k.ct_bytes, "ciphertext")
        sk = hex_decode(body.secret_key, k.sk_bytes, "secret_key")
        ss = k.decapsulate(ct, sk)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except KyberError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return DecapsulateResponse(
        algorithm=ALGORITHMS[alg], implementation=impl,
        shared_secret=hex_encode(ss),
    )

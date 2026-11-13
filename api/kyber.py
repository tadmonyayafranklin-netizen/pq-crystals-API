"""ctypes bindings for the Kyber KEM shared libraries (ref and avx2)."""

import ctypes
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# (secret_key_bytes, public_key_bytes, ciphertext_bytes, shared_secret_bytes)
PARAMS = {
    512: (1632, 800, 768, 32),
    768: (2400, 1184, 1088, 32),
    1024: (3168, 1568, 1568, 32),
}

ALGORITHMS = {
    512: "Kyber512",
    768: "Kyber768",
    1024: "Kyber1024",
}

LIB_PATHS = {
    "ref": str(REPO_ROOT / "ref" / "lib" / "libpqcrystals_kyber{alg}_ref.so"),
    "avx2": str(REPO_ROOT / "avx2" / "libpqcrystals_kyber{alg}_avx2.so"),
}

# Shared libraries that must be loaded globally before the Kyber libraries,
# because the latter have undefined symbols resolved at load time.
RANDOMBYTES_LIB = str(REPO_ROOT / "api" / "librandombytes.so")
DEPENDENCY_LIBS = {
    "ref": [str(REPO_ROOT / "ref" / "lib" / "libpqcrystals_fips202_ref.so")],
    "avx2": [
        str(REPO_ROOT / "avx2" / "libpqcrystals_fips202_ref.so"),
        str(REPO_ROOT / "avx2" / "libpqcrystals_fips202x4_avx2.so"),
    ],
}


def _cpu_has_avx2() -> bool:
    try:
        with open("/proc/cpuinfo") as f:
            return "avx2" in f.read()
    except OSError:
        return False


class KyberError(Exception):
    """Raised when a Kyber primitive returns a non-zero status."""


class KyberImpl:
    """Loaded Kyber implementation for one parameter set."""

    def __init__(self, impl: str, alg: int):
        self.impl = impl
        self.alg = alg
        self.sk_bytes, self.pk_bytes, self.ct_bytes, self.ss_bytes = PARAMS[alg]
        path = Path(LIB_PATHS[impl].format(alg=alg))
        if not path.exists():
            raise FileNotFoundError(f"Shared library not found: {path}")
        for dep in [RANDOMBYTES_LIB, *DEPENDENCY_LIBS[impl]]:
            if Path(dep).exists():
                ctypes.CDLL(dep, mode=ctypes.RTLD_GLOBAL)
        ns = f"pqcrystals_kyber{alg}_{impl}_"
        self.lib = ctypes.CDLL(str(path))
        u8p = ctypes.POINTER(ctypes.c_uint8)
        self._keypair = self.lib[ns + "keypair"]
        self._keypair.argtypes = [u8p, u8p]
        self._keypair.restype = ctypes.c_int
        self._enc = self.lib[ns + "enc"]
        self._enc.argtypes = [u8p, u8p, u8p]
        self._enc.restype = ctypes.c_int
        self._dec = self.lib[ns + "dec"]
        self._dec.argtypes = [u8p, u8p, u8p]
        self._dec.restype = ctypes.c_int

    @staticmethod
    def _buf(data: bytes, size: int) -> ctypes.Array:
        if len(data) != size:
            raise ValueError(f"expected {size} bytes, got {len(data)}")
        return (ctypes.c_uint8 * size).from_buffer_copy(data)

    def keypair(self) -> tuple[bytes, bytes]:
        pk = (ctypes.c_uint8 * self.pk_bytes)()
        sk = (ctypes.c_uint8 * self.sk_bytes)()
        if self._keypair(pk, sk) != 0:
            raise KyberError("keypair generation failed")
        return bytes(pk), bytes(sk)

    def encapsulate(self, pk: bytes) -> tuple[bytes, bytes]:
        pk_buf = self._buf(pk, self.pk_bytes)
        ct = (ctypes.c_uint8 * self.ct_bytes)()
        ss = (ctypes.c_uint8 * self.ss_bytes)()
        if self._enc(ct, ss, pk_buf) != 0:
            raise KyberError("encapsulation failed")
        return bytes(ct), bytes(ss)

    def decapsulate(self, ct: bytes, sk: bytes) -> bytes:
        ct_buf = self._buf(ct, self.ct_bytes)
        sk_buf = self._buf(sk, self.sk_bytes)
        ss = (ctypes.c_uint8 * self.ss_bytes)()
        if self._dec(ss, ct_buf, sk_buf) != 0:
            raise KyberError("decapsulation failed")
        return bytes(ss)


_REGISTRY: dict[tuple[str, int], KyberImpl | None] = {}


def available_impls() -> dict[str, list[int]]:
    """Return {impl_name: [algorithms]} for implementations that can run here."""
    result = {}
    for impl in LIB_PATHS:
        if impl == "avx2" and not _cpu_has_avx2():
            continue
        algs = [
            alg for alg in PARAMS
            if Path(LIB_PATHS[impl].format(alg=alg)).exists()
        ]
        if algs:
            result[impl] = algs
    return result


def get_impl(impl: str, alg: int) -> KyberImpl:
    if alg not in PARAMS:
        raise ValueError(f"unsupported algorithm: {alg}")
    key = (impl, alg)
    if key not in _REGISTRY:
        _REGISTRY[key] = KyberImpl(impl, alg)
    return _REGISTRY[key]


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(value: str, expected: int, name: str) -> bytes:
    try:
        data = bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{name} is not valid hex")
    if len(data) != expected:
        raise ValueError(f"{name} must be {expected} bytes ({expected * 2} hex chars), got {len(data)}")
    return data

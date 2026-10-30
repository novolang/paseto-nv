# A reference PASETO v4 and PASERK written in Python from the specification,
# on hashlib (BLAKE2b) and the `cryptography` package (Ed25519 and the
# ChaCha20 block function), with HChaCha20 written out below and checked
# against draft-irtf-cfrg-xchacha section 2.2.1 when this file is loaded.
# The Ed25519 token of the PASETO test vector 4-S-1 is reproduced and
# asserted on load, which checks the pre-authentication encoding, the
# header and the base64url framing against a published token.
# Run with `python3 -I paseto_ref.py` to see the checks.
import base64, hashlib, struct
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

M32 = 0xFFFFFFFF

def rotl(x, n): return ((x << n) | (x >> (32 - n))) & M32

def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M32; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & M32; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32; s[b] = rotl(s[b] ^ s[c], 7)

def hchacha20(key, nonce16):
    s = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))

def xchacha20(key, nonce24, data):
    sub = hchacha20(key, nonce24[:16])
    c = Cipher(algorithms.ChaCha20(sub, struct.pack("<I", 0) + b"\0\0\0\0" + nonce24[16:]), mode=None).encryptor()
    return c.update(data)

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def pae(pieces):
    out = struct.pack("<Q", len(pieces))
    for p in pieces:
        out += struct.pack("<Q", len(p)) + p
    return out

def blake(key, msg, n): return hashlib.blake2b(msg, key=key, digest_size=n).digest()

def local_keys(key, nonce):
    tmp = blake(key, b"paseto-encryption-key" + nonce, 56)
    return tmp[:32], tmp[32:], blake(key, b"paseto-auth-key-for-aead" + nonce, 32)

def encrypt(key, nonce, msg, footer=b"", implicit=b""):
    ek, n2, ak = local_keys(key, nonce)
    c = xchacha20(ek, n2, msg)
    h = b"v4.local."
    t = blake(ak, pae([h, nonce, c, footer, implicit]), 32)
    tok = h.decode() + b64(nonce + c + t)
    return tok + ("." + b64(footer) if footer else "")

def sign(seed, msg, footer=b"", implicit=b""):
    h = b"v4.public."
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(pae([h, msg, footer, implicit]))
    tok = h.decode() + b64(msg + sig)
    return tok + ("." + b64(footer) if footer else "")

def public_of(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)

def paserk_id(header, paserk):
    return header + b64(hashlib.blake2b((header + paserk).encode(), digest_size=33).digest())

def check():
    key = bytes(range(32)); n16 = bytes.fromhex("000000090000004a0000000031415927")
    assert hchacha20(key, n16).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    seed = bytes.fromhex("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774")
    assert public_of(seed).hex() == "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
    m = b'{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}'
    assert sign(seed, m) == "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA"
check()

if __name__ == "__main__":
    print("paseto_ref: HChaCha20 and the 4-S-1 token agree")

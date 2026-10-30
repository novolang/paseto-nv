# Writes ../generated_vectors_tests.nv: v4.local and v4.public tokens, and the
# PASERK strings and identifiers of their keys, produced by the reference in
# paseto_ref.py (hashlib's BLAKE2b, the `cryptography` package's Ed25519 and
# ChaCha20 block function, and a written-out HChaCha20), whose Ed25519 side
# reproduces the published token of the PASETO test vector 4-S-1 when it is
# loaded.  Run with `python3 -I generate.py` from this directory; the output is
# committed.
import hashlib, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paseto_ref as P

def det(label, n):
    out = b""; i = 0
    while len(out) < n:
        out += hashlib.sha256(label.encode() + i.to_bytes(4, "big")).digest(); i += 1
    return out[:n]

def q(b): return '"' + (b.hex() if isinstance(b, bytes) else b) + '"'

ISS, AUD = "https://auth.example", "api"

def claims(pad):
    return ('{"iss":"%s","aud":"%s","exp":"2039-01-01T00:00:00+00:00","pad":"%s"}' % (ISS, AUD, "x" * pad)).encode()

PLAIN = [b"", b"{}", b'{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}']
OK_PADS = [0, 1, 7, 8, 9, 40, 100, 300]
FOOTERS = [b"", b'{"kid":"k4.lid.abc"}', b"f", b""]
IMPLICITS = [b"", b"", b"tenant-42", b"x"]

def rows(kind):
    out = []
    msgs = [(m, "plain") for m in PLAIN] + [(claims(p), "ok") for p in OK_PADS]
    for i, (m, k) in enumerate(msgs):
        f, im = FOOTERS[i % 4], IMPLICITS[(i + 1) % 4]
        if kind == "local":
            key = bytes(range(0x70, 0x90)) if i == 0 else det(f"lk{i}", 32)
            nonce = bytes(32) if i == 0 else det(f"ln{i}", 32)
            out.append((key, nonce, m, f, im, P.encrypt(key, nonce, m, f, im), k))
        else:
            seed = bytes.fromhex("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774") if i == 2 else det(f"ps{i}", 32)
            out.append((seed, P.public_of(seed), m, f, im, P.sign(seed, m, f, im), k))
    return out

def emit_rows(L, name, rs):
    L.append(f"fn {name}() -> [[Str]]\n    [\n")
    L.append(",\n".join("        [" + ", ".join(q(x) for x in r[:6]) + ", " + q(r[6]) + "]" for r in rs))
    L.append("\n    ]\n\n")

def paserk_rows():
    rs = []
    for i in range(4):
        k = det(f"pk{i}", 32)
        s = "k4.local." + P.b64(k)
        rs.append(["local", k.hex(), s, P.paserk_id("k4.lid.", s)])
    for i in range(4):
        seed = det(f"pp{i}", 32)
        pk = P.public_of(seed)
        sp = "k4.public." + P.b64(pk)
        ss = "k4.secret." + P.b64(seed + pk)
        rs.append(["public", pk.hex(), sp, P.paserk_id("k4.pid.", sp)])
        rs.append(["secret", seed.hex(), ss, P.paserk_id("k4.sid.", ss)])
    return rs

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    L = [open(os.path.join(here, "generated_head.nv.in")).read()]
    emit_rows(L, "local_rows", rows("local"))
    emit_rows(L, "public_rows", rows("public"))
    L.append("// kind, key or seed (hex), PASERK string, identifier\nfn paserk_rows() -> [[Str]]\n    [\n")
    L.append(",\n".join("        [" + ", ".join(q(x) for x in r) + "]" for r in paserk_rows()))
    L.append("\n    ]\n\n")
    L.append(open(os.path.join(here, "generated_tail.nv.in")).read())
    out = os.path.join(here, "..", "generated_vectors_tests.nv")
    open(out, "w").write("".join(L))
    subprocess.run(["novo", "fmt", out], check=True, stdout=subprocess.DEVNULL)

main()

# paseto-nv

**Status: NOT IMPLEMENTED — interface only.**

Every public function below is published with its signature and its
effect row, and every body is `todo()`.  Installing this package works;
calling it panics with `not implemented`.

## What this is

PASETO v4 — `v4.local` (encrypted with XChaCha20, authenticated with
BLAKE2b) and `v4.public` (signed with Ed25519) — plus PASERK, the key
serialisation that goes with it.  The unverified state is unusable by
construction, the same way jwt-nv's is and deliberately the same shape,
so a consumer can switch formats by changing type names.

```
novo pkg add paseto-nv
novo pkg build
novo test
```

## The one example that will work

```novo
use pasetoken
use paspolicy
use pasclaims

fn check(token: Str, key: PasPublicKey, now_seconds: Int) -> Result<PasClaims, PasError>
    let t   = pasetoken.decode(token)!
    let pol = paspolicy.requiring(paspolicy.strict(), "https://auth.example", "api")
    Ok(pasetoken.claims_of(
        pasetoken.verify(t, key, pol, pasclaims.no_implicit(),
                         pasclaims.instant(now_seconds))!))
```

There is no shorter version that skips the check, because `claims_of`
takes a `VerifiedPaseto` and nothing but `verify` and `decrypt` produce
one.

## Why PASETO exists beside jwt-nv

**In one paragraph you can act on:** every classic JWT vulnerability is
a consequence of one design decision — the token tells the verifier
which algorithm to use, in a header the attacker also controls.  That
gives you `alg: none`, and HS256-with-the-RSA-public-key-as-the-HMAC-
secret, and a long tail of libraries that read a claim out of a token
they had not verified.  jwt-nv closes each of them by construction, and
PASETO removes the question instead: the version and the purpose are a
fixed prefix (`v4.local.`, `v4.public.`), each pair has exactly ONE
construction with no parameters, and the key carries its own purpose —
so there is no algorithm to negotiate, nothing to downgrade to, and no
header to lie in.  **So: if you control both ends, use this.  If you
have to accept a token somebody else issued — an OIDC provider, an API
gateway, a partner's service — use jwt-nv, because you do not get to
choose the format when you are not the issuer.**

Two more differences worth knowing before you choose:

- **A `v4.local` token is encrypted.**  A JWT's payload is base64 that
  anyone holding the token can read; a local PASETO's claims are
  unreadable without the key.  That is why
  `dangerous_unverified_payload_json` refuses a local token here — it
  physically cannot read one — and why jwt-nv's equivalent hatch opens
  onto something that was never hidden.
- **The implicit assertion has no JWT counterpart at all.**  It is a
  value both ends supply, authenticated, and never written into the
  token: a tenant id, a session id, a device fingerprint.  A token
  stolen from tenant A cannot be replayed against tenant B even though
  it is perfectly valid and unexpired, and the attacker cannot see or
  change the binding because it is not in the bytes they hold.

## The load-bearing interface: the unverified state is unusable

```novo
pub fn decode(token: Str) -> Result<UnverifiedPaseto, PasError>
pub fn verify(t: UnverifiedPaseto, key: PasPublicKey, policy: PasPolicy,
              implicit: PasImplicit, now: PasInstant) -> Result<VerifiedPaseto, PasError>
pub fn decrypt(t: UnverifiedPaseto, key: PasLocalKey, policy: PasPolicy,
               implicit: PasImplicit, now: PasInstant) -> Result<VerifiedPaseto, PasError>
pub fn claims_of(t: VerifiedPaseto) -> PasClaims
```

A caller holding claims has been through a check with a key it chose
and a policy it wrote — not because it remembered to, but because it
could not write the other program.  A reviewer never has to ask whether
something was verified; the type says so.

**What an unverified token will tell you**, and why that is not a hole:
`prefix_of`, `purpose_of`, `version_of` and `unverified_footer` work
before verification, because choosing *which key* to verify with
requires reading the footer's `kid`.  They are facts about the
envelope, and nothing here lets a caller act on them as claims about
the world.

**Three key types, not one with a role field.**  `PasLocalKey` decrypts,
`PasPublicKey` verifies, `PasSecretKey` signs.  `decrypt` cannot be
handed a public key at all, and a local key aimed at a public token is
`PasPurposeMismatch` by name.

**Validation is a value**, and it is jwt-nv's `strict()`-narrowed-by-
builders shape — with one thing missing.  There is no
`allowing(p, algs)`, because a PASETO policy has no algorithms to
allow.  That absence is the format's advantage showing up in an API.

## The clock and the entropy are the caller's

`core` — no effects.  Two things this package needs from the world
arrive as arguments, and both are better for it:

| what | why |
| --- | --- |
| `PasInstant` | a test validates at any instant with no fake clock; an audit tool can ask *was this valid when it was presented*; a replay of a request log gets the same answers |
| the 32-byte `v4.local` nonce | the specification's own vectors can be reproduced byte for byte by replaying their nonce, which no library that picks its own can do |

**A repeated `v4.local` nonce is catastrophic** and this package cannot
stop you: both the encryption key and the authentication key are
derived from the key *and* the nonce, so a repeat is a repeated
keystream and a repeated authentication key.  32 bytes is safe to pick
uniformly at random, which is the discipline to use.  Signing needs no
entropy at all — Ed25519 is deterministic — which is the one place
PASETO is easier than a JWT to use safely.

No device claim and no `tests/embedded_probe.nv`: the surface is `Str`,
`Bytes` and lists of claims.  chacha20-nv underneath makes the device
claim.

## What a port gets wrong, and what this package does about it

**PAE.** Every token authenticates several pieces at once — header,
nonce, ciphertext, footer, implicit assertion.  Concatenating them and
MACing the result is the classic mistake: `("ab", "c")` and
`("a", "bc")` concatenate to the same bytes, so a footer byte moved
into the ciphertext is a forgery.  PAE puts the count and every length
inside what is authenticated.  `paspae` is public, with the
specification's four vectors as its tests, and `pasetoken.pre_auth`
hands out the exact bytes so a failing implementation can be diffed
rather than guessed at.

**The top bit of every PAE length is cleared** — a specification rule,
and the reason is JavaScript: a length above 2^53 is not exact as a
double, and a language whose integers are doubles would encode a
different number than it read.

**A PASERK identifier is 33 bytes**, not 32.  It looks like a typo and
is not: the truncation is chosen so the base64url encoding is a whole
number of characters.  A port that truncated to 32 produces identifiers
that are the right shape and disagree with everybody.

**A `k4.secret.` string is 64 bytes** — the seed then the public key —
while ed25519-nv's own type holds the 32-byte seed.  That is the one
place in the package where a length surprise is likely, and
`secret_from_string` checks the two halves agree rather than trusting
them: a mismatched pair is a key file that was edited, and accepting it
produces a signer whose tokens nobody can verify.

## BLAKE2b is a missing row

`v4.local` is defined over BLAKE2b: the key splitting
(`paseto-encryption-key`, `paseto-auth-key-for-aead`) and the MAC are
keyed BLAKE2b, and every PASERK identifier is a BLAKE2b hash.  **Nothing
on the grid publishes one.**

This is the second package to find that, and the finding is the
argument.  argon2-nv's plan note already says it from the other
direction — Argon2 is defined over BLAKE2b — so a copy inside either
package would be the second of two copies of a primitive that wants to
be one.

**The row: `blake2-nv`** — `crypto` / `core` / P0, port of RustCrypto's
`blake2`, RFC 7693 as the oracle, BLAKE2b with its keyed mode and
arbitrary digest length.  P0 rather than P2 because two staged packages
are already blocked on it.

The signatures here are written as though it exists, because they will
not change when it does.

## What is outside, and named

- **v1, v2 and v3.**  v1 and v2 are deprecated by the specification.
  v3 — AES-256-CTR with HMAC-SHA-384 for local, ECDSA over P-384 for
  public — is for callers under a NIST-algorithms constraint, and needs
  P-384 and AES, neither of which is on the grid.  A `PasVersion` arm
  before the primitives is a value nothing can consume; it is a second
  arm and two new rows when somebody needs it, not a flag.
- **PASERK's wrapping tier** — `k4.local-wrap.pie.`, `k4.seal.`,
  `k4.local-pw.`, `k4.secret-pw.`.  Each is key encryption with its own
  vectors and failure modes, and the password ones need the same
  scrypt-shaped derivation age-nv named as missing.  Shipping half a
  wrapping tier is worse than shipping none.

## Dependencies

| package | for | layer |
| --- | --- | --- |
| chacha20-nv | XChaCha20, the RAW stream cipher — `cc20x.xapply_into`, not the AEAD | `core` |
| ed25519-nv | `v4.public`'s signing and verification, and its key types | `core` |
| calendar-nv | the RFC 3339 timestamps `exp`, `nbf` and `iat` are written as | `core` |
| base64-nv | base64url unpadded, everywhere | `core` |

All four are `core`, so `dep-layer` holds.

**chacha20-nv is a PATH dependency in this tree and must become
`chacha20-nv = "^0.0.1"` before publish.**  It is a path here only
because the two packages are being developed together in one checkout.

`chacha20-nv` is taken for its *unauthenticated* stream cipher, which
that package publishes separately with a warning that it authenticates
nothing.  This is the caller that means it: `v4.local` is
encrypt-then-MAC with BLAKE2b, not an AEAD, and a port that reached for
XChaCha20-Poly1305 because the names look similar would produce tokens
no other implementation can read.

## The reference implementation

Rust's `rusty_paseto` and Python's `pyseto` for the surface; the oracle
is the PASETO specification and the shared test-vector repository every
implementation runs — `4-E-*` for local, `4-S-*` for public, and the
PAE vectors under "Authentication Padding".  jwt-nv is the sibling to
read beside this one: its README argues the same security properties
from the other side, and the two APIs are shaped alike on purpose.

## Status

Every function is `todo()`.  `novo test --isolate` runs the API suite;
every assertion against a function reaches
`not implemented: paseto-nv.<module>.<fn>`, and the few that pass are
assertions about published constants, which are not stubs.

| module | public types | public items | implemented |
| --- | --- | --- | --- |
| `paskey` | `PasVersion`, `PasPurpose`, `PasLocalKey`, `PasSecretKey`, `PasPublicKey` | 6 consts, 13 fns | no |
| `pasclaims` | `PasInstant`, `PasClaims`, `PasFooter`, `PasImplicit` | 7 consts, 22 fns | no |
| `pasetoken` | `UnverifiedPaseto`, `VerifiedPaseto` | 14 fns | no |
| `paspolicy` | `PasPolicy` | 15 fns | no |
| `paserk` | `PaserkType` | 7 consts, 14 fns | no |
| `paspae` | — | 1 const, 4 fns | no |
| `paserr` | `PasError` (+ `impl Error`) | 3 fns | no |

Fourteen public types, 85 public functions, 21 public constants and one
trait impl.

## Licence

Apache-2.0.

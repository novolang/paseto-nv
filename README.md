# paseto-nv

PASETO stands for Platform-Agnostic Security Tokens. It is a token
format in which the cryptography is fixed by the token's own prefix
rather than negotiated: there is no algorithm field to read and nothing
to downgrade to. It is specified by
[the PASETO specification](https://github.com/paseto-standard/paseto-spec),
and its key serialisation by
[PASERK](https://github.com/paseto-standard/paserk). This package
implements PASETO version 4 and PASERK's key tier in novo-lang.

## What a PASETO is

A token is dot-separated text beginning with a **version** and a
**purpose**, such as `v4.local.` or `v4.public.`. That prefix is the
whole of the cryptographic negotiation: each version and purpose pair
has exactly one construction, with no parameters.

A **local** token is encrypted. Its claims are unreadable without the
key. Version 4's local construction encrypts with XChaCha20 and
authenticates with keyed BLAKE2b, encrypt-then-MAC. A **public** token
is signed and not encrypted. Version 4 signs with Ed25519.

After the prefix comes the **payload**, base64url without padding, and
optionally a dot and a **footer**. The footer is authenticated and not
encrypted, so it is where a key identifier goes: a verifier must read
it to choose a key before it can verify anything.

An **implicit assertion** is a value both ends supply, authenticated
along with the token and never written into it: a tenant identifier, a
session identifier, a device fingerprint. A token stolen from one
tenant cannot be replayed against another even though it is valid and
unexpired, and the holder cannot see or change the binding because it
is not in the bytes they hold.

The claims are a JSON object. The specification registers seven, the
same names RFC 7519 uses, and its timestamps are RFC 3339 strings
rather than numbers.

| Claim | Meaning |
| --- | --- |
| `iss` | Who issued the token |
| `sub` | Who or what the token is about |
| `aud` | Which service the token is for |
| `exp` | The instant after which it must not be accepted |
| `nbf` | The instant before which it must not be accepted |
| `iat` | When it was issued |
| `jti` | A unique identifier for this token |

**Pre-authentication encoding** (PAE) is how several pieces are
authenticated as one. Concatenating them would not do: `("ab", "c")`
and `("a", "bc")` concatenate to the same bytes, so a footer byte moved
into the ciphertext would be a forgery. PAE writes the number of pieces
and each piece's length before the pieces.

**PASERK** is how a key is written down. `k4.local.`, `k4.public.` and
`k4.secret.` are serialised keys. `k4.lid.`, `k4.pid.` and `k4.sid.`
are **identifiers**: a one-way hash of the serialised key, for naming a
key in a footer or a log without disclosing it.

Every function in this package performs no input and no output. The
current time and the local nonce arrive as arguments.

## Install

```
novo pkg add paseto-nv
```

## Example

```novo
use pasclaims
use paserk
use paspolicy
use pasetoken

fn main() [io]
    // The public key this service verifies `v4.public` tokens with,
    // read from its PASERK string.
    match paserk.public_from_string("k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        Err(e) => println("that is not a public key: ${e.message()}")
        Ok(key) =>
            // What this service accepts: one issuer, one audience, an
            // expiry required.
            let policy = paspolicy.requiring(paspolicy.strict(), "https://auth.example", "api")

            // Split the token. Its claims cannot be read yet.
            match pasetoken.decode("v4.public.eyJzdWIiOiJhZGEifQ")
                Err(e) => println("not a token: ${e.message()}")
                Ok(t)  =>
                    // Check the signature, the policy and the binding.
                    // Only this call produces a verified token.
                    match pasetoken.verify(t, key, policy, pasclaims.no_implicit(),
                                           pasclaims.instant(1789000000))
                        Err(e) => println("refused: ${e.message()}")
                        Ok(v)  => println("the subject is ${pasclaims.subject(pasetoken.claims_of(v))}")
```

Build and test with `novo pkg build` and `novo test`.

## What the package contains

| Module | Contents |
| --- | --- |
| `paserr` | Every refusal, and whether each is an authentication failure or a policy one. |
| `paskey` | The versions, the purposes, the three key types, the sizes, and the prefix. |
| `pasclaims` | An instant, the registered claims, the footer and the implicit assertion. |
| `paspae` | Pre-authentication encoding, on its own. |
| `pasetoken` | Decoding, decrypting, verifying, reading a verified token, encrypting and signing. |
| `paspolicy` | What a service accepts, as a value. |
| `paserk` | Keys written down and read back, and the identifiers over them. |

## How to choose an entry point

**`pasetoken.decode` splits a token and reads its envelope.** It
answers an `UnverifiedPaseto`, whose prefix, version, purpose and
footer can be read and whose claims cannot.

**`pasetoken.decrypt` takes a local key and `verify` takes a public
key.** Both produce the one type `claims_of` accepts. Which to call is
decided by `purpose_of`, and the wrong key for a purpose is refused by
name.

**`pasetoken.encrypt` and `sign` produce a token.** `encrypt` takes the
32-byte nonce from the caller. `sign` needs no entropy: Ed25519 is
deterministic.

**`paspae` is published on its own** so a failing implementation can be
compared against the specification's vectors byte for byte, and
`pasetoken.pre_auth` hands out the exact bytes a token authenticates.

**`paserk.local_id`, `public_id` and `secret_id` name a key without
disclosing it.** Put one in a footer or a log.

## The rules a user needs

1. **Claims can only be read from a verified token.**
   `pasetoken.claims_of` takes a `VerifiedPaseto`, and only
   `pasetoken.verify` and `pasetoken.decrypt` produce one.
2. **There are three key types, not one with a role.** `PasLocalKey`
   decrypts, `PasPublicKey` verifies, `PasSecretKey` signs. `decrypt`
   cannot be handed a public key at all, and a local key aimed at a
   public token is `PasPurposeMismatch`.
3. **An unverified token will tell you its prefix, version, purpose and
   footer.** Choosing which key to verify with requires reading the
   footer's key identifier, so a token that showed nothing could never
   be verified. None of those is a claim about the world.
4. **`dangerous_unverified_payload_json` refuses a local token.** A
   local token's payload is encrypted, so there is nothing to read
   without the key. It answers a public token's payload as text.
5. **Never repeat a `v4.local` nonce.** Both the encryption key and the
   authentication key are derived from the key and the nonce, so a
   repeat is a repeated keystream and a repeated authentication key.
   Thirty-two bytes drawn uniformly at random is safe. This package
   cannot check it.
6. **The current time is an argument.** `pasclaims.instant` takes Unix
   seconds the caller read. A test validates at any instant with no
   fake clock, and an audit tool can ask whether a token was valid when
   it was presented.
7. **The nonce being an argument is what makes the vectors
   reproducible.** The specification's own test vectors replay their
   nonce, which no implementation that picks its own can do.
8. **The implicit assertion must match at both ends.** A token
   encrypted or signed under one assertion does not verify under
   another, and the difference is invisible to whoever holds the token.
   Pass `pasclaims.no_implicit()` when there is none.
9. **The footer is authenticated, not encrypted.** Anything in it is
   readable by whoever holds the token.
10. **PAE clears the top bit of every length field.** It is a
    specification rule, and the reason is that a length above 2^53 is
    not exact as a double, so a language whose integers are doubles
    would encode a different number than it read.
11. **A PASERK identifier is 33 bytes, not 32.** The truncation is
    chosen so the base64url encoding is a whole number of characters.
    An implementation that truncated to 32 produces identifiers of the
    right shape that disagree with every other implementation.
12. **A `k4.secret.` string is 64 bytes**: the 32-byte seed and then
    the 32-byte public key. `paserk.secret_from_string` checks that the
    two halves agree rather than trusting them, because a mismatched
    pair is a key file somebody edited, and accepting it produces a
    signer whose tokens nobody can verify.
13. **A policy has no algorithm list**, unlike a JWT policy. There is
    nothing to allow. `paspolicy.strict()` requires an expiry, an
    issuer and an audience, and the builders narrow it.
14. **Timestamps are RFC 3339 strings, not numbers.**
    `pasclaims.parse_timestamp` and `format_timestamp` are the
    conversion.

## Sizes

| Quantity | Bytes |
| --- | --- |
| A `v4.local` key | 32 |
| An Ed25519 seed | 32 |
| An Ed25519 public key | 32 |
| An Ed25519 signature | 64 |
| A `v4.local` nonce | 32 |
| A `v4.local` authentication tag | 32 |
| A PASERK identifier, before base64url | 33 |
| A `k4.secret.` string, decoded | 64 |

## Timing behaviour

The limits of each claim are stated here exactly. They describe the source.
The compiler makes no promise about the machine code.

**The tag comparison is constant time.** `decrypt` compares the computed
BLAKE2b tag with the one in the token using `digest.ct_eq` of crypto-nv, and
`paserk.local_id_matches` compares identifiers the same way. The comparison
takes the same time whatever the position of the first difference.

**The signature check follows ed25519-nv.** `verify` calls ed25519-nv at its
`EdStrict` setting and says nothing more than that package does.

**Everything else varies with the token.** Decoding, claim parsing and policy
checking take time that depends on the length of the token and on which claim
is first refused. None of them handles a key.

## What is not included

- **Versions 1, 2 and 3.** Versions 1 and 2 are deprecated by the
  specification. Version 3, which is AES-256-CTR with HMAC-SHA-384 for
  local and ECDSA over P-384 for public, is for callers under a
  constraint to use NIST algorithms, and needs P-384 and AES, neither
  of which this package has. A `PasVersion` arm published before the
  primitives exist is a value nothing can consume.
- **PASERK's wrapping tier.** `k4.local-wrap.pie.`, `k4.seal.`,
  `k4.local-pw.` and `k4.secret-pw.` are each key encryption with their
  own vectors and failure modes, and the password ones need a
  memory-hard derivation. Half a wrapping tier is worse than none.
- **Randomness.** This package declares no effects. The `v4.local`
  nonce is the caller's.
- **A clock.** See rule 6.
- **A build for a microcontroller.** The surface is strings, byte
  buffers and lists of claims, so this package does not build for a
  microcontroller with no heap allocator. The cipher underneath,
  [chacha20-nv](https://novo-lang.org/packages/chacha20-nv), does, and so
  does [blake2-nv](https://novo-lang.org/packages/blake2-nv).

## Related packages

- [jwt-nv](https://novo-lang.org/packages/jwt-nv) is JSON Web Tokens.
  Take it when you must accept a token somebody else issues, such as
  from an identity provider, an API gateway or a partner's service,
  because the format is not yours to choose. Take this package when you
  control both ends. The two APIs are shaped alike on purpose, so a
  consumer switches by changing type names.
- [chacha20-nv](https://novo-lang.org/packages/chacha20-nv) supplies
  XChaCha20 as a raw stream cipher, which is what `v4.local` needs:
  encrypt-then-MAC with BLAKE2b, not an authenticated encryption
  scheme. Reaching for XChaCha20-Poly1305 because the names look
  similar produces tokens no other implementation can read. This
  package depends on it.
- [ed25519-nv](https://novo-lang.org/packages/ed25519-nv) supplies
  `v4.public`'s signing and verification and its key types. This
  package depends on it.
- [calendar-nv](https://novo-lang.org/packages/calendar-nv) is the RFC
  3339 timestamps the claims are written as. This package depends on
  it.
- [base64-nv](https://novo-lang.org/packages/base64-nv) is the
  base64url without padding used throughout. This package depends on
  it.
- [blake2-nv](https://novo-lang.org/packages/blake2-nv) supplies keyed
  BLAKE2b, which is the key splitting, the tag and every PASERK identifier.
  This package depends on it.
- [crypto-nv](https://novo-lang.org/packages/crypto-nv) supplies `digest.ct_eq`,
  the constant-time comparison. This package depends on it.
- [cookie-nv](https://novo-lang.org/packages/cookie-nv) signs and
  encrypts a cookie value, which is the same job when the value never
  leaves one service.

## Tests

```bash
novo test
```

`tests/paspae_tests.nv` holds the pre-authentication encoding vectors of the
specification. `tests/generated_vectors_tests.nv` is written by
`tests/vectors/generate.py` and holds `v4.local` and `v4.public` tokens and
PASERK strings and identifiers. They come from a reference in
`tests/vectors/paseto_ref.py`, written from the specifications on Python's
`hashlib` (BLAKE2b) and the `cryptography` package (Ed25519 and the ChaCha20
block function), with HChaCha20 written out and checked against
draft-irtf-cfrg-xchacha section 2.2.1 when the file is loaded. Loading it also
reproduces the published token of PASETO test vector 4-S-1, which checks the
pre-authentication encoding, the header and the base64url framing against a
token this package did not produce. `tests/paseto_edge_tests.nv` checks that
token again through the package and covers every refusal, every policy
outcome and every accessor.

The suite asserts that PAE's length prefixes make `("ab", "c")` and
`("a", "bc")` different inputs, that the top bit of a length field is
cleared, that a PASERK identifier is 33 bytes, that a `k4.secret.` string
whose halves disagree is refused, that a local key aimed at a public token is
refused by name, that a token verified under one implicit assertion does not
verify under another, and that a changed byte is an authentication failure.

## Licence

Apache-2.0.

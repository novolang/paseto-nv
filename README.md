# paseto-nv

PASETO stands for Platform-Agnostic Security Tokens. It is a token
format in which the cryptography is fixed by the token's own prefix
rather than negotiated: there is no algorithm field to read and nothing
to downgrade to. It is specified by
[the PASETO specification](https://github.com/paseto-standard/paseto-spec),
and its key serialisation by
[PASERK](https://github.com/paseto-standard/paserk). This package
implements PASETO version 4 and PASERK's key tier in novo-lang.

**Status: NOT IMPLEMENTED — interface only.** Every function is
declared with its full signature, but every body is a `todo()` that
panics when called. The package is published so its design can be
reviewed and depended on before it is implemented. Version 0.1.0 will
be the first working release.

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

Build and test with `novo pkg build` and `novo test`. Today `novo test`
fails on purpose: almost every test reaches a
`not implemented: paseto-nv.<module>.<fn>` panic. The exceptions assert
about published constants, which are not stubs. The tests are the
specification the implementation will have to satisfy.

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

No claim is made here beyond what the primitives underneath provide.
The authentication tag comparison in `decrypt` and the signature check
in `verify` belong to the BLAKE2b and Ed25519 implementations this
package calls, and each of those packages states its own behaviour.

## What is not included

- **Versions 1, 2 and 3.** Versions 1 and 2 are deprecated by the
  specification. Version 3, which is AES-256-CTR with HMAC-SHA-384 for
  local and ECDSA over P-384 for public, is for callers under a
  constraint to use NIST algorithms, and needs P-384 and AES, neither
  of which is on the registry. A `PasVersion` arm published before the
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
  microcontroller with no heap allocator.
  [chacha20-nv](https://novo-lang.org/packages/chacha20-nv) underneath
  does.

## What is still missing underneath

`v4.local` is defined over BLAKE2b: the key splitting into
`paseto-encryption-key` and `paseto-auth-key-for-aead`, and the tag
itself. Every PASERK identifier is a BLAKE2b hash too.

[blake2-nv](https://novo-lang.org/packages/blake2-nv) 0.0.2 publishes
that primitive, and it is itself an interface release whose bodies
panic. This package does not name it as a dependency yet. The
signatures here do not change when it does.

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
- [blake2-nv](https://novo-lang.org/packages/blake2-nv) is the hash
  named above.
- [cookie-nv](https://novo-lang.org/packages/cookie-nv) signs and
  encrypts a cookie value, which is the same job when the value never
  leaves one service.

## Tests

```bash
novo test tests/paspae_tests.nv      # pre-authentication encoding
novo test tests/paskey_tests.nv      # the versions, purposes and key types
novo test tests/pasetoken_tests.nv   # decoding, verifying, decrypting
novo test tests/paspolicy_tests.nv   # what a policy accepts
novo test tests/paserk_tests.nv      # keys written down, and their identifiers
```

The oracle is the PASETO specification and the shared test vector
repository every implementation runs: `4-E-*` for local tokens, `4-S-*`
for public tokens, and the vectors under "Authentication Padding" for
PAE. The reference implementations are the Rust crate `rusty_paseto`
and Python's `pyseto`.

The suite asserts that PAE's length prefixes make `("ab", "c")` and
`("a", "bc")` different inputs, that the top bit of a length field is
cleared, that a PASERK identifier is 33 bytes, that a `k4.secret.`
string whose halves disagree is refused, that a local key aimed at a
public token is refused by name, and that a token verified under one
implicit assertion does not verify under another.

The tests compile today and fail at run, each on the
`not implemented: paseto-nv.<module>.<fn>` panic that is its body. That
is the expected state of an interface release. They turn green one at a
time as bodies land.

## Implementation status

| Item | Implemented |
| --- | --- |
| `paskey.PAS_LOCAL_KEY_BYTES`, `.PAS_SEED_BYTES`, `.PAS_PUBLIC_KEY_BYTES`, `.PAS_SIGNATURE_BYTES`, `.PAS_NONCE_BYTES`, `.PAS_MAC_BYTES` | yes (they are constants) |
| `pasclaims.PAS_CLAIM_*`, the seven names | yes (they are constants) |
| `paserk.PASERK_*` and `.PASERK_ID_BYTES` | yes (they are constants) |
| `paspae.PAE_MAX_PIECE_BYTES` | yes (it is a constant) |
| Every `pub struct` and `pub enum` in the seven modules | the types are declared |
| `paserr.describe`, `.is_authentication_failure`, `.is_policy_refusal`, `PasError.message` | no |
| `paskey.version_name`, `.purpose_name`, `.prefix`, `.parse_prefix` | no |
| `paskey.local_key`, `.local_key_bytes`, `.secret_key`, `.public_key`, `.public_key_of`, `.public_key_bytes` | no |
| `paskey.signing_key_of`, `.signature_strictness`, `.local_key_purpose` | no |
| `pasclaims.instant`, `.unix_seconds`, `.parse_timestamp`, `.format_timestamp`, `.civil_of` | no |
| `pasclaims.parse`, `.payload_json`, `.issuer`, `.subject`, `.audience`, `.token_id` | no |
| `pasclaims.expiration`, `.not_before`, `.issued_at` | no |
| `pasclaims.footer`, `.no_footer`, `.footer_text`, `.footer_is_empty` | no |
| `pasclaims.implicit`, `.no_implicit`, `.implicit_text`, `.implicit_is_empty` | no |
| `paspae.encode_len`, `.encode_into`, `.encode`, `.length_field` | no |
| `pasetoken.decode`, `.prefix_of`, `.purpose_of`, `.version_of`, `.unverified_footer`, `.has_footer` | no |
| `pasetoken.dangerous_unverified_payload_json` | no |
| `pasetoken.decrypt`, `.verify`, `.claims_of`, `.footer_of` | no |
| `pasetoken.encrypt`, `.sign`, `.pre_auth` | no |
| `paspolicy.strict`, `.requiring`, `.with_leeway`, `.allowing_no_expiration` | no |
| `paspolicy.requiring_not_before`, `.requiring_issued_at`, `.requiring_subject` | no |
| `paspolicy.issuer`, `.audience`, `.leeway_seconds`, `.check` | no |
| `paspolicy.requires_expiration`, `.requires_not_before`, `.requires_issued_at`, `.requires_subject` | no |
| `paserk.type_prefix`, `.type_of`, `.is_secret` | no |
| `paserk.local_to_string`, `.local_from_string`, `.public_to_string`, `.public_from_string` | no |
| `paserk.secret_to_string`, `.secret_from_string` | no |
| `paserk.local_id`, `.public_id`, `.secret_id`, `.local_id_matches`, `.public_id_matches` | no |

## Licence

Apache-2.0. See `LICENSE`.

<!-- docs/writing-a-readme.md is the style guide for this page. -->

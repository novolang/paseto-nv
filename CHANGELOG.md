# Changelog

All notable changes to paseto-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.0.1 — 2026-09-11

The **interface**: every signature and every effect row, and no bodies.
`stability = "draft"`, and the release is recorded `implemented = false`.

### Added

- `paskey` — `PasVersion` and `PasPurpose` as the fixed prefix that
  replaces an algorithm field, and the three key types that carry their
  own purpose.
- `pasclaims` — `PasInstant`, `PasClaims`, `PasFooter` and
  `PasImplicit`, with the registered claims parsed out of RFC 3339
  strings over calendar-nv.
- `pasetoken` — `UnverifiedPaseto` and `VerifiedPaseto`, `decode`,
  `decrypt`, `verify`, `claims_of`, the two ways to make a token, and
  `pre_auth` so the authenticated bytes can be diffed.
- `paspolicy` — `strict()` narrowed by builders, and `check` that
  refuses an unusable policy at start-up.
- `paserk` — the six key and identifier types, their strings, and the
  `kid` comparison.
- `paspae` — the pre-authentication encoding, public because the
  specification gives it vectors.
- `paserr` — one error type, with an authentication failure told apart
  from a policy refusal and from a malformed token.

### Known

- **The load-bearing interface is that the unverified state is
  unusable**, matching jwt-nv's shape so a consumer can switch formats
  by changing type names. A `v4.local` token goes further than jwt-nv
  can: its payload is ENCRYPTED, so the escape hatch refuses it.
- **There is no algorithm field**, so `paspolicy` has no `allowing`,
  and that absence is the format's advantage showing up in an API.
- **The implicit assertion has no JWT counterpart**, and binds a token
  to a context it never carries.
- **BLAKE2b is a MISSING ROW** — `blake2-nv`, crypto/core, P0. The key
  splitting, the MAC and every PASERK identifier need it, and argon2-nv
  already named the same gap from the other direction.
- **The clock and the 32-byte v4.local nonce are the caller's**, which
  is what keeps this `core` and what lets a test replay the
  specification's own vectors byte for byte.
- **v4.local is encrypt-then-MAC, not an AEAD.** It uses chacha20-nv's
  RAW `cc20x.xapply_into`; a port that reached for XChaCha20-Poly1305
  because the names look similar would produce unreadable tokens.
- **chacha20-nv is a PATH dependency in the development tree** and must
  become `^0.0.1` before publish.
- v1, v2 and v3, and PASERK's wrapping tier, are named as outside with
  the reason in each case.
- No device claim and no probe.

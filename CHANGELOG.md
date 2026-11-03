# Changelog

All notable changes to paseto-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0 — 2026-10-30

PASETO v4 `local` and `public`, and PASERK keys and identifiers.
`stability = "experimental"` and the toolchain floor is `novo >= 0.22.0`.

### Added

- `pasetoken`: `decode`, `decrypt`, `verify`, `encrypt`, `sign`, `pre_auth`
  and the readers of an unverified and a verified token. `v4.local` is
  XChaCha20 under keys split from the key and the nonce with keyed BLAKE2b,
  and a keyed BLAKE2b tag over the pre-authentication encoding. `v4.public`
  is Ed25519 at `EdStrict`.
- `paspae`, `paskey`, `pasclaims`, `paspolicy`, `paserk` and `paserr`: the
  bodies of the interface of 0.0.4.
- The policy is applied inside `decrypt` and `verify`, after the MAC or the
  signature has passed, in this order: the policy is usable, the payload is a
  claims object, the issuer, the audience, `exp`, `nbf`, then the required
  `iat` and `sub`. A token is expired when the instant is at or past `exp`
  plus the leeway, and not yet valid when the instant plus the leeway is
  before `nbf`.
- Dependencies: blake2-nv `^0.1`, chacha20-nv `^0.1`, ed25519-nv `^0.1`,
  crypto-nv `^0.1.7` (for `digest.ct_eq`), calendar-nv `^0.2.0` and
  base64-nv `^0.1.1`.
- Tests: the vectors of `paspae`, tokens and PASERK strings from a reference in
  `tests/vectors/paseto_ref.py`, the published token of PASETO test vector
  4-S-1, and `tests/paseto_edge_tests.nv`.

### Changed

- The parameter of `pasclaims.parse` is named `text`, not `json`, because a
  parameter named `json` hides the standard `json` module inside the function.
  A call passes it by position and is unaffected.
- `pasclaims.format_timestamp` writes `+00:00`, as documented, and not `Z`.
- `pasetoken.encrypt` refuses a nonce that is not 32 bytes with
  `PasKeyLengthWrong(got, 32)`.
- `paserk.secret_from_string` refuses a pair whose public half is not the
  seed's with `PasBadPaserkData`.
- Fixture of `tests/paskey_tests.nv`: the `v4.local` token that two tests
  decode had a 27-byte payload, which `decode` refuses as too short by its own
  documentation. The payload is now 66 bytes. No assertion changed.
- `tests/paspolicy_tests.nv` names the `iso8601` module it uses. The release
  stamp paragraphs are removed from the tests.

### Known

- The PASERK identifier is BLAKE2b with a 33-byte digest over the identifier
  prefix followed by the key's PASERK string. It was written from the PASERK
  specification and has not been compared with a published identifier vector.
- The `v4.local` construction was checked against a reference written from the
  specification, not against the published `4-E-*` tokens, which were not
  available offline. The `v4.public` side is checked against the published
  token of vector 4-S-1.

This release requires novo 0.23.0 or later.

## 0.0.5 — 2026-10-28

The dependency requirement is raised: `chacha20-nv` from ^0.0.1 to ^0.0.5.  The newest version of each builds with no migration warning under the 0.22.0 compiler, and the older one drew E2050, E2052 or E2055 warnings into this package's build.  No signature and no behaviour changed.

## 0.0.4 — 2026-10-25

A call that passes a variable to a `var` parameter now writes the `var` marker, which the 0.21.1 compiler asks for (E2050).  The package needs Novo 0.21.1 or later.  A file that names a sibling module's type, function or constant now has the `use` line for that module (E2033, E2003).  No signature and no behaviour changed.

## 0.0.3 — 2026-09-28

The dependency ranges move to the dependencies' current releases.  A
pre-1.0 caret range admits only the release it names, so the old
ranges held this package on interface releases, and a program could
not take this package beside those packages' current releases.  No
signature in this package changed.

- calendar-nv: `^0.0.2` to `^0.2.0`.
- base64-nv: `^0.0.1` to `^0.1.1`.

## 0.0.2 — 2026-09-15

README rewritten to the package README style guide (docs/writing-a-readme.md); no change to the interface.

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

### Design notes

Two statements in the 0.0.1 README have gone stale and are recorded
here rather than repeated on the page. It said chacha20-nv was a path
dependency that had to become a registry range before publish; the
manifest has carried `chacha20-nv = "^0.0.1"` since that release. It
also said nothing on the registry published BLAKE2b and proposed
`blake2-nv` as a new row; blake2-nv 0.0.2 is now published, as an
interface. The module headers of `pasetoken` and `paserk` still say the
row is missing, and they are left alone because this release changes no
source.

PASETO exists beside jwt-nv because every classic JWT vulnerability
follows from one decision: the token tells the verifier which algorithm
to use, in a header the attacker also controls. jwt-nv closes each of
them by construction. PASETO removes the question instead.

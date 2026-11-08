# XEdDSA

**Status:** implemented, **superseded** by Ed256189, experimental, not
independently audited.

XEdDSA is the original signature scheme of this package: an x-only
Schnorr-style signature over the Montgomery form of Curve256189. It is kept for
backwards compatibility because its 32-byte public keys are the same keys used
by X256189 ECDH, and because `BatchVerify` is specific to this scheme. New
protocols should use Ed256189.

This document records the exact profile implemented here. It is **not** a
description of Signal's XEdDSA and is **not** wire-compatible with it. The two
schemes share a name and a general design idea, but not a byte format.

---

## 1. Summary

| Property | Value |
|---|---|
| Curve | Montgomery `y² = x³ + A·x² + x` |
| Field | `p = 2²⁵⁶ − 189` |
| Hash | SHA-512 |
| Seed / private key | 32 bytes |
| Public key | 32 bytes (`x(P)` little-endian) |
| Signature | 64 bytes (`x(R)` 32 bytes, then `s` 32 bytes little-endian) |
| Cofactor | 4 |
| Subgroup order | 254-bit prime `n` |
| Key derivation | SHA-512, clamp, reduce, then multiply by 4 |
| Canonical points | even-`y` representatives for both `P` and `R` |
| Nonce | deterministic, domain-separated, 4-byte retry counter |
| Verification | strict, exact, non-cofactored, prime-order subgroup checks |
| Batch verification | random linear combination; strict per-input validation |
| Variants | pure only; no context and no prehash |

XEdDSA public keys are identical to X256189 public keys derived from the same
seed. XEdDSA signatures are unrelated to Ed256189 signatures and cannot be
verified by Ed256189, or vice versa.

---

## 2. Parameters

### 2.1 Field

```
p = 2^256 − 189
  = 115792089237316195423570985008687907853269984665640564039457584007913129639747
  = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43
```

`p` is prime and `p ≡ 3 (mod 4)`, so a square root of a quadratic residue `u`
is `u^((p+1)/4) mod p`.

### 2.2 Curve

```
E: y² = x³ + A·x² + x
A = 479597
```

The Montgomery curve is birationally equivalent to the twisted Edwards curve
used by Ed256189, but XEdDSA never performs Edwards arithmetic. All operations
in this scheme are Montgomery operations.

### 2.3 Group structure

```
#E = 4 · n
n = 28948022309329048855892746252171976963257918617752773869725216245594308445583
```

`n` is prime and has 254 bits. The cofactor is `h = 4`. The group has the point
at infinity, one point of order 2, two points of order 4, and a prime-order
subgroup of order `n`.

### 2.4 Generator

```
Gx = 107794463287790729181798923754704247240057009056848862892287801730172665808003
Gy = 5935226473593038842940459288042955305454636525326183552707973708623513097342
```

`G` is the standard Curve256189 base point. It has order `n`.

---

## 3. Encoding

All integers are encoded little-endian, following the RFC 7748 convention.

| Value | Size | Encoding |
|---|---|---|
| Seed / private key | 32 bytes | opaque seed |
| Public key | 32 bytes | `x(P)` little-endian |
| Signature | 64 bytes | `x(R) ‖ s` |
| `x(R)` | 32 bytes | little-endian |
| `s` | 32 bytes | little-endian, canonical `s < n` |

There is no sign bit, version byte, or parity byte in the wire format. An
x-coordinate determines a point only up to sign; XEdDSA resolves that ambiguity
by always using the even-`y` representative.

---

## 4. Key derivation

Given a 32-byte seed:

```
digest  = SHA-512(seed)
skBytes = digest[0..32]
skBytes[0]  &= 0xfc        # clear bits 0 and 1
skBytes[31] &= 0x7f        # clear bit 255
skBytes[31] |= 0x40        # set bit 254
sk      = LE(skBytes) mod n
if sk == 0: sk = 1
a0      = (4 · sk) mod n
```

The multiplication by 4 is cofactor clearing. It makes the public key

```
P = [a0]G
```

identical to the X256189 public key derived from the same seed.

Finally the signer canonicalises the key pair to an even-`y` point. Let
`a = a0` and `P0 = [a0]G`. If `P0.y` is even, set `a = a0` and `P = P0`.
Otherwise set

```
a = (n − (a0 mod n)) mod n
P = −P0
```

The x-coordinate is unchanged, so the public key bytes do not change. The
scalar `a` is the one used for signing. `a` is non-zero for every valid seed.

The nonce prefix is

```
prefix = digest[32..64]
```

and is secret. It is used only for deterministic nonce derivation.

`XEdDSA.publicKeyFromSeed(seed)` performs the same derivation and returns only
`x(P)`. `XEdDSA.generateKeyPair(seed)` returns the seed as `privateKey` and
`x(P)` as `publicKey`.

---

## 5. Canonical even-y points

For an x-coordinate `x`, the curve equation gives

```
y² = x³ + A·x² + x.
```

When the right-hand side is a non-zero quadratic residue, there are two
solutions `y` and `−y`. XEdDSA always selects the solution with even `y`. The
point at infinity is never a valid encoded point.

Decoding rejects:

* `x <= 0` or `x >= p`,
* a right-hand side that is not a quadratic residue.

In particular `x = 0` (the order-2 point) is rejected by the decoder, and
`x = p − 1` (an order-4 point) is rejected later by the subgroup check.

The same rule is applied to both the public key `P` and the signature point `R`.
It removes the sign ambiguity without spending a bit in the encoding.

---

## 6. Nonce derivation

The domain separator is the ASCII string

```
Curve256189-XEdDSA-v1
```

(21 bytes). Nonce derivation uses the tag `0x01`:

```
counter = 0
loop:
    digest = SHA-512(domain ‖ 0x01 ‖ prefix ‖ LE32(counter) ‖ message)
    r0 = LE(digest) mod n
    if r0 != 0: return r0
    counter += 1
```

`LE32(counter)` is a 4-byte little-endian counter. The retry is included for
completeness; a zero result is negligible.

Because `prefix` is secret and `message` is bound into the hash, signing is
deterministic: the same seed and message always produce the same signature.
No random number generator is needed for signing.

---

## 7. Challenge

The challenge uses the tag `0x02`:

```
h = LE(SHA-512(domain ‖ 0x02 ‖ x(R) ‖ x(P) ‖ message)) mod n
```

`x(R)` and `x(P)` are exactly 32 bytes each, so the concatenation is
unambiguous. The challenge binds the signer's public key, the nonce point, and
the message.

---

## 8. Signing

Given a 32-byte seed and a message:

1. Derive `a`, `P`, and `prefix` as in [§4](#4-key-derivation).
2. Derive `r0` as in [§6](#6-nonce-derivation).
3. Compute `R0 = [r0]G` and canonicalise the pair `(r0, R0)` to even `y`,
   obtaining `(r, R)` exactly as in key derivation.
4. Encode `xR = x(R)` and `xP = x(P)` as 32-byte little-endian values.
5. Compute `h` as in [§7](#7-challenge).
6. Compute

   ```
   s = (r + h·a) mod n
   ```

7. Output

   ```
   signature = xR ‖ LE32(s)
   ```

The scalar multiplication for `[r0]G` uses the same blinding path as key
derivation. Signing never uses Edwards arithmetic.

---

## 9. Verification

Given a message, a 64-byte signature, and a 32-byte public key:

1. Require `signature.length == 64` and `publicKey.length == 32`.
2. Split `xR = signature[0..32]` and `s = LE(signature[32..64])`.
3. Require `s < n`.
4. Decode `R` from `xR` using the canonical even-`y` rule.
5. Decode `P` from `publicKey` using the canonical even-`y` rule.
6. Require both `R` and `P` to be non-identity points of the prime-order
   subgroup, i.e. `[n]R = O` and `[n]P = O`.
7. Compute `h` as in [§7](#7-challenge).
8. Accept exactly when the full-point equation holds:

   ```
   [s]G == R + [h]P
   ```

The equation is **exact** and **non-cofactored**. Verification does not accept
the weaker cofactored form `[4s]G == [4]R + [4h]P`, and it does not skip the
subgroup checks.

Every malformed input returns `false`; verification does not throw for wrong
lengths or invalid point encodings.

---

## 10. Batch verification

`BatchVerify.verify` accepts a list of `SignatureBundle` values, each holding a
message, a 64-byte signature, and a 32-byte public key.

* An empty batch returns `true`.
* A batch with one element delegates to `XEdDSA.verify`.
* A batch with `m ≥ 2` elements uses the following procedure.

For each bundle `i`:

1. Validate it with the same parser used by individual verification. Every
   length, canonical-`s`, even-`y`, and subgroup rule is identical.
2. Compute `h_i` as in [§7](#7-challenge).
3. Sample a random non-zero scalar `z_i` in `[1, n)`.

Accumulate

```
LHS = (Σ z_i·s_i) mod n
RHS = Σ z_i·R_i + Σ (z_i·h_i)·P_i
```

and accept exactly when

```
[LHS]G == RHS
```

as full points.

The random coefficients prevent an attacker from making two invalid
signatures cancel. If any input is invalid, the probability of a false accept
is negligible.

### Performance caveat

`Montgomery.multiScalarMul` is currently a loop of independent full scalar
multiplications. It does not share doublings between terms. Consequently, a
batch of `m` signatures currently costs about `4m + 1` scalar multiplications,
while verifying the same signatures individually costs about `4m`. Batch
verification is therefore an API convenience today, not a throughput
optimisation. Real multi-scalar multiplication and fixed-base precomputation
are planned separately.

---

## 11. Domain separation and protocol isolation

The domain separator `Curve256189-XEdDSA-v1` and the distinct nonce and
challenge tags keep XEdDSA transcripts separate from other protocols.

Ed256189 uses a different curve model, a different key derivation, different
byte formats, and a different domain separator. An XEdDSA signature cannot be
parsed as an Ed256189 signature, and an Ed256189 signature cannot be parsed as
an XEdDSA signature. The two schemes must never be treated as interchangeable.

X256189 performs ECDH and has no signature transcript, so there is no direct
hash-domain collision with XEdDSA. Key reuse between X256189 and XEdDSA is
intentional and is the reason XEdDSA exists.

---

## 12. Relation to X256189

XEdDSA and X256189 use the same 32-byte seed and the same public key:

```
XEdDSA.generateKeyPair(seed)['publicKey']
  == X256189.generateKeyPair(seed)['publicKey']
```

Both derive the secret scalar by hashing the seed, clamping, reducing modulo
`n`, and multiplying by 4. XEdDSA then uses that scalar for signing; X256189
uses it for ECDH. This lets a peer that already has an X256189 key sign with
the same key material without publishing a second public key.

The schemes are still distinct protocols. Applications should make the key
usage explicit and should not assume that a signature proves anything about an
ECDH session key beyond possession of the same seed.

---

## 13. Relation to Ed256189

| | XEdDSA | Ed256189 |
|---|---|---|
| Curve model | Montgomery | dual Edwards `E_{d,a}` |
| Public key | 32 bytes, `x(P)` | 33 bytes, `v(P) ‖ parity(u(P))` |
| Signature | 64 bytes, `x(R) ‖ s` | 65 bytes, `R ‖ S` |
| Key derivation | clamp, reduce, `×4` | RFC 8032 pruning, no `×4` |
| Key reuse with X256189 | yes | no |
| Verification | exact, non-cofactored | exact, non-cofactored |
| Batch | `BatchVerify` | `Ed256189BatchVerify` |

Ed256189 is the intended replacement for new protocols. XEdDSA remains the
compatibility and x-only profile.

---

## 14. Deviations from Signal XEdDSA

This scheme is called XEdDSA because it follows the same high-level idea: sign
with a Montgomery/x-only key using a Schnorr-style equation. It is not Signal's
XEdDSA and is not wire-compatible with it.

| Aspect | This profile | Signal XEdDSA |
|---|---|---|
| Curve | Curve256189 | Curve25519 |
| Public key encoding | raw Montgomery `x`, 32 bytes | Montgomery `u`, 32 bytes |
| Point sign handling | canonical even-`y` | Edwards sign bit / negation conventions |
| Key derivation | clamp, reduce, `×4` to match X256189 | Curve25519 clamping and Edwards conversion |
| Transcript | explicit domain string and tags | Signal-specific hash transcript |
| Verification | strict prime-order subgroup checks, exact non-cofactored equation | Signal's Curve25519 verification rules |
| Variants | pure only | defined by the Signal specification |
| Wire compatibility | none | none |

In particular, do not feed an XEdDSA signature to a Signal XEdDSA verifier, or
the reverse. The transcript and key conversion differ.

---

## 15. Edge cases and rejection rules

### Key generation and signing

* A seed whose length is not exactly 32 bytes throws `ArgumentError`.
* An empty message is allowed.
* A message of any length is allowed; it is hashed directly.
* Signing is deterministic.
* `s = 0` is not explicitly rejected at signing time, but it occurs only with
  negligible probability for an honest signer.

### Verification

The following all return `false`:

* signature length not 64 bytes,
* public key length not 32 bytes,
* `s >= n`,
* `x(R)` or `x(P)` equal to 0,
* `x(R)` or `x(P)` greater than or equal to `p`,
* an x-coordinate whose right-hand side is not a quadratic residue,
* an order-2 or order-4 point,
* a mixed-order point,
* any point not in the prime-order subgroup,
* a failed exact equation.

Verification never throws for malformed byte strings. It is safe to call on
untrusted input.

### Batch verification

* Empty batch: `true`.
* Single element: delegated to `XEdDSA.verify`.
* Any invalid element makes the whole batch `false`.
* The same strict parser is used for individual and batch verification, so the
  two paths cannot drift apart.

---

## 16. Security notes

* **Deterministic nonces.** The nonce is derived from a secret prefix and the
  message. Reusing a seed with the same message reproduces the same signature;
  this is intentional. The prefix must remain secret.
* **Subgroup validation.** Both `R` and `P` must be non-identity points of the
  prime-order subgroup. This rejects small-subgroup and mixed-order inputs.
* **Exact equation.** The non-cofactored equation is stricter than a cofactored
  variant and matches the signing equation exactly.
* **Domain separation.** The domain string and tags prevent transcript reuse
  across schemes.
* **Batch soundness.** Random non-zero coefficients make cancellation attacks
  infeasible. Batch verification does not weaken the per-signature checks.
* **Not constant-time.** The implementation uses Dart `BigInt`. Arithmetic,
  inversion, and scalar multiplication are not guaranteed constant-time.
  Secret-dependent timing and cache behaviour are outside the guarantees of
  this library. Do not deploy it where local side channels are in scope without
  an independent constant-time implementation.
* **Not audited.** This is experimental cryptography. Treat it accordingly.

---

## 17. API

```dart
import 'package:curve256189/curve256189.dart';
import 'dart:typed_data';

final seed = Uint8List(32); // cryptographically random seed

// Key generation.
final keyPair = XEdDSA.generateKeyPair(seed);
final publicKey = XEdDSA.publicKeyFromSeed(seed);

// Sign and verify.
final message = Uint8List.fromList('Hello!'.codeUnits);
final signature = XEdDSA.sign(message, keyPair['privateKey']!);
final valid = XEdDSA.verify(message, signature, publicKey);

// Batch verification.
final ok = BatchVerify.verify([
  SignatureBundle(
    message: message,
    signature: signature,
    publicKey: publicKey,
  ),
]);
```

Public constants:

```dart
XEdDSA.seedLength      // 32
XEdDSA.publicKeyLength // 32
XEdDSA.signatureLength // 64
```

Helper:

```dart
XEdDSA.challengeFor(xR, xP, message) // BigInt in [0, n)
```

`challengeFor` requires `xR.length == 32` and `xP.length == 32`; otherwise it
throws `ArgumentError`. It is exposed so that batch verification and external
tooling can reproduce the challenge exactly.

---

## 18. Test vectors and coverage

`test/xeddsa_vectors.dart` contains 16 known-answer vectors generated by the
independent Python reference in `tool/xeddsa_vectors.py`. The generator uses
only the Python standard library and shares no code with the Dart package.

The vector matrix is 4 seeds × 4 messages:

* seeds: `seed0`, `seed1`, `seed7`, and the Ed25519 test seed,
* messages: empty, `"abc"`, `"Hello Curve256189!"`, and a 1000-byte pattern.

The pre-existing anchor vector is preserved:

```
seed      = 0102030405060708090a0b0c0d0e0f10
            1112131415161718191a1b1c1d1e1f20
message   = 48656c6c6f20437572766532353631383921
            ("Hello Curve256189!")
publicKey = 337d3142bff70cdcbe04d69ee7b7a36c
            3e8df6bba0a5e0a12cb4b1b580bab424
signature = c87e2d535cab5c2ede5993907c4c8d97
            aa6be84dd9de5b0b4b39e56d4d084284
            ee7a80cfbff274f44f74b7a03b49b744
            c481f702a80c35a93ff03ad11cef142e
```

Any change to key derivation, canonicalisation, nonce derivation, challenge
construction, or signing must leave this vector unchanged. If it does not, the
change is a wire-format break and requires a new scheme name and a version bump.

`test/xeddsa_test.dart` covers:

* key generation and the X256189 key relation,
* `publicKeyFromSeed`,
* all 16 independent vectors,
* the legacy anchor regression,
* malformed lengths, non-canonical scalars, and invalid x-coordinates,
* low-order and mixed-order points,
* no-throw behaviour on random inputs,
* protocol separation from Ed256189,
* ECDH plus XEdDSA key reuse.

`test/batch_verify_test.dart` covers:

* agreement between batch and individual verification,
* an invalid entry at every position,
* low-order and mixed-order entries,
* empty and single-element batches,
* large batches and repeated signers,
* repeated randomised runs to catch flakiness from the batch coefficients.

Reproduce the generated vectors with:

```bash
python tool/xeddsa_vectors.py --dart test/xeddsa_vectors.dart
```

---

## 19. References

* [RFC 7748 — Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748)
* [RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
* [Signal XEdDSA specification](https://signal.org/docs/specifications/xeddsa/)
* [SafeCurves](https://safecurves.cr.yp.to/)
* [doc/ed256189.md](ed256189.md) — the Ed256189 scheme

# Security Policy

## Status

Curve256189 is **beta software** and has **not been independently audited**.
Do not use it to protect data whose loss would be catastrophic.

## Supported versions

| Version | Supported |
|---|---|
| `1.0.0-beta.x` | Yes (current pre-release line) |
| earlier versions | No |

Only the latest `1.0.0-beta.x` release receives fixes.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting:

<https://github.com/elregann/Curve256189/security/advisories/new>

Do not open a public issue for a suspected vulnerability. Please include:

- the affected version or commit,
- a minimal reproduction,
- expected versus actual behaviour,
- an impact assessment if you have one.

We aim to acknowledge a report within 7 days and to provide a remediation plan
within 30 days. There is no bug bounty.

## Known limitations

These are properties of the current implementation, not hypothetical issues.

1. **Not constant-time.** The library uses Dart `BigInt`. Its operations are not
   guaranteed to run in constant time, and the VM may allocate, normalise and
   branch in data-dependent ways. Timing, cache and allocation side channels
   cannot be ruled out. This matters most for operations on secret scalars
   (ECDH, signing, blinding).
2. **No independent audit.** Correctness is supported by test vectors, property
   tests and the SageMath scripts in `tool/`, not by a third-party review.
3. **No fault-attack or memory hardening.** Secret values are not zeroised, and
   the library does not defend against an attacker who can induce faults or read
   process memory.
4. **Caller-supplied randomness.** Key generation takes a 32-byte seed; the
   library does not generate it. Use a cryptographically secure random source.
   `Random.secure()` is used internally for scalar blinding and batch
   verification scalars only.
5. **Nonce management.** AES-GCM requires a unique nonce for every message under
   a key. The library does not track or enforce this; the caller must.
6. **Superseded XEdDSA.** XEdDSA is kept for compatibility only. New designs
   should use Ed256189.
7. **Beta API and parameter stability.** The public API, and before `1.0.0` the
   wire formats, may change. The move from `A = 479597` to `A = 61370` was a
   breaking parameter change: keys, signatures and shared secrets are not
   compatible across it.

## Design properties relevant to security

- All eleven SafeCurves criteria, verified with
  `tool/safecurves_curve256189.sage`.
- Cofactor `(4, 4)`; prime subgroup orders on the curve and its twist.
- Complete addition on the dual Edwards model `E_{d,a}`.
- Strict decoding and prime-order subgroup checks for public keys, `R` and
  signatures.
- Deterministic, domain-separated nonces for Ed256189 and XEdDSA.
- Canonical `S < n` and rejection of malleated signatures.
- No `BigInt.modPow`; modular exponentiation uses a checked square-and-multiply.

## Scope

Reports about the following are in scope:

- incorrect or non-canonical decoding and validation,
- subgroup or cofactor mistakes,
- signature malleability or forgery,
- ECDH invalid-curve or small-subgroup attacks,
- test vectors that do not match the documented algorithm,
- discrepancies between `doc/` and the implementation.

Out of scope: attacks that require the private key, attacks on the host OS, and
issues that only restate the non-constant-time caveat unless they demonstrate a
practical key recovery.

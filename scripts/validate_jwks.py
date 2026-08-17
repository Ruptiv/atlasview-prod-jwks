#!/usr/bin/env python3
"""Validate memory-bus/jwks.json as a production authentication trust root.

This repository's jwks.json is fetched directly by the Memory Bus verifier
(MEMORY_BUS_JWKS_URL points at raw.githubusercontent.com/.../main/memory-bus/jwks.json),
so any content merged to main is immediately trusted to authenticate production
requests. That makes an unreviewed, unvalidated commit here a direct
authentication bypass. This script is the mechanical half of that gate.

Checks, in rough order of severity:

  1. No private key material. A JWKS is public by definition; a leaked `d`
     would hand an attacker the signing key.
  2. No silent mutation of an existing kid. Rotation must ADD a new kid, never
     repoint an existing one at different key material — verifiers cache by kid,
     so an in-place swap is indistinguishable from a key substitution attack.
  3. Structural/cryptographic sanity: EC P-256 / ES256 only, unique kids,
     32-byte coordinates, and the point actually lies on the P-256 curve.

Usage:
    validate_jwks.py <jwks.json> [--baseline <previous jwks.json>]

Exits non-zero with all findings printed. Stdlib only, no dependencies.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys

# NIST P-256 (secp256r1) domain parameters, for the on-curve check.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_A = P256_P - 3  # a = -3 mod p

COORD_BYTES = 32

# Any of these appearing in a published JWK means private material leaked.
PRIVATE_MEMBERS = (
    "d",   # EC / OKP private scalar, RSA private exponent
    "p", "q", "dp", "dq", "qi", "oth",  # RSA CRT factors
    "k",   # symmetric key
)


def b64url_decode(value: str) -> bytes:
    """Decode unpadded base64url, rejecting non-canonical input."""
    if value != value.strip():
        raise ValueError("has surrounding whitespace")
    if "=" in value or "+" in value or "/" in value:
        raise ValueError("is not unpadded base64url (found '=', '+', or '/')")
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def on_p256_curve(x: int, y: int) -> bool:
    """True when (x, y) satisfies y^2 = x^3 + ax + b (mod p) for P-256."""
    if not (0 <= x < P256_P and 0 <= y < P256_P):
        return False
    left = (y * y) % P256_P
    right = (pow(x, 3, P256_P) + P256_A * x + P256_B) % P256_P
    return left == right


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def key_material(jwk: dict) -> tuple:
    """The identity of a key, for detecting in-place substitution."""
    return (jwk.get("kty"), jwk.get("crv"), jwk.get("x"), jwk.get("y"))


def validate_key(index: int, jwk: dict, errors: list) -> str | None:
    """Validate one JWK. Returns its kid when usable for cross-key checks."""
    where = f"keys[{index}]"

    if not isinstance(jwk, dict):
        errors.append(f"{where}: not a JSON object")
        return None

    for member in PRIVATE_MEMBERS:
        if member in jwk:
            errors.append(
                f"{where}: contains private key member {member!r} — a published "
                f"JWKS must never carry private material. Treat this key as "
                f"COMPROMISED and rotate it, do not merely delete the field."
            )

    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid:
        errors.append(f"{where}: missing or non-string 'kid'")
        kid = None

    if jwk.get("kty") != "EC":
        errors.append(f"{where}: kty must be 'EC', got {jwk.get('kty')!r}")
    if jwk.get("crv") != "P-256":
        errors.append(f"{where}: crv must be 'P-256', got {jwk.get('crv')!r}")
    if jwk.get("alg") != "ES256":
        errors.append(f"{where}: alg must be 'ES256', got {jwk.get('alg')!r}")

    use = jwk.get("use")
    if use is not None and use != "sig":
        errors.append(f"{where}: use must be 'sig' when present, got {use!r}")

    coords = {}
    for name in ("x", "y"):
        raw = jwk.get(name)
        if not isinstance(raw, str) or not raw:
            errors.append(f"{where}: missing or non-string '{name}'")
            continue
        try:
            decoded = b64url_decode(raw)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            errors.append(f"{where}: '{name}' {exc}")
            continue
        if len(decoded) != COORD_BYTES:
            errors.append(
                f"{where}: '{name}' decodes to {len(decoded)} bytes, "
                f"expected {COORD_BYTES} for P-256"
            )
            continue
        coords[name] = int.from_bytes(decoded, "big")

    if len(coords) == 2 and not on_p256_curve(coords["x"], coords["y"]):
        errors.append(
            f"{where}: (x, y) is not a point on the P-256 curve — the key is "
            f"corrupt or was not generated for this curve"
        )

    return kid


def main() -> int:
    # Findings are the whole product of this script, so never let a console's
    # default codepage turn one into a UnicodeEncodeError or a mangled glyph.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jwks", help="path to the jwks.json under validation")
    parser.add_argument(
        "--baseline",
        help="path to the previous jwks.json, to detect in-place key mutation",
    )
    args = parser.parse_args()

    errors: list[str] = []

    try:
        document = load(args.jwks)
    except json.JSONDecodeError as exc:
        print(f"FAIL {args.jwks}: not valid JSON: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"FAIL {args.jwks}: cannot read: {exc}", file=sys.stderr)
        return 1

    if not isinstance(document, dict):
        print(f"FAIL {args.jwks}: top level must be a JSON object", file=sys.stderr)
        return 1

    keys = document.get("keys")
    if not isinstance(keys, list) or not keys:
        print(
            f"FAIL {args.jwks}: 'keys' must be a non-empty array — publishing an "
            f"empty JWKS breaks authentication for every verifier",
            file=sys.stderr,
        )
        return 1

    extra = set(document) - {"keys"}
    if extra:
        errors.append(f"unexpected top-level members: {sorted(extra)}")

    kids: list[str] = []
    for index, jwk in enumerate(keys):
        kid = validate_key(index, jwk, errors)
        if kid:
            kids.append(kid)

    duplicates = sorted({k for k in kids if kids.count(k) > 1})
    if duplicates:
        errors.append(
            f"duplicate kid(s) {duplicates} — a verifier resolving a kid to two "
            f"different keys has undefined behavior"
        )

    # The anti-substitution check: an existing kid must keep its exact material.
    if args.baseline:
        try:
            base = load(args.baseline)
            base_keys = base.get("keys") or []
        except (OSError, json.JSONDecodeError) as exc:
            print(f"WARN baseline unreadable, skipping mutation check: {exc}")
            base_keys = None

        if base_keys is not None:
            base_by_kid = {
                k.get("kid"): k for k in base_keys if isinstance(k, dict) and k.get("kid")
            }
            new_by_kid = {
                k.get("kid"): k for k in keys if isinstance(k, dict) and k.get("kid")
            }
            for kid, base_key in base_by_kid.items():
                incoming = new_by_kid.get(kid)
                if incoming is None:
                    print(
                        f"NOTE kid {kid!r} was removed. Confirm every verifier's "
                        f"JWKS cache has expired and no unexpired token was signed "
                        f"by it before merging."
                    )
                    continue
                if key_material(incoming) != key_material(base_key):
                    errors.append(
                        f"kid {kid!r} kept its name but its key material CHANGED. "
                        f"Rotation must publish a NEW kid; repointing an existing "
                        f"one is indistinguishable from key substitution and will "
                        f"silently break or hijack cached verifiers."
                    )
            for kid in sorted(set(new_by_kid) - set(base_by_kid)):
                print(f"NOTE new kid {kid!r} added.")

    if errors:
        print(f"FAIL {args.jwks}: {len(errors)} problem(s):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"OK {args.jwks}: {len(keys)} key(s) valid: {', '.join(kids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

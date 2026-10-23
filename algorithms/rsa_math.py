"""Educational RSA arithmetic and CRT helpers.

These functions demonstrate number-theoretic operations. They are not a
cryptographic library and must never protect real data or private keys.
"""

from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """Return the non-negative greatest common divisor using Euclid's method."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return ``(g, x, y)`` such that ``g = gcd(a, b) = a*x + b*y``."""
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    x = old_s if a >= 0 else -old_s
    y = old_t if b >= 0 else -old_t
    return old_r, x, y


def mod_inverse(value: int, modulus: int) -> int:
    """Return the multiplicative inverse of ``value`` modulo ``modulus``."""
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")
    divisor, coefficient, _ = extended_gcd(value, modulus)
    if divisor != 1:
        raise ValueError("value has no inverse for this modulus")
    return coefficient % modulus


def modular_power(base: int, exponent: int, modulus: int) -> int:
    """Compute ``base**exponent % modulus`` with square-and-multiply."""
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    result = 1 % modulus
    factor = base % modulus
    power = exponent
    while power:
        if power & 1:
            result = (result * factor) % modulus
        factor = (factor * factor) % modulus
        power >>= 1
    return result


def crt_combine(residue_p: int, residue_q: int, p: int, q: int) -> int:
    """Combine two residues for coprime moduli using the CRT."""
    if p <= 1 or q <= 1:
        raise ValueError("CRT moduli must be greater than 1")
    if gcd(p, q) != 1:
        raise ValueError("CRT moduli must be coprime")
    q_inverse_mod_p = mod_inverse(q, p)
    multiplier = ((residue_p - residue_q) * q_inverse_mod_p) % p
    return (residue_q + multiplier * q) % (p * q)


def rsa_private_operation_crt(ciphertext: int, p: int, q: int, private_exponent: int) -> int:
    """Apply the educational RSA private operation with CRT recombination.

    ``p`` and ``q`` must be distinct RSA primes and ``private_exponent`` must
    be the matching private exponent. This implementation is intentionally
    unsuitable for protecting real data.
    """
    if p <= 1 or q <= 1 or p == q or gcd(p, q) != 1:
        raise ValueError("p and q must be distinct coprime integers greater than 1")
    if private_exponent <= 0:
        raise ValueError("private exponent must be positive")
    modulus = p * q
    reduced_ciphertext = ciphertext % modulus
    residue_p = modular_power(reduced_ciphertext, private_exponent % (p - 1), p)
    residue_q = modular_power(reduced_ciphertext, private_exponent % (q - 1), q)
    return crt_combine(residue_p, residue_q, p, q)

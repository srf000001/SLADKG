#!/usr/bin/env python3
"""
Sanity checks for Parameter Set B:
- q = 2^32 - 99
- n = 256 (NTT would require size=512 roots, etc.)
"""

from __future__ import annotations


def is_probable_prime(n: int) -> bool:
    """Deterministic Miller–Rabin for 64-bit integers."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n - 1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def check(a: int) -> bool:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return True
        return False

    # Deterministic bases for n < 2^64.
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        a %= n
        if a == 0:
            continue
        if not check(a):
            return False
    return True


def main() -> None:
    q = 2**32 - 99
    n = 256
    conv_len = 1
    target = n * 2
    while conv_len < target:
        conv_len *= 2

    print(f"Parameter Set B:")
    print(f"  q = 2^32 - 99 = {q}")
    print(f"  n = {n}")
    print(f"  prime(q)? {is_probable_prime(q)}")
    print(f"  NTT conv_len (>= 2n): {conv_len}")
    print(f"  (q - 1) % conv_len = {(q - 1) % conv_len}")
    if (q - 1) % conv_len != 0:
        print("  note: q does NOT support power-of-two NTT of this size; code will fall back to naive convolution.")


if __name__ == '__main__':
    main()



import unittest

from algorithms.rsa_math import (
    crt_combine,
    extended_gcd,
    gcd,
    mod_inverse,
    modular_power,
    rsa_private_operation_crt,
)


class RSAMathTests(unittest.TestCase):
    def test_gcd_and_bezout_identity(self):
        self.assertEqual(gcd(-240, 46), 2)
        divisor, x, y = extended_gcd(-240, 46)
        self.assertEqual(divisor, 2)
        self.assertEqual(-240 * x + 46 * y, divisor)

    def test_modular_inverse(self):
        self.assertEqual(mod_inverse(17, 3120), 2753)
        with self.assertRaises(ValueError):
            mod_inverse(6, 15)

    def test_square_and_multiply_matches_builtin(self):
        self.assertEqual(modular_power(65, 17, 3233), pow(65, 17, 3233))
        self.assertEqual(modular_power(5, 0, 7), 1)
        with self.assertRaises(ValueError):
            modular_power(2, -1, 7)

    def test_crt_combination(self):
        result = crt_combine(2, 3, 3, 5)
        self.assertEqual(result % 3, 2)
        self.assertEqual(result % 5, 3)
        self.assertEqual(result, 8)
        with self.assertRaises(ValueError):
            crt_combine(1, 1, 6, 9)

    def test_toy_rsa_crt_vector(self):
        p, q, public_exponent, private_exponent = 61, 53, 17, 2753
        message = 65
        ciphertext = pow(message, public_exponent, p * q)
        self.assertEqual(rsa_private_operation_crt(ciphertext, p, q, private_exponent), message)


if __name__ == "__main__":
    unittest.main()

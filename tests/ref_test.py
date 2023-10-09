'''
Verify that the output of each NaCl function exactly matches the output of the corresponding pure_pynacl function given the same
inputs.
'''
import pathlib
import unittest.mock
from ctypes import (POINTER, c_int, c_longlong, c_ubyte, c_uint, c_ulong,
                    c_ulonglong, sizeof)

import pure_pynacl
import tests
import tests.bit_ops

TEST_COUNT = 2**8
SLOW_TEST_COUNT = TEST_COUNT//16
VERY_SLOW_TEST_COUNT = TEST_COUNT//128


class CBitOps(tests.CLibrary):
    '''
    CTypes interface to C library of bitwise exercises, `bit_ops.c`
    '''
    fcns = {
        'lshift_u8': [(c_ubyte, c_ubyte), c_ubyte],
        'rshift_u8': [(c_ubyte, c_ubyte), c_ubyte],
        'and_u8': [(c_ubyte, c_ubyte), c_ubyte],
        'or_u8': [(c_ubyte, c_ubyte), c_ubyte],
        'xor_u8': [(c_ubyte, c_ubyte), c_ubyte],
        'not_u8': [(c_ubyte,), c_ubyte],
        'lshift_u32': [(c_ulong, c_ubyte), c_ulong],
        'rshift_u32': [(c_ulong, c_ubyte), c_ulong],
        'and_u32': [(c_ulong, c_ulong), c_ulong],
        'or_u32': [(c_ulong, c_ulong), c_ulong],
        'xor_u32': [(c_ulong, c_ulong), c_ulong],
        'not_u32': [(c_ulong,), c_ulong],
        'lshift_u64': [(c_ulonglong, c_ubyte), c_ulonglong],
        'rshift_u64': [(c_ulonglong, c_ubyte), c_ulonglong],
        'and_u64': [(c_ulonglong, c_ulonglong), c_ulonglong],
        'or_u64': [(c_ulonglong, c_ulonglong), c_ulonglong],
        'xor_u64': [(c_ulonglong, c_ulonglong), c_ulonglong],
        'not_u64': [(c_ulonglong,), c_ulonglong],
        'lshift_i64': [(c_longlong, c_ubyte), c_longlong],
        'rshift_i64': [(c_longlong, c_ubyte), c_longlong],
        'and_i64': [(c_longlong, c_longlong), c_longlong],
        'or_i64': [(c_longlong, c_longlong), c_longlong],
        'xor_i64': [(c_longlong, c_longlong), c_longlong],
        'not_i64': [(c_longlong,), c_longlong],
    }

    def __init__(self):
        super().__init__(pathlib.Path(__file__).parent, 'bit_ops')


class TestBitOps:
    '''
    Test bitwise operations
    '''
    c_bit_ops = CBitOps()
    py_bit_ops = tests.bit_ops

    def test_lshift(self):
        '''
        Test left bit shifting
        '''
        for fcn, typ in (('lshift_u8', c_ubyte),
                         ('lshift_u32', c_ulong),
                         ('lshift_u64', c_ulonglong),
                         ('lshift_i64', c_longlong)):

            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for c in range(bits):
                for x in [1 << n for n in range(bits - c)]:
                    c_out = getattr(self.c_bit_ops, fcn)(typ(x), c_ubyte(c))
                    py_out = getattr(self.py_bit_ops, fcn)(x, c)

                    assert c_out == py_out

    def test_rshift(self):
        '''
        Test right bit shifting
        '''
        for fcn, typ in (('rshift_u8', c_ubyte),
                         ('rshift_u32', c_ulong),
                         ('rshift_u64', c_ulonglong),
                         ('rshift_i64', c_longlong)):

            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for c in range(1, bits + 1):
                for x in [1 << n for n in range(c, bits)]:
                    c_out = getattr(self.c_bit_ops, fcn)(typ(x), c_ubyte(c))
                    py_out = getattr(self.py_bit_ops, fcn)(x, c)

                    assert c_out == py_out

    def test_and(self):
        '''
        Test bit anding
        '''
        for fcn, typ in (('and_u8', c_ubyte),
                         ('and_u32', c_ulong),
                         ('and_u64', c_ulonglong),
                         ('and_i64', c_longlong)):

            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x, y in tests.randargs(TEST_COUNT, [typ], [typ]):
                c_out = getattr(self.c_bit_ops, fcn)(typ(x), typ(y))
                py_out = getattr(self.py_bit_ops, fcn)(x, y)

                assert c_out == py_out

    def test_or(self):
        '''
        Test bit oring
        '''
        for fcn, typ in (('or_u8', c_ubyte),
                         ('or_u32', c_ulong),
                         ('or_u64', c_ulonglong),
                         ('or_i64', c_longlong)):

            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x, y in tests.randargs(TEST_COUNT, [typ], [typ]):
                c_out = getattr(self.c_bit_ops, fcn)(typ(x), typ(y))
                py_out = getattr(self.py_bit_ops, fcn)(x, y)

                assert c_out == py_out

    def test_xor(self):
        '''
        Test bit xoring
        '''
        for fcn, typ in (('xor_u8', c_ubyte),
                         ('xor_u32', c_ulong),
                         ('xor_u64', c_ulonglong),
                         ('xor_i64', c_longlong)):

            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x, y in tests.randargs(TEST_COUNT, [typ], [typ]):
                c_out = getattr(self.c_bit_ops, fcn)(typ(x), typ(y))
                py_out = getattr(self.py_bit_ops, fcn)(x, y)

                assert c_out == py_out

    def test_not(self):
        '''
        Test bit noting
        '''
        for fcn, typ in (('not_u8', c_ubyte),
                         ('not_u32', c_ulong),
                         ('not_u64', c_ulonglong),
                         ('not_i64', c_longlong)):

            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x in tests.randargs(TEST_COUNT, [typ]):
                c_out = getattr(self.c_bit_ops, fcn,)(typ(x))
                py_out = getattr(self.py_bit_ops, fcn)(x)

                assert c_out == py_out


class TweetNaCl(tests.CLibrary):
    '''
    CTypes interface to tweetnacl
    '''
    fcns = {
        #'crypto_auth_hmacsha512256_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte)), c_int],
        #'crypto_auth_hmacsha512256_tweet_verify': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte)), c_int],
        'crypto_box_curve25519xsalsa20poly1305_tweet_afternm': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_box_curve25519xsalsa20poly1305_tweet_beforenm': [(POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_box_curve25519xsalsa20poly1305_tweet_keypair': [(POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_box_curve25519xsalsa20poly1305_tweet_open': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_box_curve25519xsalsa20poly1305_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_core_hsalsa20_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_core_salsa20_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        #'crypto_hashblocks_sha256_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong), c_ulonglong],
        'crypto_hashblocks_sha512_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong), c_ulonglong],
        #'crypto_hash_sha256_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong), c_int],
        'crypto_hash_sha512_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong), c_int],
        'crypto_onetimeauth_poly1305_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte)), c_int],
        'crypto_onetimeauth_poly1305_tweet_verify': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte)), c_int],
        'crypto_scalarmult_curve25519_tweet_base': [(POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_scalarmult_curve25519_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_secretbox_xsalsa20poly1305_tweet_open': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_secretbox_xsalsa20poly1305_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_sign_ed25519_tweet_keypair': [(POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_sign_ed25519_tweet_open': [(POINTER(c_ubyte), POINTER(c_ulonglong), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte)), c_int],
        'crypto_sign_ed25519_tweet': [(POINTER(c_ubyte), POINTER(c_ulonglong), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte)), c_int],
        'crypto_stream_salsa20_tweet': [(POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_stream_salsa20_tweet_xor': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_stream_xsalsa20_tweet': [(POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_stream_xsalsa20_tweet_xor': [(POINTER(c_ubyte), POINTER(c_ubyte), c_ulonglong, POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_verify_16_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'crypto_verify_32_tweet': [(POINTER(c_ubyte), POINTER(c_ubyte)), c_int],
        'A': [(POINTER(c_longlong), POINTER(c_longlong), POINTER(c_longlong)), None],
        'Ch': [(c_ulonglong, c_ulonglong, c_ulonglong), c_ulonglong],
        'L32': [(c_ulong, c_int), c_ulong],
        'M': [(POINTER(c_longlong), POINTER(c_longlong), POINTER(c_longlong)), None],
        'Maj': [(c_ulonglong, c_ulonglong, c_ulonglong), c_ulonglong],
        'R': [(c_ulonglong, c_int), c_ulonglong],
        'S': [(POINTER(c_longlong), POINTER(c_longlong)), None],
        'Sigma0': [(c_ulonglong,), c_ulonglong],
        'Sigma1': [(c_ulonglong,), c_ulonglong],
        'Z': [(POINTER(c_longlong), POINTER(c_longlong), POINTER(c_longlong)), None],
        'add': [((c_longlong*16)*4, (c_longlong*16)*4), None],
        'add1305': [(POINTER(c_ulong), POINTER(c_ulong)), None],
        'car25519': [(POINTER(c_longlong),), None],
        'core': [(POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), c_int), None],
        'cswap': [((c_longlong*16)*4, (c_longlong*16)*4, c_ubyte), None],
        'dl64': [(POINTER(c_ubyte),), c_ulonglong],
        'inv25519': [(POINTER(c_longlong), POINTER(c_longlong)), None],
        'ld32': [(POINTER(c_ubyte),), c_ulong],
        'modL': [(POINTER(c_ubyte), POINTER(c_longlong)), None],
        'neq25519': [(POINTER(c_longlong), POINTER(c_longlong)), c_int],
        'pack': [(POINTER(c_ubyte), (c_longlong*16)*4), None],
        'pack25519': [(POINTER(c_ubyte), POINTER(c_longlong)), None],
        'par25519': [(POINTER(c_longlong),), c_int],
        'pow2523': [(POINTER(c_longlong), POINTER(c_longlong)), None],
        'reduce': [(POINTER(c_ubyte),), None],
        'scalarbase': [((c_longlong*16)*4, POINTER(c_ubyte)), None],
        'scalarmult': [((c_longlong*16)*4, (c_longlong*16)*4, POINTER(c_ubyte)), None],
        'sel25519': [(POINTER(c_longlong), POINTER(c_longlong), c_int), None],
        'set25519': [(POINTER(c_longlong), POINTER(c_longlong)), None],
        'sigma0': [(c_ulonglong,), c_ulonglong],
        'sigma1': [(c_ulonglong,), c_ulonglong],
        'st32': [(POINTER(c_ubyte), c_ulong), None],
        'ts64': [(POINTER(c_ubyte), c_ulong), None],
        'unpack25519': [(POINTER(c_longlong), POINTER(c_ubyte)), None],
        'unpackneg': [((c_longlong*16)*4, POINTER(c_ubyte)), c_int],
        'vn': [(POINTER(c_ubyte), POINTER(c_ubyte), c_int), c_int],
    }

    def __init__(self):
        super().__init__(pathlib.Path(__file__).parent.parent/'tweetnacl', 'TweetNaCl')


class TestTweetNaClParallel:
    '''
    Test TweetNaCl function parity through parallel testing.  See `README.md` for an explanation.
    '''
    c_tweetnacl = TweetNaCl()
    py_tweetnacl = pure_pynacl.tweetnacl

    def test_L32(self):
        '''
        Test L32 functions
        '''
        for x, c in tests.randargs(TEST_COUNT, [(0, 2**32)], [(0, 32)]):
            X = c_ulong(x)
            C = c_int(c)

            tw_out = self.c_tweetnacl.L32(X, C)
            py_out = self.py_tweetnacl.L32(x, c)

            assert tw_out == py_out

    def test_ld32(self):
        '''
        Test ld32 functions
        '''
        for x in tests.randargs(TEST_COUNT, [c_ubyte, 4]):
            X = tests.ptr(c_ubyte, x)

            tw_out = self.c_tweetnacl.ld32(X)
            py_out = self.py_tweetnacl.ld32(x)

            assert tw_out == py_out

    def test_dl64(self):
        '''
        Test dl64 functions
        '''
        for x in tests.randargs(TEST_COUNT, [c_ubyte, 8]):
            X = tests.ptr(c_ubyte, x)

            tw_out = self.c_tweetnacl.dl64(X)
            py_out = self.py_tweetnacl.dl64(x)

            assert tw_out == py_out

    def test_st32(self):
        '''
        Test st32 functions
        '''
        for x, u in tests.randargs(TEST_COUNT, [c_ubyte, 4], [c_ubyte]):
            X = tests.ptr(c_ubyte, x)
            U = c_ulong(u)

            self.c_tweetnacl.st32(X, U)
            py_out = self.py_tweetnacl.st32(x, u)

            # CTypes requires explicit conversion to list
            assert x == list(X)  # Assert both python and C mutate `x` in-place
            assert u == U.value  # Assert `u` equality
            assert py_out == list(X)  # Assert python returns `x` in addition to mutating in place

    def test_ts64(self):
        '''
        Test ts64 functions
        '''
        for x, u in tests.randargs(TEST_COUNT, [c_ubyte, 8], [c_ubyte]):
            X = tests.ptr(c_ubyte, x)
            U = c_ulong(u)

            self.c_tweetnacl.ts64(X, U)
            py_out = self.py_tweetnacl.ts64(x, u)

            assert x == list(X)
            assert u == U.value
            assert py_out == list(X)

    def test_vn(self):
        '''
        Test vn functions
        '''
        test_count = int(TEST_COUNT**0.5)

        for n in tests.randargs(test_count, [c_ubyte]):
            N = c_int(n)
            for x, y in tests.randargs(test_count, [c_ubyte, n], [c_ubyte, n]):
                X = tests.ptr(c_ubyte, x)
                Y = tests.ptr(c_ubyte, y)

                tw_out = self.c_tweetnacl.vn(X, Y, N)
                py_out = self.py_tweetnacl.vn(x, y, n)

                assert n == N.value
                assert tw_out == py_out

    def test_crypto_verify_16_tweet(self):
        '''
        Test crypto_verify_16_tweet functions
        '''
        for x, y in tests.randargs(TEST_COUNT, [c_ubyte, 16], [c_ubyte, 16]):
            X = tests.ptr(c_ubyte, x)
            Y = tests.ptr(c_ubyte, y)

            tw_out = self.c_tweetnacl.crypto_verify_16_tweet(X, Y)
            py_out = self.py_tweetnacl.crypto_verify_16_tweet(x, y)

            assert tw_out == py_out

    def test_crypto_verify_32_tweet(self):
        '''
        Test crypto_verify_32_tweet functions
        '''
        for x, y in tests.randargs(TEST_COUNT, [c_ubyte, 32], [c_ubyte, 32]):
            X = tests.ptr(c_ubyte, x)
            Y = tests.ptr(c_ubyte, y)

            tw_out = self.c_tweetnacl.crypto_verify_32_tweet(X, Y)
            py_out = self.py_tweetnacl.crypto_verify_32_tweet(x, y)

            assert tw_out == py_out

    def test_core(self):
        '''
        Test core functions
        '''
        test_count = SLOW_TEST_COUNT//2

        for h in (True, False):
            H = c_int(1) if h else c_int(0)
            for out, in_, k, c in tests.randargs(test_count,
                                           [c_ubyte, 2**7], [c_ubyte, 2**7], [c_ubyte, 2**7], [c_ubyte, 2**7]):
                OUT = tests.ptr(c_ubyte, out)
                IN_ = tests.ptr(c_ubyte, in_)
                K = tests.ptr(c_ubyte, k)
                C = tests.ptr(c_ubyte, c)

                self.c_tweetnacl.core(OUT, IN_, K, C, H)
                self.py_tweetnacl.core(out, in_, k, c, h)

                assert out == list(OUT)

    def test_crypto_core_salsa20_tweet(self):
        '''
        Test crypto_core_salsa20_tweet functions
        '''
        for out, in_, k, c in tests.randargs(TEST_COUNT,
                                       [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64]):
            OUT = tests.ptr(c_ubyte, out)
            IN_ = tests.ptr(c_ubyte, in_)
            K = tests.ptr(c_ubyte, k)
            C = tests.ptr(c_ubyte, c)

            tw_out = self.c_tweetnacl.crypto_core_salsa20_tweet(OUT, IN_, K, C)
            py_out = self.py_tweetnacl.crypto_core_salsa20_tweet(out, in_, k, c)

            assert out == list(OUT)
            assert tw_out == py_out

    def test_crypto_core_hsalsa20_tweet(self):
        '''
        Test crypto_core_hsalsa20_tweet functions
        '''
        for out, in_, k, c in tests.randargs(TEST_COUNT,
                                       [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64]):
            OUT = tests.ptr(c_ubyte, out)
            IN_ = tests.ptr(c_ubyte, in_)
            K = tests.ptr(c_ubyte, k)
            C = tests.ptr(c_ubyte, c)

            tw_out = self.c_tweetnacl.crypto_core_hsalsa20_tweet(OUT, IN_, K, C)
            py_out = self.py_tweetnacl.crypto_core_hsalsa20_tweet(out, in_, k, c)

            assert out == list(OUT)
            assert tw_out == py_out

    def test_crypto_stream_salsa20_tweet_xor(self):
        '''
        Test crypto_stream_salsa20_tweet_xor functions
        '''
        test_count = int(TEST_COUNT**0.5)

        for b in tests.randargs(test_count, [(32, 2**7)]):
            B = c_ulonglong(b)
            for c, m, n, k in tests.randargs(test_count,
                                       [c_ubyte, b], [c_ubyte, b], [c_ubyte, b], [c_ubyte, b]):
                C = tests.ptr(c_ubyte, c)
                M = tests.ptr(c_ubyte, m)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_stream_salsa20_tweet_xor(C, M, B, N, K)
                py_out = self.py_tweetnacl.crypto_stream_salsa20_tweet_xor(c, m, b, n, k)

                assert c == list(C)
                assert tw_out == py_out
            assert b == B.value

    def test_crypto_stream_salsa20_tweet(self):
        '''
        Test crypto_stream_salsa20_tweet functions
        '''
        test_count = int(TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(32, 64)]):
            D = c_ulonglong(d)
            for c, n, k in tests.randargs(test_count,
                                    [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = tests.ptr(c_ubyte, c)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_stream_salsa20_tweet(C, D, N, K)
                py_out = self.py_tweetnacl.crypto_stream_salsa20_tweet(c, d, n, k)

                assert c == list(C)
                assert tw_out == py_out
            assert d == D.value

    def test_crypto_stream_xsalsa20_tweet(self):
        '''
        Test crypto_stream_xsalsa20_tweet functions
        '''
        test_count = int(TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(32, 64)]):
            D = c_ulonglong(d)
            for c, n, k in tests.randargs(test_count,
                                    [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = tests.ptr(c_ubyte, c)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_stream_xsalsa20_tweet(C, D, N, K)
                py_out = self.py_tweetnacl.crypto_stream_xsalsa20_tweet(c, d, n, k)

                assert c == list(C)
                assert tw_out == py_out
            assert d == D.value

    def test_crypto_stream_xsalsa20_tweet_xor(self):
        '''
        Test crypto_stream_xsalsa20_tweet_xor functions
        '''
        test_count = int(TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(32, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, k in tests.randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = tests.ptr(c_ubyte, c)
                M = tests.ptr(c_ubyte, m)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_stream_xsalsa20_tweet_xor(C, M, D, N, K)
                py_out = self.py_tweetnacl.crypto_stream_xsalsa20_tweet_xor(c, m, d, n, k)

                assert c == list(C)
                assert tw_out == py_out
            assert d == D.value

    def test_add1305(self):
        '''
        Test add1305 functions
        '''
        for h, c in tests.randargs(TEST_COUNT, [c_ulong, 17], [c_ulong, 17]):
            H = tests.ptr(c_ulong, h)
            C = tests.ptr(c_ulong, c)

            self.c_tweetnacl.add1305(H, C)
            self.py_tweetnacl.add1305(h, c)

            assert h == list(H)

    def test_crypto_onetimeauth_poly1305_tweet(self):
        '''
        Test crypto_onetimeauth_poly1305_tweet functions
        '''
        test_count = int(SLOW_TEST_COUNT**0.5)

        for n in tests.randargs(test_count, [(17, 2**11)]):
            N = c_ulonglong(n)
            for out, m, k in tests.randargs(test_count,
                                      [c_ubyte, n], [c_ubyte, n], [c_ubyte, 2*n]):
                OUT = tests.ptr(c_ubyte, out)
                M = tests.ptr(c_ubyte, m)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_onetimeauth_poly1305_tweet(OUT, M, N, K)
                py_out = self.py_tweetnacl.crypto_onetimeauth_poly1305_tweet(out, m, n, k)

                assert out == list(OUT)
                assert tw_out == py_out
            assert n == N.value

    def test_crypto_onetimeauth_poly1305_tweet_verify(self):
        '''
        Test crypto_onetimeauth_poly1305_tweet_verify functions
        '''
        test_count = int(SLOW_TEST_COUNT**0.5)

        for n in tests.randargs(test_count, [(17, 2**11)]):
            N = c_ulonglong(n)
            for h, m, k in tests.randargs(test_count,
                                    [c_ubyte, n], [c_ubyte, n], [c_ubyte, 2*n]):
                H = tests.ptr(c_ubyte, h)
                M = tests.ptr(c_ubyte, m)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_onetimeauth_poly1305_tweet_verify(H, M, N, K)
                py_out = self.py_tweetnacl.crypto_onetimeauth_poly1305_tweet_verify(h, m, n, k)

                assert tw_out == py_out
            assert n == N.value

    def test_crypto_secretbox_xsalsa20poly1305_tweet(self):
        '''
        Test crypto_secretbox_xsalsa20poly1305_tweet functions
        '''
        test_count = int(SLOW_TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, k in tests.randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                C = tests.ptr(c_ubyte, c)
                M = tests.ptr(c_ubyte, m)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet(C, M, D, N, K)
                py_out = self.py_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet(c, m, d, n, k)

                assert c == list(C)
                assert tw_out == py_out
            assert d == D.value

    def test_crypto_secretbox_xsalsa20poly1305_tweet_open(self):
        '''
        Test crypto_secretbox_xsalsa20poly1305_tweet_open functions
        '''
        test_count = int(SLOW_TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for m, c, n, k in tests.randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                M = tests.ptr(c_ubyte, m)
                C = tests.ptr(c_ubyte, c)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open(M, C, D, N, K)
                py_out = self.py_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open(m, c, d, n, k)

                assert m == list(M)
                assert tw_out == py_out
            assert d == D.value

    def test_set25519(self):
        '''
        Test set25519 functions
        '''
        for r, a in tests.randargs(TEST_COUNT, [c_longlong, 16], [c_longlong, 16]):
            R = tests.ptr(c_longlong, r)
            A = tests.ptr(c_longlong, a)

            self.c_tweetnacl.set25519(R, A)
            self.py_tweetnacl.set25519(r, a)

            assert r == list(R)

    def test_car25519(self):
        '''
        Test car25519 functions
        '''
        lim = 2**62

        for o in tests.randargs(TEST_COUNT, [(-lim, lim), 16]):
            O = tests.ptr(c_longlong, o)

            self.c_tweetnacl.car25519(O)
            self.py_tweetnacl.car25519(o)

            assert o == list(O)

    def test_sel25519(self):
        '''
        Test sel25519 functions
        '''
        for p, q, b in tests.randargs(TEST_COUNT, [c_longlong, 16], [c_longlong, 16], c_int):
            P = tests.ptr(c_longlong, p)
            Q = tests.ptr(c_longlong, q)
            B = c_int(b)

            self.c_tweetnacl.sel25519(P, Q, B)
            py_out = self.py_tweetnacl.sel25519(p, q, b)

            assert p == list(P)
            assert q == list(Q)
            assert b == B.value
            assert py_out[0] == list(P)
            assert py_out[1] == list(Q)

    def test_pack25519(self):
        '''
        Test pack25519 functions
        '''
        lim = 2**47

        for o, n in tests.randargs(TEST_COUNT, [c_ubyte, 32], [(-lim, lim), 16]):
            O = tests.ptr(c_ubyte, o)
            N = tests.ptr(c_longlong, n)

            self.c_tweetnacl.pack25519(O, N)
            self.py_tweetnacl.pack25519(o, n)

            assert o == list(O)

    def test_neq25519(self):
        '''
        Test neq25519 functions
        '''
        lim = 2**47

        for a, b in tests.randargs(TEST_COUNT, [(-lim, lim), 16], [(-lim, lim), 16]):
            A = tests.ptr(c_longlong, a)
            B = tests.ptr(c_longlong, b)

            tw_out = self.c_tweetnacl.neq25519(A, B)
            py_out = self.py_tweetnacl.neq25519(a, b)

            assert tw_out == py_out

    def test_par25519(self):
        '''
        Test par25519 functions
        '''
        lim = 2**47

        for a in tests.randargs(TEST_COUNT, [(-lim, lim), 16]):
            A = tests.ptr(c_longlong, a)

            tw_out = self.c_tweetnacl.par25519(A)
            py_out = self.py_tweetnacl.par25519(a)

            assert tw_out == py_out

    def test_unpack25519(self):
        '''
        Test unpack25519 functions
        '''
        for o, n in tests.randargs(TEST_COUNT, [c_longlong, 16], [c_ubyte, 32]):
            O = tests.ptr(c_longlong, o)
            N = tests.ptr(c_ubyte, n)

            self.c_tweetnacl.unpack25519(O, N)
            self.py_tweetnacl.unpack25519(o, n)

            assert o == list(O)

    def test_A(self):
        '''
        Test A functions
        '''
        lim = 2**62

        for o, a, b in tests.randargs(TEST_COUNT,
                                [(-lim, lim - 1), 16], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = tests.ptr(c_longlong, o)
            A = tests.ptr(c_longlong, a)
            B = tests.ptr(c_longlong, b)

            self.c_tweetnacl.A(O, A, B)
            self.py_tweetnacl.A(o, a, b)

            assert o == list(O)

    def test_Z(self):
        '''
        Test Z functions
        '''
        lim = 2**62

        for o, a, b in tests.randargs(TEST_COUNT,
                                [(-lim, lim - 1), 16], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = tests.ptr(c_longlong, o)
            A = tests.ptr(c_longlong, a)
            B = tests.ptr(c_longlong, b)

            self.c_tweetnacl.Z(O, A, B)
            self.py_tweetnacl.Z(o, a, b)

            assert o == list(O)

    def test_M(self):
        '''
        Test M functions
        '''
        lim = 2**27

        for o, a, b in tests.randargs(TEST_COUNT,
                                [(-lim, lim - 1), 16], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = tests.ptr(c_longlong, o)
            A = tests.ptr(c_longlong, a)
            B = tests.ptr(c_longlong, b)

            self.c_tweetnacl.M(O, A, B)
            py_out = self.py_tweetnacl.M(o, a, b)

            assert o == list(O)
            assert py_out == list(O)

    def test_S(self):
        '''
        Test S functions
        '''
        lim = 2**27

        for o, a in tests.randargs(TEST_COUNT, [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = tests.ptr(c_longlong, o)
            A = tests.ptr(c_longlong, a)

            self.c_tweetnacl.S(O, A)
            self.py_tweetnacl.S(o, a)

            assert o == list(O)

    def test_inv25519(self):
        '''
        Test inv25519 functions
        '''
        lim = 2**27

        for o, i in tests.randargs(VERY_SLOW_TEST_COUNT, [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = tests.ptr(c_longlong, o)
            I = tests.ptr(c_longlong, i)

            self.c_tweetnacl.inv25519(O, I)
            py_out = self.py_tweetnacl.inv25519(o, i)

            assert o == [j for j in O]
            assert py_out == [j for j in O]

    def test_pow2523(self):
        '''
        Test pow2523 functions
        '''
        lim = 2**27

        for o, i in tests.randargs(VERY_SLOW_TEST_COUNT, [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = tests.ptr(c_longlong, o)
            I = tests.ptr(c_longlong, i)

            self.c_tweetnacl.pow2523(O, I)
            self.py_tweetnacl.pow2523(o, i)

            assert o == [j for j in O]

    def test_crypto_scalarmult_curve25519_tweet(self):
        '''
        Test crypto_scalarmult_curve25519_tweet functions
        '''
        for q, n, p in tests.randargs(VERY_SLOW_TEST_COUNT, [c_ubyte, 32], [c_ubyte, 32], [c_ubyte, 32]):
            Q = tests.ptr(c_ubyte, q)
            N = tests.ptr(c_ubyte, n)
            P = tests.ptr(c_ubyte, p)

            tw_out = self.c_tweetnacl.crypto_scalarmult_curve25519_tweet(Q, N, P)
            py_out = self.py_tweetnacl.crypto_scalarmult_curve25519_tweet(q, n, p)

            assert q == list(Q)
            assert tw_out == py_out

    def test_crypto_scalarmult_curve25519_tweet_base(self):
        '''
        Test crypto_scalarmult_curve25519_tweet_base functions
        '''
        for q, n in tests.randargs(VERY_SLOW_TEST_COUNT, [c_ubyte, 32], [c_ubyte, 32]):
            Q = tests.ptr(c_ubyte, q)
            N = tests.ptr(c_ubyte, n)

            tw_out = self.c_tweetnacl.crypto_scalarmult_curve25519_tweet_base(Q, N)
            py_out = self.py_tweetnacl.crypto_scalarmult_curve25519_tweet_base(q, n)

            assert q == list(Q)
            assert tw_out == py_out

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_keypair(self):
        '''
        Test crypto_box_curve25519xsalsa20poly1305_tweet_keypair functions
        '''
        # randombytes is unnecessary for testing since x is already randomized
        # before sending it into both libraries
        with unittest.mock.patch('pure_pynacl.tweetnacl.randombytes', unittest.mock.Mock()):
            for y, x in tests.randargs(VERY_SLOW_TEST_COUNT, [c_ubyte, 32], [c_ubyte, 32]):
                Y = tests.ptr(c_ubyte, y)
                X = tests.ptr(c_ubyte, x)

                tw_out = self.c_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_keypair(Y, X)
                py_out = self.py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_keypair(y, x)

                assert y == list(Y)
                assert x == list(X)
                assert tw_out == py_out

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(self):
        '''
        Test crypto_box_curve25519xsalsa20poly1305_tweet_beforenm functions
        '''
        for k, y, x in tests.randargs(VERY_SLOW_TEST_COUNT, [c_ubyte, 32], [c_ubyte, 32], [c_ubyte, 32]):
            K = tests.ptr(c_ubyte, k)
            Y = tests.ptr(c_ubyte, y)
            X = tests.ptr(c_ubyte, x)

            tw_out = self.c_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(K, Y, X)
            py_out = self.py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k, y, x)

            assert k == list(K)
            assert tw_out == py_out

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_afternm(self):
        '''
        Test crypto_box_curve25519xsalsa20poly1305_tweet_afternm functions
        '''
        test_count = int(SLOW_TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, k in tests.randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                C = tests.ptr(c_ubyte, c)
                M = tests.ptr(c_ubyte, m)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_afternm(C, M, D, N, K)
                py_out = self.py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_afternm(c, m, d, n, k)

                assert c == list(C)
                assert tw_out == py_out
            assert d == D.value

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(self):
        '''
        Test crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm functions
        '''
        test_count = int(SLOW_TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for m, c, n, k in tests.randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                M = tests.ptr(c_ubyte, m)
                C = tests.ptr(c_ubyte, c)
                N = tests.ptr(c_ubyte, n)
                K = tests.ptr(c_ubyte, k)

                tw_out = self.c_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(M, C, D, N, K)
                py_out = self.py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(m, c, d, n, k)

                assert m == list(M)
                assert tw_out == py_out
            assert d == D.value

    def test_crypto_box_curve25519xsalsa20poly1305_tweet(self):
        '''
        Test crypto_box_curve25519xsalsa20poly1305_tweet functions
        '''
        test_count = int(VERY_SLOW_TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, y, x in tests.randargs(test_count,
                                          [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = tests.ptr(c_ubyte, c)
                M = tests.ptr(c_ubyte, m)
                N = tests.ptr(c_ubyte, n)
                Y = tests.ptr(c_ubyte, y)
                X = tests.ptr(c_ubyte, x)

                tw_out = self.c_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet(C, M, D, N, Y, X)
                py_out = self.py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet(c, m, d, n, y, x)

                assert c == list(C)
                assert tw_out == py_out
            assert d == D.value

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_open(self):
        '''
        Test crypto_box_curve25519xsalsa20poly1305_tweet_open functions
        '''
        test_count = int(VERY_SLOW_TEST_COUNT**0.5)

        for d in tests.randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for m, c, n, y, x in tests.randargs(test_count,
                                          [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                M = tests.ptr(c_ubyte, m)
                C = tests.ptr(c_ubyte, c)
                N = tests.ptr(c_ubyte, n)
                Y = tests.ptr(c_ubyte, y)
                X = tests.ptr(c_ubyte, x)

                tw_out = self.c_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open(M, C, D, N, Y, X)
                py_out = self.py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open(m, c, d, n, y, x)

                assert m == list(M)
                assert tw_out == py_out
            assert d == D.value

    def test_R(self):
        '''
        Test R functions
        '''
        for x, c in tests.randargs(TEST_COUNT, [c_ulonglong], [(0, 64)]):
            X = c_ulonglong(x)
            C = c_int(c)

            tw_out = self.c_tweetnacl.R(X, C)
            py_out = self.py_tweetnacl.R(x, c)

            assert x == X.value
            assert c == C.value
            assert tw_out == py_out

    def test_Ch(self):
        '''
        Test Ch functions
        '''
        for x, y, z in tests.randargs(TEST_COUNT, [c_ulonglong], [c_ulonglong], [c_ulonglong]):
            X = c_ulonglong(x)
            Y = c_ulonglong(y)
            Z = c_ulonglong(z)

            tw_out = self.c_tweetnacl.Ch(X, Y, Z)
            py_out = self.py_tweetnacl.Ch(x, y, z)

            assert x == X.value
            assert y == Y.value
            assert z == Z.value
            assert tw_out == py_out

    def test_Maj(self):
        '''
        Test Maj functions
        '''
        for x, y, z in tests.randargs(TEST_COUNT, [c_ulonglong], [c_ulonglong], [c_ulonglong]):
            X = c_ulonglong(x)
            Y = c_ulonglong(y)
            Z = c_ulonglong(z)

            tw_out = self.c_tweetnacl.Maj(X, Y, Z)
            py_out = self.py_tweetnacl.Maj(x, y, z)

            assert x == X.value
            assert y == Y.value
            assert z == Z.value
            assert tw_out == py_out

    def test_Sigma0(self):
        '''
        Test Sigma0 functions
        '''
        for x in tests.randargs(TEST_COUNT, [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.c_tweetnacl.Sigma0(X)
            py_out = self.py_tweetnacl.Sigma0(x)

            assert x == X.value
            assert tw_out == py_out

    def test_Sigma1(self):
        '''
        Test Sigma1 functions
        '''
        for x in tests.randargs(TEST_COUNT, [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.c_tweetnacl.Sigma1(X)
            py_out = self.py_tweetnacl.Sigma1(x)

            assert x == X.value
            assert tw_out == py_out

    def test_sigma0(self):
        '''
        Test sigma0 functions
        '''
        for x in tests.randargs(TEST_COUNT, [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.c_tweetnacl.sigma0(X)
            py_out = self.py_tweetnacl.sigma0(x)

            assert x == X.value
            assert tw_out == py_out

    def test_sigma1(self):
        '''
        Test sigma1 functions
        '''
        for x in tests.randargs(TEST_COUNT, [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.c_tweetnacl.sigma1(X)
            py_out = self.py_tweetnacl.sigma1(x)

            assert x == X.value
            assert tw_out == py_out

    def test_crypto_hashblocks_sha512_tweet(self):
        '''
        Test crypto_hashblocks_sha512_tweet functions
        '''
        test_count = int(VERY_SLOW_TEST_COUNT**0.5)

        for n in tests.randargs(test_count, [(0, 2**17)]):
            N = c_ulonglong(n)
            for x, m in tests.randargs(test_count, [c_ubyte, 64], [c_ubyte, n]):
                X = tests.ptr(c_ubyte, x)
                M = tests.ptr(c_ubyte, m)

                tw_out = self.c_tweetnacl.crypto_hashblocks_sha512_tweet(X, M, N)
                py_out = self.py_tweetnacl.crypto_hashblocks_sha512_tweet(x, m, n)

                assert x == list(X)
                assert tw_out == py_out
            assert n == N.value

    def test_crypto_hash_sha512_tweet(self):
        '''
        Test crypto_hash_sha512_tweet functions
        '''
        test_count = int(SLOW_TEST_COUNT**0.5)

        for n in tests.randargs(test_count, [(0, 2**11)]):
            N = c_ulonglong(n)
            for out, m in tests.randargs(test_count, [c_ubyte, 64], [c_ubyte, 2*n]):
                OUT = tests.ptr(c_ubyte, out)
                M = tests.ptr(c_ubyte, m)

                tw_out = self.c_tweetnacl.crypto_hash_sha512_tweet(OUT, M, N)
                py_out = self.py_tweetnacl.crypto_hash_sha512_tweet(out, m, n)

                assert out == list(OUT)
                assert tw_out == py_out
            assert n == N.value

    def test_add(self):
        '''
        Test add functions
        '''
        lim = 2**27

        for p, q in tests.randargs(SLOW_TEST_COUNT, [(-lim, lim), (16, 4)], [(-lim, lim), (16, 4)]):
            P = tests.ptr(c_longlong, p, (16, 4))
            Q = tests.ptr(c_longlong, q, (16, 4))

            self.c_tweetnacl.add(P, Q)
            self.py_tweetnacl.add(p, q)

            for i, row in enumerate(P):
                assert p[i] == [j for j in row]
            for i, row in enumerate(Q):
                assert q[i] == [j for j in row]

    def test_cswap(self):
        '''
        Test cswap functions
        '''
        for p, q, b in tests.randargs(TEST_COUNT, [c_longlong, (16, 4)], [c_longlong, (16, 4)], [c_ubyte]):
            P = tests.ptr(c_longlong, p, (16, 4))
            Q = tests.ptr(c_longlong, q, (16, 4))
            B = c_ubyte(b)

            self.c_tweetnacl.cswap(P, Q, B)
            self.py_tweetnacl.cswap(p, q, b)

            for i, row in enumerate(P):
                assert p[i] == [j for j in row]
            for i, row in enumerate(Q):
                assert q[i] == [j for j in row]
            assert b == B.value

    def test_pack(self):
        '''
        Test pack functions
        '''
        lim = 2**27

        for r, p in tests.randargs(VERY_SLOW_TEST_COUNT, [c_ubyte, 32], [(-lim, lim), (16, 4)]):
            R = tests.ptr(c_ubyte, r)
            P = tests.ptr(c_longlong, p, (16, 4))

            self.c_tweetnacl.pack(R, P)
            self.py_tweetnacl.pack(r, p)

            assert r == list(R)
            for i, row in enumerate(P):
                assert p[i] == [j for j in row]

    def test_scalarmult(self):
        '''
        Test scalarmult functions
        '''
        lim = 2**27

        for p, q, s in tests.randargs(VERY_SLOW_TEST_COUNT, [(-lim, lim), (16, 4)], [(-lim, lim), (16, 4)], [c_ubyte, 32]):
            P = tests.ptr(c_longlong, p, (16, 4))
            Q = tests.ptr(c_longlong, q, (16, 4))
            S = tests.ptr(c_ubyte, s)

            self.c_tweetnacl.scalarmult(P, Q, S)
            self.py_tweetnacl.scalarmult(p, q, s)

            for i, row in enumerate(P):
                assert p[i] == [j for j in row]
            for i, row in enumerate(Q):
                assert q[i] == [j for j in row]

    def test_scalarbase(self):
        '''
        Test scalarbase functions
        '''
        lim = 2**27

        for p, s in tests.randargs(VERY_SLOW_TEST_COUNT, [(-lim, lim), (16, 4)], [c_ubyte, 32]):
            P = tests.ptr(c_longlong, p, (16, 4))
            S = tests.ptr(c_ubyte, s)

            self.c_tweetnacl.scalarbase(P, S)
            self.py_tweetnacl.scalarbase(p, s)

            for i, row in enumerate(P):
                assert p[i] == [j for j in row]

    def test_crypto_sign_ed25519_tweet_keypair(self):
        '''
        Test crypto_sign_ed25519_tweet_keypair functions
        '''
        with unittest.mock.patch('pure_pynacl.tweetnacl.randombytes', unittest.mock.Mock()):
            for pk, sk in tests.randargs(VERY_SLOW_TEST_COUNT, [c_ubyte, 64], [c_ubyte, 64]):
                PK = tests.ptr(c_ubyte, pk)
                SK = tests.ptr(c_ubyte, sk)

                tw_out = self.c_tweetnacl.crypto_sign_ed25519_tweet_keypair(PK, SK)
                py_out = self.py_tweetnacl.crypto_sign_ed25519_tweet_keypair(pk, sk)

                assert pk == list(PK)
                assert sk == list(SK)
                assert tw_out == py_out

    def test_modL(self):
        '''
        Test modL functions
        '''
        lim = 2**8

        with unittest.mock.patch('pure_pynacl.tweetnacl.randombytes', unittest.mock.Mock()):
            for r, x in tests.randargs(SLOW_TEST_COUNT, [c_ubyte, 64], [(-lim, lim), 64]):
                R = tests.ptr(c_ubyte, r)
                X = tests.ptr(c_longlong, x)

                self.c_tweetnacl.modL(R, X)
                py_out = self.py_tweetnacl.modL(r, x)

                assert r == list(R)
                assert x == list(X)
                assert py_out == list(R)

    def test_reduce(self):
        '''
        Test reduce functions
        '''
        for r in tests.randargs(SLOW_TEST_COUNT, [c_ubyte, 64]):
            R = tests.ptr(c_ubyte, r)

            self.c_tweetnacl.reduce(R)
            self.py_tweetnacl.reduce(r)

            assert r == list(R)

    def test_crypto_sign_ed25519_tweet(self):
        '''
        Test crypto_sign_ed25519_tweet functions
        '''
        llim = 8
        hlim = 2**8
        test_count = int(VERY_SLOW_TEST_COUNT**0.5)

        for n in tests.randargs(test_count, [(llim, hlim)]):
            N = c_ulonglong(n)
            for sm, smlen, m, sk in tests.randargs(test_count, [c_ubyte, n + 64], [c_ulonglong], [c_ubyte, n], [c_ubyte, 64]):
                SM = tests.ptr(c_ubyte, sm)
                SMLEN = tests.ptr(c_ulonglong, smlen)
                M = tests.ptr(c_ubyte, m)
                SK = tests.ptr(c_ubyte, sk)

                tw_out = self.c_tweetnacl.crypto_sign_ed25519_tweet(SM, SMLEN, M, N, SK)
                py_out = self.py_tweetnacl.crypto_sign_ed25519_tweet(sm, smlen, m, n, sk)

                assert sm == list(SM)
                # In principle we should also test that
                #
                # ``str(c_ulonglong(smlen)) == SMLEN.contents``,
                #
                # but python copies the argument when the function is called
                assert tw_out == py_out
            assert n == N.value

    def test_unpackneg(self):
        '''
        Test unpackneg functions
        '''
        for r, p in tests.randargs(VERY_SLOW_TEST_COUNT, [c_longlong, (16, 4)], [c_ubyte, 32]):
            R = tests.ptr(c_longlong, r, (16, 4))
            P = tests.ptr(c_ubyte, p)

            tw_out = self.c_tweetnacl.unpackneg(R, P)
            py_out = self.py_tweetnacl.unpackneg(r, p)

            for i, row in enumerate(R):
                assert r[i] == [j for j in row]
            assert tw_out == py_out

    def test_crypto_sign_ed25519_tweet_open(self):
        '''
        Test crypto_sign_ed25519_tweet_open functions
        '''
        llim = 8
        hlim = 2**8
        test_count = int(VERY_SLOW_TEST_COUNT**0.5)

        for n in tests.randargs(test_count, [(llim, hlim)]):
            N = c_ulonglong(n)
            for m, mlen, sm, pk in tests.randargs(test_count, [c_ubyte, n + 64], [c_ulonglong], [c_ubyte, n], [c_ubyte, 64]):
                M = tests.ptr(c_ubyte, m)
                MLEN = tests.ptr(c_ulonglong, mlen)
                SM = tests.ptr(c_ubyte, sm)
                PK = tests.ptr(c_ubyte, pk)

                tw_out = self.c_tweetnacl.crypto_sign_ed25519_tweet_open(M, MLEN, SM, N, PK)
                py_out = self.py_tweetnacl.crypto_sign_ed25519_tweet_open(m, mlen, sm, n, pk)

                assert m == list(M)
                # In principle we should also test that
                #
                # ``str(c_ulonglong(mlen)) == MLEN.contents``,
                #
                # but python copies the argument when the function is called
                assert tw_out == py_out
            assert n == N.value


class TestTweetNaClAntiParallel:
    '''
    Test TweetNaCl function parity through antiparallel testing.  See `README.md` for an explanation.
    '''
    c_tweetnacl = TweetNaCl()
    py_tweetnacl = pure_pynacl.tweetnacl

    def test_py_keys_with_c_lib(self):
        pass

    def test_c_keys_with_py_lib(self):
        pass

    def test_py_encrypt_c_decrypt_curve25519xsalsa20poly1305(self):
        # Implementing this function should use as many (all?) curve25519xsalsa20poly1305 fcns as possible here
        #
        # crypto_box_curve25519xsalsa20poly1305_tweet_keypair
        # crypto_box_curve25519xsalsa20poly1305_tweet_beforenm
        # crypto_box_curve25519xsalsa20poly1305_tweet_afternm
        # crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm
        # crypto_box_curve25519xsalsa20poly1305_tweet
        # crypto_box_curve25519xsalsa20poly1305_tweet_open
        pass

    def test_c_encrypt_py_decrypt_curve25519xsalsa20poly1305(self):
        # Same as above
        pass

    # Additional fcn(inv_fcn()) call paths that could be explored by tests will draw from the following list
    #
    # test_crypto_verify_16_tweet
    # test_crypto_verify_32_tweet
    # test_crypto_core_salsa20_tweet
    # test_crypto_core_hsalsa20_tweet
    # test_crypto_stream_salsa20_tweet_xor
    # test_crypto_stream_salsa20_tweet
    # test_crypto_stream_xsalsa20_tweet
    # test_crypto_stream_xsalsa20_tweet_xor
    # test_crypto_onetimeauth_poly1305_tweet
    # test_crypto_onetimeauth_poly1305_tweet_verify
    # test_crypto_secretbox_xsalsa20poly1305_tweet
    # test_crypto_secretbox_xsalsa20poly1305_tweet_open
    # test_crypto_scalarmult_curve25519_tweet
    # test_crypto_scalarmult_curve25519_tweet_base
    # test_crypto_hashblocks_sha512_tweet
    # test_crypto_hash_sha512_tweet
    # test_crypto_sign_ed25519_tweet_keypair
    # test_crypto_sign_ed25519_tweet
    # test_crypto_sign_ed25519_tweet_open

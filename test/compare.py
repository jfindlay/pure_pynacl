# -*- coding: utf-8 -*-
'''
Verify that the output of each TweetNaCl.c function exactly matches the output of
the corresponding tweetnacl.py function given the same inputs.
'''
# import python libs
import os
import sys
from unittest import TestSuite, TestCase, TestLoader, TextTestRunner
from mock import Mock, patch
from ctypes import POINTER, sizeof
from ctypes import c_ubyte, c_int, c_uint, c_ulong, c_ulonglong, c_longlong
from subprocess import call
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, ArgumentTypeError

# import pure_pynacl libs
test_dir = os.path.split(__file__)[0]
libraries = [os.path.join(test_dir, lib) for lib in os.listdir(test_dir) if lib.endswith('.so')]
call(['rm', '-f'] + libraries)
from pure_pynacl import tweetnacl as py_tweetnacl

# import testing libraries
from test import bit_ops as py_bit_ops
from test import ptr, randargs
from test import CLibrary


class BitOps(CLibrary):
    '''
    ctypes interface to library of bitwise exercises
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

    def __init__(self, opts):
        CLibrary.__init__(self, opts, './', 'bit_ops')


class TweetNaCl(CLibrary):
    '''
    ctypes interface to tweetnacl
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

    def __init__(self, opts):
        CLibrary.__init__(self, opts, '../tweetnacl', 'TweetNaCl')


class BitTest(TestCase):
    '''
    test bitwise operations
    '''
    # these cannot be setup with an __init__ because of the silly way that
    # unittest works
    opts = None
    c_bit_ops = None

    def test_lshift(self):
        '''
        test left bit shifting
        '''
        for fcn, typ in (('lshift_u8', c_ubyte),
                         ('lshift_u32', c_ulong),
                         ('lshift_u64', c_ulonglong),
                         ('lshift_i64', c_longlong)):
            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for c in range(bits):
                for x in [1 << n for n in range(bits - c)]:
                    c_out = self.c_bit_ops.call_fcn(fcn, typ(x), c_ubyte(c))
                    py_out = getattr(py_bit_ops, fcn)(x, c)
                    self.assertEqual(c_out, py_out)

    def test_rshift(self):
        '''
        test right bit shifting
        '''
        for fcn, typ in (('rshift_u8', c_ubyte),
                         ('rshift_u32', c_ulong),
                         ('rshift_u64', c_ulonglong),
                         ('rshift_i64', c_longlong)):
            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for c in range(1, bits + 1):
                for x in [1 << n for n in range(c, bits)]:
                    c_out = self.c_bit_ops.call_fcn(fcn, typ(x), c_ubyte(c))
                    py_out = getattr(py_bit_ops, fcn)(x, c)
                    self.assertEqual(c_out, py_out)

    def test_and(self):
        '''
        test bit anding
        '''
        for fcn, typ in (('and_u8', c_ubyte),
                         ('and_u32', c_ulong),
                         ('and_u64', c_ulonglong),
                         ('and_i64', c_longlong)):
            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x, y in randargs(self.opts['test_count'], [typ], [typ]):
                c_out = self.c_bit_ops.call_fcn(fcn, typ(x), typ(y))
                py_out = getattr(py_bit_ops, fcn)(x, y)
                self.assertEqual(c_out, py_out)

    def test_or(self):
        '''
        test bit oring
        '''
        for fcn, typ in (('or_u8', c_ubyte),
                         ('or_u32', c_ulong),
                         ('or_u64', c_ulonglong),
                         ('or_i64', c_longlong)):
            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x, y in randargs(self.opts['test_count'], [typ], [typ]):
                c_out = self.c_bit_ops.call_fcn(fcn, typ(x), typ(y))
                py_out = getattr(py_bit_ops, fcn)(x, y)
                self.assertEqual(c_out, py_out)

    def test_xor(self):
        '''
        test bit xoring
        '''
        for fcn, typ in (('xor_u8', c_ubyte),
                         ('xor_u32', c_ulong),
                         ('xor_u64', c_ulonglong),
                         ('xor_i64', c_longlong)):
            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x, y in randargs(self.opts['test_count'], [typ], [typ]):
                c_out = self.c_bit_ops.call_fcn(fcn, typ(x), typ(y))
                py_out = getattr(py_bit_ops, fcn)(x, y)
                self.assertEqual(c_out, py_out)

    def test_not(self):
        '''
        test bit noting
        '''
        for fcn, typ in (('not_u8', c_ubyte),
                         ('not_u32', c_ulong),
                         ('not_u64', c_ulonglong),
                         ('not_i64', c_longlong)):
            bits = sizeof(typ)*8 if repr(typ).startswith('c_u') else sizeof(typ)*8 - 1
            for x in randargs(self.opts['test_count'], [typ]):
                c_out = self.c_bit_ops.call_fcn(fcn, typ(x))
                py_out = getattr(py_bit_ops, fcn)(x)
                self.assertEqual(c_out, py_out)


class NaClTest(TestCase):
    '''
    test NaCl function parity
    '''
    # these cannot be setup with an __init__ because of the silly way that
    # unittest works
    opts = None
    tweetnacl = None

    def test_L32(self):
        '''
        test L32 functions
        '''
        for x, c in randargs(self.opts['test_count'], [(0, 2**32)], [(0, 32)]):
            X = c_ulong(x)
            C = c_int(c)

            tw_out = self.tweetnacl.call_fcn('L32', X, C)
            py_out = py_tweetnacl.L32(x, c)

            self.assertEqual(tw_out, py_out)

    def test_ld32(self):
        '''
        test ld32 functions
        '''
        for x in randargs(self.opts['test_count'], [c_ubyte, 4]):
            X = ptr(c_ubyte, x)

            tw_out = self.tweetnacl.call_fcn('ld32', X)
            py_out = py_tweetnacl.ld32(x)

            self.assertEqual(tw_out, py_out)

    def test_dl64(self):
        '''
        test dl64 functions
        '''
        for x in randargs(self.opts['test_count'], [c_ubyte, 8]):
            X = ptr(c_ubyte, x)

            tw_out = self.tweetnacl.call_fcn('dl64', X)
            py_out = py_tweetnacl.dl64(x)

            self.assertEqual(tw_out, py_out)

    def test_st32(self):
        '''
        test st32 functions
        '''
        for x, u in randargs(self.opts['test_count'], [c_ubyte, 4], [c_ubyte]):
            X = ptr(c_ubyte, x)
            U = c_ulong(u)

            self.tweetnacl.call_fcn('st32', X, U)
            py_out = py_tweetnacl.st32(x, u)

            self.assertEqual(x, [i for i in X])  # ctypes funkery requires explicit iteration
            self.assertEqual(u, U.value)
            self.assertEqual(py_out, [i for i in X])

    def test_ts64(self):
        '''
        test ts64 functions
        '''
        for x, u in randargs(self.opts['test_count'], [c_ubyte, 8], [c_ubyte]):
            X = ptr(c_ubyte, x)
            U = c_ulong(u)

            self.tweetnacl.call_fcn('ts64', X, U)
            py_out = py_tweetnacl.ts64(x, u)

            self.assertEqual(x, [i for i in X])
            self.assertEqual(u, U.value)
            self.assertEqual(py_out, [i for i in X])

    def test_vn(self):
        '''
        test vn functions
        '''
        test_count = int(self.opts['test_count']**0.5)

        for n in randargs(test_count, [c_ubyte]):
            N = c_int(n)
            for x, y in randargs(test_count, [c_ubyte, n], [c_ubyte, n]):
                X = ptr(c_ubyte, x)
                Y = ptr(c_ubyte, y)

                tw_out = self.tweetnacl.call_fcn('vn', X, Y, N)
                py_out = py_tweetnacl.vn(x, y, n)

                self.assertEqual(n, N.value)
                self.assertEqual(tw_out, py_out)

    def test_crypto_verify_16_tweet(self):
        '''
        test crypto_verify_16_tweet functions
        '''
        for x, y in randargs(self.opts['test_count'], [c_ubyte, 16], [c_ubyte, 16]):
            X = ptr(c_ubyte, x)
            Y = ptr(c_ubyte, y)

            tw_out = self.tweetnacl.call_fcn('crypto_verify_16_tweet', X, Y)
            py_out = py_tweetnacl.crypto_verify_16_tweet(x, y)

            self.assertEqual(tw_out, py_out)

    def test_crypto_verify_32_tweet(self):
        '''
        test crypto_verify_32_tweet functions
        '''
        for x, y in randargs(self.opts['test_count'], [c_ubyte, 32], [c_ubyte, 32]):
            X = ptr(c_ubyte, x)
            Y = ptr(c_ubyte, y)

            tw_out = self.tweetnacl.call_fcn('crypto_verify_32_tweet', X, Y)
            py_out = py_tweetnacl.crypto_verify_32_tweet(x, y)

            self.assertEqual(tw_out, py_out)

    def test_core(self):
        '''
        test core functions
        '''
        test_count = self.opts['slow_test_count']//2

        for h in (True, False):
            H = c_int(1) if h else c_int(0)
            for out, in_, k, c in randargs(test_count,
                                           [c_ubyte, 2**7], [c_ubyte, 2**7], [c_ubyte, 2**7], [c_ubyte, 2**7]):
                OUT = ptr(c_ubyte, out)
                IN_ = ptr(c_ubyte, in_)
                K = ptr(c_ubyte, k)
                C = ptr(c_ubyte, c)

                self.tweetnacl.call_fcn('core', OUT, IN_, K, C, H)
                py_tweetnacl.core(out, in_, k, c, h)

                self.assertEqual(out, [i for i in OUT])

    def test_crypto_core_salsa20_tweet(self):
        '''
        test crypto_core_salsa20_tweet functions
        '''
        for out, in_, k, c in randargs(self.opts['test_count'],
                                       [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64]):
            OUT = ptr(c_ubyte, out)
            IN_ = ptr(c_ubyte, in_)
            K = ptr(c_ubyte, k)
            C = ptr(c_ubyte, c)

            tw_out = self.tweetnacl.call_fcn('crypto_core_salsa20_tweet', OUT, IN_, K, C)
            py_out = py_tweetnacl.crypto_core_salsa20_tweet(out, in_, k, c)

            self.assertEqual(out, [i for i in OUT])
            self.assertEqual(tw_out, py_out)

    def test_crypto_core_hsalsa20_tweet(self):
        '''
        test crypto_core_hsalsa20_tweet functions
        '''
        for out, in_, k, c in randargs(self.opts['test_count'],
                                       [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64], [c_ubyte, 64]):
            OUT = ptr(c_ubyte, out)
            IN_ = ptr(c_ubyte, in_)
            K = ptr(c_ubyte, k)
            C = ptr(c_ubyte, c)

            tw_out = self.tweetnacl.call_fcn('crypto_core_hsalsa20_tweet', OUT, IN_, K, C)
            py_out = py_tweetnacl.crypto_core_hsalsa20_tweet(out, in_, k, c)

            self.assertEqual(out, [i for i in OUT])
            self.assertEqual(tw_out, py_out)

    def test_crypto_stream_salsa20_tweet_xor(self):
        '''
        test crypto_stream_salsa20_tweet_xor functions
        '''
        test_count = int(self.opts['test_count']**0.5)

        for b in randargs(test_count, [(32, 2**7)]):
            B = c_ulonglong(b)
            for c, m, n, k in randargs(test_count,
                                       [c_ubyte, b], [c_ubyte, b], [c_ubyte, b], [c_ubyte, b]):
                C = ptr(c_ubyte, c)
                M = ptr(c_ubyte, m)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_stream_salsa20_tweet_xor', C, M, B, N, K)
                py_out = py_tweetnacl.crypto_stream_salsa20_tweet_xor(c, m, b, n, k)

                self.assertEqual(c, [i for i in C])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(b, B.value)

    def test_crypto_stream_salsa20_tweet(self):
        '''
        test crypto_stream_salsa20_tweet functions
        '''
        test_count = int(self.opts['test_count']**0.5)

        for d in randargs(test_count, [(32, 64)]):
            D = c_ulonglong(d)
            for c, n, k in randargs(test_count,
                                    [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = ptr(c_ubyte, c)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_stream_salsa20_tweet', C, D, N, K)
                py_out = py_tweetnacl.crypto_stream_salsa20_tweet(c, d, n, k)

                self.assertEqual(c, [i for i in C])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_crypto_stream_xsalsa20_tweet(self):
        '''
        test crypto_stream_xsalsa20_tweet functions
        '''
        test_count = int(self.opts['test_count']**0.5)

        for d in randargs(test_count, [(32, 64)]):
            D = c_ulonglong(d)
            for c, n, k in randargs(test_count,
                                    [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = ptr(c_ubyte, c)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_stream_xsalsa20_tweet', C, D, N, K)
                py_out = py_tweetnacl.crypto_stream_xsalsa20_tweet(c, d, n, k)

                self.assertEqual(c, [i for i in C])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_crypto_stream_xsalsa20_tweet_xor(self):
        '''
        test crypto_stream_xsalsa20_tweet_xor functions
        '''
        test_count = int(self.opts['test_count']**0.5)

        for d in randargs(test_count, [(32, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, k in randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = ptr(c_ubyte, c)
                M = ptr(c_ubyte, m)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_stream_xsalsa20_tweet_xor', C, M, D, N, K)
                py_out = py_tweetnacl.crypto_stream_xsalsa20_tweet_xor(c, m, d, n, k)

                self.assertEqual(c, [i for i in C])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_add1305(self):
        '''
        test add1305 functions
        '''
        for h, c in randargs(self.opts['test_count'], [c_ulong, 17], [c_ulong, 17]):
            H = ptr(c_ulong, h)
            C = ptr(c_ulong, c)

            self.tweetnacl.call_fcn('add1305', H, C)
            py_tweetnacl.add1305(h, c)

            self.assertEqual(h, [i for i in H])

    def test_crypto_onetimeauth_poly1305_tweet(self):
        '''
        test crypto_onetimeauth_poly1305_tweet functions
        '''
        test_count = int(self.opts['slow_test_count']**0.5)

        for n in randargs(test_count, [(17, 2**11)]):
            N = c_ulonglong(n)
            for out, m, k in randargs(test_count,
                                      [c_ubyte, n], [c_ubyte, n], [c_ubyte, 2*n]):
                OUT = ptr(c_ubyte, out)
                M = ptr(c_ubyte, m)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_onetimeauth_poly1305_tweet', OUT, M, N, K)
                py_out = py_tweetnacl.crypto_onetimeauth_poly1305_tweet(out, m, n, k)

                self.assertEqual(out, [i for i in OUT])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(n, N.value)

    def test_crypto_onetimeauth_poly1305_tweet_verify(self):
        '''
        test crypto_onetimeauth_poly1305_tweet_verify functions
        '''
        test_count = int(self.opts['slow_test_count']**0.5)

        for n in randargs(test_count, [(17, 2**11)]):
            N = c_ulonglong(n)
            for h, m, k in randargs(test_count,
                                    [c_ubyte, n], [c_ubyte, n], [c_ubyte, 2*n]):
                H = ptr(c_ubyte, h)
                M = ptr(c_ubyte, m)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_onetimeauth_poly1305_tweet_verify', H, M, N, K)
                py_out = py_tweetnacl.crypto_onetimeauth_poly1305_tweet_verify(h, m, n, k)

                self.assertEqual(tw_out, py_out)
            self.assertEqual(n, N.value)

    def test_crypto_secretbox_xsalsa20poly1305_tweet(self):
        '''
        test crypto_secretbox_xsalsa20poly1305_tweet functions
        '''
        test_count = int(self.opts['slow_test_count']**0.5)

        for d in randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, k in randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                C = ptr(c_ubyte, c)
                M = ptr(c_ubyte, m)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_secretbox_xsalsa20poly1305_tweet', C, M, D, N, K)
                py_out = py_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet(c, m, d, n, k)

                self.assertEqual(c, [i for i in C])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_crypto_secretbox_xsalsa20poly1305_tweet_open(self):
        '''
        test crypto_secretbox_xsalsa20poly1305_tweet_open functions
        '''
        test_count = int(self.opts['slow_test_count']**0.5)

        for d in randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for m, c, n, k in randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                M = ptr(c_ubyte, m)
                C = ptr(c_ubyte, c)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_secretbox_xsalsa20poly1305_tweet_open', M, C, D, N, K)
                py_out = py_tweetnacl.crypto_secretbox_xsalsa20poly1305_tweet_open(m, c, d, n, k)

                self.assertEqual(m, [i for i in M])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_set25519(self):
        '''
        test set25519 functions
        '''
        for r, a in randargs(self.opts['test_count'], [c_longlong, 16], [c_longlong, 16]):
            R = ptr(c_longlong, r)
            A = ptr(c_longlong, a)

            self.tweetnacl.call_fcn('set25519', R, A)
            py_tweetnacl.set25519(r, a)

            self.assertEqual(r, [i for i in R])

    def test_car25519(self):
        '''
        test car25519 functions
        '''
        lim = 2**62

        for o in randargs(self.opts['test_count'], [(-lim, lim), 16]):
            O = ptr(c_longlong, o)

            self.tweetnacl.call_fcn('car25519', O)
            py_tweetnacl.car25519(o)

            self.assertEqual(o, [i for i in O])

    def test_sel25519(self):
        '''
        test sel25519 functions
        '''
        for p, q, b in randargs(self.opts['test_count'], [c_longlong, 16], [c_longlong, 16], c_int):
            P = ptr(c_longlong, p)
            Q = ptr(c_longlong, q)
            B = c_int(b)

            self.tweetnacl.call_fcn('sel25519', P, Q, B)
            py_out = py_tweetnacl.sel25519(p, q, b)

            self.assertEqual(p, [i for i in P])
            self.assertEqual(q, [i for i in Q])
            self.assertEqual(b, B.value)
            self.assertEqual(py_out[0], [i for i in P])
            self.assertEqual(py_out[1], [i for i in Q])

    def test_pack25519(self):
        '''
        test pack25519 functions
        '''
        lim = 2**47

        for o, n in randargs(self.opts['test_count'], [c_ubyte, 32], [(-lim, lim), 16]):
            O = ptr(c_ubyte, o)
            N = ptr(c_longlong, n)

            self.tweetnacl.call_fcn('pack25519', O, N)
            py_tweetnacl.pack25519(o, n)

            self.assertEqual(o, [i for i in O])

    def test_neq25519(self):
        '''
        test neq25519 functions
        '''
        lim = 2**47

        for a, b in randargs(self.opts['test_count'], [(-lim, lim), 16], [(-lim, lim), 16]):
            A = ptr(c_longlong, a)
            B = ptr(c_longlong, b)

            tw_out = self.tweetnacl.call_fcn('neq25519', A, B)
            py_out = py_tweetnacl.neq25519(a, b)

            self.assertEqual(tw_out, py_out)

    def test_par25519(self):
        '''
        test par25519 functions
        '''
        lim = 2**47

        for a in randargs(self.opts['test_count'], [(-lim, lim), 16]):
            A = ptr(c_longlong, a)

            tw_out = self.tweetnacl.call_fcn('par25519', A)
            py_out = py_tweetnacl.par25519(a)

            self.assertEqual(tw_out, py_out)

    def test_unpack25519(self):
        '''
        test unpack25519 functions
        '''
        for o, n in randargs(self.opts['test_count'], [c_longlong, 16], [c_ubyte, 32]):
            O = ptr(c_longlong, o)
            N = ptr(c_ubyte, n)

            self.tweetnacl.call_fcn('unpack25519', O, N)
            py_tweetnacl.unpack25519(o, n)

            self.assertEqual(o, [i for i in O])

    def test_A(self):
        '''
        test A functions
        '''
        lim = 2**62

        for o, a, b in randargs(self.opts['test_count'],
                                [(-lim, lim - 1), 16], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = ptr(c_longlong, o)
            A = ptr(c_longlong, a)
            B = ptr(c_longlong, b)

            self.tweetnacl.call_fcn('A', O, A, B)
            py_tweetnacl.A(o, a, b)

            self.assertEqual(o, [i for i in O])

    def test_Z(self):
        '''
        test Z functions
        '''
        lim = 2**62

        for o, a, b in randargs(self.opts['test_count'],
                                [(-lim, lim - 1), 16], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = ptr(c_longlong, o)
            A = ptr(c_longlong, a)
            B = ptr(c_longlong, b)

            self.tweetnacl.call_fcn('Z', O, A, B)
            py_tweetnacl.Z(o, a, b)

            self.assertEqual(o, [i for i in O])

    def test_M(self):
        '''
        test M functions
        '''
        lim = 2**27

        for o, a, b in randargs(self.opts['test_count'],
                                [(-lim, lim - 1), 16], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = ptr(c_longlong, o)
            A = ptr(c_longlong, a)
            B = ptr(c_longlong, b)

            self.tweetnacl.call_fcn('M', O, A, B)
            py_out = py_tweetnacl.M(o, a, b)

            self.assertEqual(o, [i for i in O])
            self.assertEqual(py_out, [i for i in O])

    def test_S(self):
        '''
        test S functions
        '''
        lim = 2**27

        for o, a in randargs(self.opts['test_count'], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = ptr(c_longlong, o)
            A = ptr(c_longlong, a)

            self.tweetnacl.call_fcn('S', O, A)
            py_tweetnacl.S(o, a)

            self.assertEqual(o, [i for i in O])

    def test_inv25519(self):
        '''
        test inv25519 functions
        '''
        lim = 2**27

        for o, i in randargs(self.opts['very_slow_test_count'], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = ptr(c_longlong, o)
            I = ptr(c_longlong, i)

            self.tweetnacl.call_fcn('inv25519', O, I)
            py_out = py_tweetnacl.inv25519(o, i)

            self.assertEqual(o, [j for j in O])
            self.assertEqual(py_out, [j for j in O])

    def test_pow2523(self):
        '''
        test pow2523 functions
        '''
        lim = 2**27

        for o, i in randargs(self.opts['very_slow_test_count'], [(-lim, lim - 1), 16], [(-lim, lim - 1), 16]):
            O = ptr(c_longlong, o)
            I = ptr(c_longlong, i)

            self.tweetnacl.call_fcn('pow2523', O, I)
            py_tweetnacl.pow2523(o, i)

            self.assertEqual(o, [j for j in O])

    def test_crypto_scalarmult_curve25519_tweet(self):
        '''
        test crypto_scalarmult_curve25519_tweet functions
        '''
        for q, n, p in randargs(self.opts['very_slow_test_count'], [c_ubyte, 32], [c_ubyte, 32], [c_ubyte, 32]):
            Q = ptr(c_ubyte, q)
            N = ptr(c_ubyte, n)
            P = ptr(c_ubyte, p)

            tw_out = self.tweetnacl.call_fcn('crypto_scalarmult_curve25519_tweet', Q, N, P)
            py_out = py_tweetnacl.crypto_scalarmult_curve25519_tweet(q, n, p)

            self.assertEqual(q, [i for i in Q])
            self.assertEqual(tw_out, py_out)

    def test_crypto_scalarmult_curve25519_tweet_base(self):
        '''
        test crypto_scalarmult_curve25519_tweet_base functions
        '''
        for q, n in randargs(self.opts['very_slow_test_count'], [c_ubyte, 32], [c_ubyte, 32]):
            Q = ptr(c_ubyte, q)
            N = ptr(c_ubyte, n)

            tw_out = self.tweetnacl.call_fcn('crypto_scalarmult_curve25519_tweet_base', Q, N)
            py_out = py_tweetnacl.crypto_scalarmult_curve25519_tweet_base(q, n)

            self.assertEqual(q, [i for i in Q])
            self.assertEqual(tw_out, py_out)

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_keypair(self):
        '''
        test crypto_box_curve25519xsalsa20poly1305_tweet_keypair functions
        '''
        # randombytes is unnecessary for testing since x is already randomized
        # before sending it into both libraries
        with patch('pure_pynacl.tweetnacl.randombytes', Mock()):
            for y, x in randargs(self.opts['very_slow_test_count'], [c_ubyte, 32], [c_ubyte, 32]):
                Y = ptr(c_ubyte, y)
                X = ptr(c_ubyte, x)

                tw_out = self.tweetnacl.call_fcn('crypto_box_curve25519xsalsa20poly1305_tweet_keypair', Y, X)
                py_out = py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_keypair(y, x)

                self.assertEqual(y, [i for i in Y])
                self.assertEqual(x, [i for i in X])
                self.assertEqual(tw_out, py_out)

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(self):
        '''
        test crypto_box_curve25519xsalsa20poly1305_tweet_beforenm functions
        '''
        for k, y, x in randargs(self.opts['very_slow_test_count'], [c_ubyte, 32], [c_ubyte, 32], [c_ubyte, 32]):
            K = ptr(c_ubyte, k)
            Y = ptr(c_ubyte, y)
            X = ptr(c_ubyte, x)

            tw_out = self.tweetnacl.call_fcn('crypto_box_curve25519xsalsa20poly1305_tweet_beforenm', K, Y, X)
            py_out = py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(k, y, x)

            self.assertEqual(k, [i for i in K])
            self.assertEqual(tw_out, py_out)

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_afternm(self):
        '''
        test crypto_box_curve25519xsalsa20poly1305_tweet_afternm functions
        '''
        test_count = int(self.opts['slow_test_count']**0.5)

        for d in randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, k in randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                C = ptr(c_ubyte, c)
                M = ptr(c_ubyte, m)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_box_curve25519xsalsa20poly1305_tweet_afternm', C, M, D, N, K)
                py_out = py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_afternm(c, m, d, n, k)

                self.assertEqual(c, [i for i in C])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(self):
        '''
        test crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm functions
        '''
        test_count = int(self.opts['slow_test_count']**0.5)

        for d in randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for m, c, n, k in randargs(test_count,
                                       [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, 2*d]):
                M = ptr(c_ubyte, m)
                C = ptr(c_ubyte, c)
                N = ptr(c_ubyte, n)
                K = ptr(c_ubyte, k)

                tw_out = self.tweetnacl.call_fcn('crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm', M, C, D, N, K)
                py_out = py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(m, c, d, n, k)

                self.assertEqual(m, [i for i in M])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_crypto_box_curve25519xsalsa20poly1305_tweet(self):
        '''
        test crypto_box_curve25519xsalsa20poly1305_tweet functions
        '''
        test_count = int(self.opts['very_slow_test_count']**0.5)

        for d in randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for c, m, n, y, x in randargs(test_count,
                                          [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                C = ptr(c_ubyte, c)
                M = ptr(c_ubyte, m)
                N = ptr(c_ubyte, n)
                Y = ptr(c_ubyte, y)
                X = ptr(c_ubyte, x)

                tw_out = self.tweetnacl.call_fcn('crypto_box_curve25519xsalsa20poly1305_tweet', C, M, D, N, Y, X)
                py_out = py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet(c, m, d, n, y, x)

                self.assertEqual(c, [i for i in C])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_crypto_box_curve25519xsalsa20poly1305_tweet_open(self):
        '''
        test crypto_box_curve25519xsalsa20poly1305_tweet_open functions
        '''
        test_count = int(self.opts['very_slow_test_count']**0.5)

        for d in randargs(test_count, [(17, 2**11)]):
            D = c_ulonglong(d)
            for m, c, n, y, x in randargs(test_count,
                                          [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d], [c_ubyte, d]):
                M = ptr(c_ubyte, m)
                C = ptr(c_ubyte, c)
                N = ptr(c_ubyte, n)
                Y = ptr(c_ubyte, y)
                X = ptr(c_ubyte, x)

                tw_out = self.tweetnacl.call_fcn('crypto_box_curve25519xsalsa20poly1305_tweet_open', M, C, D, N, Y, X)
                py_out = py_tweetnacl.crypto_box_curve25519xsalsa20poly1305_tweet_open(m, c, d, n, y, x)

                self.assertEqual(m, [i for i in M])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(d, D.value)

    def test_R(self):
        '''
        test R functions
        '''
        for x, c in randargs(self.opts['test_count'], [c_ulonglong], [(0, 64)]):
            X = c_ulonglong(x)
            C = c_int(c)

            tw_out = self.tweetnacl.call_fcn('R', X, C)
            py_out = py_tweetnacl.R(x, c)

            self.assertEqual(x, X.value)
            self.assertEqual(c, C.value)
            self.assertEqual(tw_out, py_out)

    def test_Ch(self):
        '''
        test Ch functions
        '''
        for x, y, z in randargs(self.opts['test_count'], [c_ulonglong], [c_ulonglong], [c_ulonglong]):
            X = c_ulonglong(x)
            Y = c_ulonglong(y)
            Z = c_ulonglong(z)

            tw_out = self.tweetnacl.call_fcn('Ch', X, Y, Z)
            py_out = py_tweetnacl.Ch(x, y, z)

            self.assertEqual(x, X.value)
            self.assertEqual(y, Y.value)
            self.assertEqual(z, Z.value)
            self.assertEqual(tw_out, py_out)

    def test_Maj(self):
        '''
        test Maj functions
        '''
        for x, y, z in randargs(self.opts['test_count'], [c_ulonglong], [c_ulonglong], [c_ulonglong]):
            X = c_ulonglong(x)
            Y = c_ulonglong(y)
            Z = c_ulonglong(z)

            tw_out = self.tweetnacl.call_fcn('Maj', X, Y, Z)
            py_out = py_tweetnacl.Maj(x, y, z)

            self.assertEqual(x, X.value)
            self.assertEqual(y, Y.value)
            self.assertEqual(z, Z.value)
            self.assertEqual(tw_out, py_out)

    def test_Sigma0(self):
        '''
        test Sigma0 functions
        '''
        for x in randargs(self.opts['test_count'], [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.tweetnacl.call_fcn('Sigma0', X)
            py_out = py_tweetnacl.Sigma0(x)

            self.assertEqual(x, X.value)
            self.assertEqual(tw_out, py_out)

    def test_Sigma1(self):
        '''
        test Sigma1 functions
        '''
        for x in randargs(self.opts['test_count'], [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.tweetnacl.call_fcn('Sigma1', X)
            py_out = py_tweetnacl.Sigma1(x)

            self.assertEqual(x, X.value)
            self.assertEqual(tw_out, py_out)

    def test_sigma0(self):
        '''
        test sigma0 functions
        '''
        for x in randargs(self.opts['test_count'], [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.tweetnacl.call_fcn('sigma0', X)
            py_out = py_tweetnacl.sigma0(x)

            self.assertEqual(x, X.value)
            self.assertEqual(tw_out, py_out)

    def test_sigma1(self):
        '''
        test sigma1 functions
        '''
        for x in randargs(self.opts['test_count'], [c_ulonglong]):
            X = c_ulonglong(x)

            tw_out = self.tweetnacl.call_fcn('sigma1', X)
            py_out = py_tweetnacl.sigma1(x)

            self.assertEqual(x, X.value)
            self.assertEqual(tw_out, py_out)

    def test_crypto_hashblocks_sha512_tweet(self):
        '''
        test crypto_hashblocks_sha512_tweet functions
        '''
        test_count = int(self.opts['very_slow_test_count']**0.5)

        for n in randargs(test_count, [(0, 2**17)]):
            N = c_ulonglong(n)
            for x, m in randargs(test_count, [c_ubyte, 64], [c_ubyte, n]):
                X = ptr(c_ubyte, x)
                M = ptr(c_ubyte, m)

                tw_out = self.tweetnacl.call_fcn('crypto_hashblocks_sha512_tweet', X, M, N)
                py_out = py_tweetnacl.crypto_hashblocks_sha512_tweet(x, m, n)

                self.assertEqual(x, [i for i in X])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(n, N.value)

    def test_crypto_hash_sha512_tweet(self):
        '''
        test crypto_hash_sha512_tweet functions
        '''
        test_count = int(self.opts['slow_test_count']**0.5)

        for n in randargs(test_count, [(0, 2**11)]):
            N = c_ulonglong(n)
            for out, m in randargs(test_count, [c_ubyte, 64], [c_ubyte, 2*n]):
                OUT = ptr(c_ubyte, out)
                M = ptr(c_ubyte, m)

                tw_out = self.tweetnacl.call_fcn('crypto_hash_sha512_tweet', OUT, M, N)
                py_out = py_tweetnacl.crypto_hash_sha512_tweet(out, m, n)

                self.assertEqual(out, [i for i in OUT])
                self.assertEqual(tw_out, py_out)
            self.assertEqual(n, N.value)

    def test_add(self):
        '''
        test add functions
        '''
        lim = 2**27

        for p, q in randargs(self.opts['slow_test_count'], [(-lim, lim), (16, 4)], [(-lim, lim), (16, 4)]):
            P = ptr(c_longlong, p, (16, 4))
            Q = ptr(c_longlong, q, (16, 4))

            self.tweetnacl.call_fcn('add', P, Q)
            py_tweetnacl.add(p, q)

            for i, row in enumerate(P):
                self.assertEqual(p[i], [j for j in row])
            for i, row in enumerate(Q):
                self.assertEqual(q[i], [j for j in row])

    def test_cswap(self):
        '''
        test cswap functions
        '''
        for p, q, b in randargs(self.opts['test_count'], [c_longlong, (16, 4)], [c_longlong, (16, 4)], [c_ubyte]):
            P = ptr(c_longlong, p, (16, 4))
            Q = ptr(c_longlong, q, (16, 4))
            B = c_ubyte(b)

            self.tweetnacl.call_fcn('cswap', P, Q, B)
            py_tweetnacl.cswap(p, q, b)

            for i, row in enumerate(P):
                self.assertEqual(p[i], [j for j in row])
            for i, row in enumerate(Q):
                self.assertEqual(q[i], [j for j in row])
            self.assertEqual(b, B.value)

    def test_pack(self):
        '''
        test pack functions
        '''
        lim = 2**27

        for r, p in randargs(self.opts['very_slow_test_count'], [c_ubyte, 32], [(-lim, lim), (16, 4)]):
            R = ptr(c_ubyte, r)
            P = ptr(c_longlong, p, (16, 4))

            self.tweetnacl.call_fcn('pack', R, P)
            py_tweetnacl.pack(r, p)

            self.assertEqual(r, [i for i in R])
            for i, row in enumerate(P):
                self.assertEqual(p[i], [j for j in row])

    def test_scalarmult(self):
        '''
        test scalarmult functions
        '''
        lim = 2**27

        for p, q, s in randargs(self.opts['very_slow_test_count'], [(-lim, lim), (16, 4)], [(-lim, lim), (16, 4)], [c_ubyte, 32]):
            P = ptr(c_longlong, p, (16, 4))
            Q = ptr(c_longlong, q, (16, 4))
            S = ptr(c_ubyte, s)

            self.tweetnacl.call_fcn('scalarmult', P, Q, S)
            py_tweetnacl.scalarmult(p, q, s)

            for i, row in enumerate(P):
                self.assertEqual(p[i], [j for j in row])
            for i, row in enumerate(Q):
                self.assertEqual(q[i], [j for j in row])

    def test_scalarbase(self):
        '''
        test scalarbase functions
        '''
        lim = 2**27

        for p, s in randargs(self.opts['very_slow_test_count'], [(-lim, lim), (16, 4)], [c_ubyte, 32]):
            P = ptr(c_longlong, p, (16, 4))
            S = ptr(c_ubyte, s)

            self.tweetnacl.call_fcn('scalarbase', P, S)
            py_tweetnacl.scalarbase(p, s)

            for i, row in enumerate(P):
                self.assertEqual(p[i], [j for j in row])

    def test_crypto_sign_ed25519_tweet_keypair(self):
        '''
        test crypto_sign_ed25519_tweet_keypair functions
        '''
        with patch('pure_pynacl.tweetnacl.randombytes', Mock()):
            for pk, sk in randargs(self.opts['very_slow_test_count'], [c_ubyte, 64], [c_ubyte, 64]):
                PK = ptr(c_ubyte, pk)
                SK = ptr(c_ubyte, sk)

                tw_out = self.tweetnacl.call_fcn('crypto_sign_ed25519_tweet_keypair', PK, SK)
                py_out = py_tweetnacl.crypto_sign_ed25519_tweet_keypair(pk, sk)

                self.assertEqual(pk, [i for i in PK])
                self.assertEqual(sk, [i for i in SK])
                self.assertEqual(tw_out, py_out)

    def test_modL(self):
        '''
        test modL functions
        '''
        lim = 2**8

        with patch('pure_pynacl.tweetnacl.randombytes', Mock()):
            for r, x in randargs(self.opts['slow_test_count'], [c_ubyte, 64], [(-lim, lim), 64]):
                R = ptr(c_ubyte, r)
                X = ptr(c_longlong, x)

                self.tweetnacl.call_fcn('modL', R, X)
                py_out = py_tweetnacl.modL(r, x)

                self.assertEqual(r, [i for i in R])
                self.assertEqual(x, [i for i in X])
                self.assertEqual(py_out, [i for i in R])

    def test_reduce(self):
        '''
        test reduce functions
        '''
        for r in randargs(self.opts['slow_test_count'], [c_ubyte, 64]):
            R = ptr(c_ubyte, r)

            self.tweetnacl.call_fcn('reduce', R)
            py_tweetnacl.reduce(r)

            self.assertEqual(r, [i for i in R])

    def test_crypto_sign_ed25519_tweet(self):
        '''
        test crypto_sign_ed25519_tweet functions
        '''
        llim = 8
        hlim = 2**8
        test_count = int(self.opts['very_slow_test_count']**0.5)

        for n in randargs(test_count, [(llim, hlim)]):
            N = c_ulonglong(n)
            for sm, smlen, m, sk in randargs(test_count, [c_ubyte, n + 64], [c_ulonglong], [c_ubyte, n], [c_ubyte, 64]):
                SM = ptr(c_ubyte, sm)
                SMLEN = ptr(c_ulonglong, smlen)
                M = ptr(c_ubyte, m)
                SK = ptr(c_ubyte, sk)

                tw_out = self.tweetnacl.call_fcn('crypto_sign_ed25519_tweet', SM, SMLEN, M, N, SK)
                py_out = py_tweetnacl.crypto_sign_ed25519_tweet(sm, smlen, m, n, sk)

                self.assertEqual(sm, [i for i in SM])
                # In principle we should also test that
                #
                # ``str(c_ulonglong(smlen)) == SMLEN.contents``,
                #
                # but python copies the argument when the function is called
                self.assertEqual(tw_out, py_out)
            self.assertEqual(n, N.value)

    def test_unpackneg(self):
        '''
        test unpackneg functions
        '''
        for r, p in randargs(self.opts['very_slow_test_count'], [c_longlong, (16, 4)], [c_ubyte, 32]):
            R = ptr(c_longlong, r, (16, 4))
            P = ptr(c_ubyte, p)

            tw_out = self.tweetnacl.call_fcn('unpackneg', R, P)
            py_out = py_tweetnacl.unpackneg(r, p)

            for i, row in enumerate(R):
                self.assertEqual(r[i], [j for j in row])
            self.assertEqual(tw_out, py_out)

    def test_crypto_sign_ed25519_tweet_open(self):
        '''
        test crypto_sign_ed25519_tweet_open functions
        '''
        llim = 8
        hlim = 2**8
        test_count = int(self.opts['very_slow_test_count']**0.5)

        for n in randargs(test_count, [(llim, hlim)]):
            N = c_ulonglong(n)
            for m, mlen, sm, pk in randargs(test_count, [c_ubyte, n + 64], [c_ulonglong], [c_ubyte, n], [c_ubyte, 64]):
                M = ptr(c_ubyte, m)
                MLEN = ptr(c_ulonglong, mlen)
                SM = ptr(c_ubyte, sm)
                PK = ptr(c_ubyte, pk)

                tw_out = self.tweetnacl.call_fcn('crypto_sign_ed25519_tweet_open', M, MLEN, SM, N, PK)
                py_out = py_tweetnacl.crypto_sign_ed25519_tweet_open(m, mlen, sm, n, pk)

                self.assertEqual(m, [i for i in M])
                # In principle we should also test that
                #
                # ``str(c_ulonglong(mlen)) == MLEN.contents``,
                #
                # but python copies the argument when the function is called
                self.assertEqual(tw_out, py_out)
            self.assertEqual(n, N.value)


def get_opts():
    '''
    setup program options
    '''
    def test_name(name):
        '''
        parse the supplied test name
        '''
        error_message = '{0} is not in the format "NaClTest.test_<name>" or "BitTest.test_<name>"'.format(name)
        if len(name.split('Test.test_')) != 2:
            raise ArgumentTypeError(error_message)
        elif name.startswith('NaClTest') or name.startswith('BitTest'):
            return name.split('.')
        else:
            raise ArgumentTypeError(error_message)

    def parse_args():
        '''
        collect user input
        '''
        desc = ('test for parity between C and python bitwise operations and'
                ' between TweetNaCl.c and tweetnacl.py functions')
        arg_parser = ArgumentParser(description=desc,
                                    formatter_class=ArgumentDefaultsHelpFormatter)
        arg_parser.add_argument('-c','--test-count',
                                type=int,
                                default=2**11,
                                help='number of times to run each test')
        arg_parser.add_argument('-n','--test-name',
                                type=test_name,
                                default=None,
                                help='run a specific test')
        arg_parser.add_argument('-v','--verbose',
                                action='store_true',
                                help='print output for each test')
        return vars(arg_parser.parse_args())

    opts = parse_args()

    opts['script_dir'] = os.path.dirname(os.path.realpath(__file__))
    opts['slow_test_count'] = opts['test_count']//16
    opts['very_slow_test_count'] = opts['test_count']//128

    return opts


def main():
    '''
    run the comparison tests
    '''
    opts = get_opts()
    verbosity = 2 if opts.get('verbose', None) else 0

    BitTest.opts = opts
    BitTest.c_bit_ops = BitOps(opts)
    if not opts['test_name']:
        bit_suite = TestLoader().loadTestsFromTestCase(BitTest)
        TextTestRunner(verbosity=verbosity).run(bit_suite)
    elif opts['test_name'][0] == 'BitTest':
        bit_suite = TestSuite()
        bit_suite.addTest(BitTest(opts['test_name'][1]))
        TextTestRunner(verbosity=verbosity).run(bit_suite)

    NaClTest.opts = opts
    NaClTest.tweetnacl = TweetNaCl(opts)
    if not opts['test_name']:
        nacl_suite = TestLoader().loadTestsFromTestCase(NaClTest)
        TextTestRunner(verbosity=verbosity).run(nacl_suite)
    elif opts['test_name'][0] == 'NaClTest':
        nacl_suite = TestSuite()
        nacl_suite.addTest(NaClTest(opts['test_name'][1]))
        TextTestRunner(verbosity=verbosity).run(nacl_suite)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

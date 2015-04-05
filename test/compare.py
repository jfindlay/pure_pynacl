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


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

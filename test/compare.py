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
from test import ptr, randargs
from test import CLibrary

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


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

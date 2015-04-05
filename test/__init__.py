# -*- coding: utf-8 -*-
# import python libs
import os
import sys
import string
from collections import Iterable, Mapping
from random import choice, randint
from ctypes import CDLL, POINTER, sizeof
from subprocess import call


lt_py3 = sys.version_info < (3,)


def isiterable(arg):
    '''
    determine whether arg is an iterable
    '''
    if isinstance(arg, Iterable) and not isinstance(arg, Mapping):
        return True
    else:
        return False


def bytes_(byte_list):
    '''
    convert byte_list to bytes
    '''
    if lt_py3:
        return str(bytearray(byte_list))
    else:
        return bytes(byte_list)


def ptr_typ(c_type, shape):
    '''
    inductively construct a pointer to a multidimensional type specified by
    shape

    Example:

    ((c_long)*16)*256 -> c_long_Array_16_Array_256
    '''
    if isiterable(shape) and len(shape):
        if not isinstance(shape, list):
            shape = list(shape)
        dim = shape.pop()
        return (ptr_typ(c_type, shape))*dim
    else:
        return c_type


def ptr(c_type, val, shape=None):
    '''
    return a pointer to val; shape describes the dimension of val
    '''
    if isiterable(shape) and len(shape) == 2:
        ptr_obj = ptr_typ(c_type, shape)()
        for i, row in enumerate(val):
            for j, element in enumerate(row):
                ptr_obj[i][j] = val[i][j]
        return ptr_obj
    elif isiterable(val):
        return (c_type*len(val))(*val)
    else:
        return POINTER(c_type)(c_type(val))


def randnum(arg):
    '''
    uniform random variable distributed across either two boundary numbers or
    the space available in a c_type
    '''
    if isiterable(arg):
        return randint(arg[0], arg[1])
    else:  # arg is a c_type
        if 'c_u' in repr(arg):
            return randint(0, 2**(sizeof(arg)*8) - 1)
        else:
            return randint(-(2**(sizeof(arg)*8 - 1) - 1), 2**(sizeof(arg)*8 - 1) - 1)


def randchars(test_count, size):
    '''
    return a list of strings of random characters of length size
    '''
    random_chars = []
    for i in range(test_count):
        random_chars.append(''.join([choice(string.printable) for j in range(size)]))
    return random_chars


def randarg(size, shape=1):
    '''
    return random data in a tensor specified by shape; each element of the
    tensor is randomly distributed across the space available in size
    '''
    def random_data(dimension):
        '''
        inductively construct a data type specified by shape filled with
        random elements
        '''
        dimension -= 1
        if dimension >= 0:
            row = shape[dimension]
            if row == 1:  # collapse rows of no length
                return random_data(dimension)
            else:
                return [random_data(dimension) for element in range(row)]
        else:
            return randnum(size)

    if isinstance(shape, int):
        shape = [shape]  # a single integer implies a rank 1 tensor
    return random_data(len(shape))


def randargs(test_count, *args):
    '''
    generate a list of random numerical data for each arg in args
    '''
    random_list = []
    if len(args) == 1:
        for i in range(test_count):
            random_list.append(randarg(*args[0]))
    else:
        for i in range(test_count):
            arg_list = []
            for arg in args:
                if isiterable(arg):
                    arg_list.append(randarg(*arg))
                else:
                    arg_list.append(randarg(arg))
            random_list.append(arg_list)
    return random_list


class CLibrary(CDLL):
    '''
    ctypes interface to a C library
    '''
    fcns = {}  # used to define argtypes and restype

    def __init__(self, opts, path, name):
        '''
        create C library and read it into memory
        '''
        self.opts = opts
        self.name = name
        os.chdir(opts['script_dir'])
        call('rm -f ' + self.name + '.so', shell=True)
        call(['gcc', '-std=c11', '-fPIC', '-shared', '-o', name + '.so', os.path.join(path, name + '.c')])
        CDLL.__init__(self, './' + name + '.so')
        self._set_fcn_types()

    def __del__(self):
        '''
        remove library
        '''
        os.chdir(self.opts['script_dir'])
        call('rm -f ' + self.name + '.so', shell=True)

    def _set_fcn_types(self):
        '''
        specify argument types for the functions in the library
        '''
        for fcn, types in self.fcns.items():
            argtypes, restype = types
            getattr(self, fcn).argtypes = argtypes
            if restype:
                getattr(self, fcn).restype = restype

    def call_fcn(self, fcn, *args):
        '''
        call a function in the library with the provided arguments
        '''
        class ArgumentError(TypeError):
            pass

        if len(args) != len(self.fcns[fcn][0]):
            raise ArgumentError('number of arguments supplied does not match number of arguments required')

        return getattr(self, fcn)(*args)

import atexit
import collections
import ctypes
import pathlib
import random
import string
import subprocess
import tempfile


def isiterable(arg):
    '''
    Determine whether `arg` is an iterable
    '''
    if isinstance(arg, collections.abc.Iterable) and not isinstance(arg, collections.abc.Mapping):
        return True
    else:
        return False


def ptr_typ(c_type, shape):
    '''
    Inductively construct a pointer to a multidimensional type specified by `shape`

    Example:
    ```
    ((c_long)*16)*256 -> c_long_Array_16_Array_256
    ```
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
    Return a pointer to `val`; `shape` describes the dimension of `val`
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
        return ctypes.POINTER(c_type)(c_type(val))


def randnum(arg):
    '''
    Uniform random variable distributed across either the inclusive interval defined by two boundary numbers or the space
    available in a `c_type`
    '''
    if isiterable(arg):
        return random.randint(arg[0], arg[1])
    else:  # arg is a c_type
        if 'c_u' in repr(arg):
            return random.randint(0, 2**(ctypes.sizeof(arg)*8) - 1)
        else:
            return random.randint(-(2**(ctypes.sizeof(arg)*8 - 1) - 1), 2**(ctypes.sizeof(arg)*8 - 1) - 1)


def randchars(test_count, size):
    '''
    Return a list of strings of random characters of length `size`
    '''
    random_chars = []
    for i in range(test_count):
        random_chars.append(''.join([random.choice(string.printable) for j in range(size)]))
    return random_chars


def randarg(size, shape=1):
    '''
    Return random data in a multidimensional array specified by `shape`; each element of the multiarray is randomly distributed
    across the space available in `size`
    '''
    def random_data(dimension):
        '''
        Inductively construct a data type specified by `shape` filled with
        random elements
        '''
        dimension -= 1
        if dimension >= 0:
            row = shape[dimension]
            if row == 1:  # Collapse rows of no length
                return random_data(dimension)
            else:
                return [random_data(dimension) for element in range(row)]
        else:
            return randnum(size)

    if isinstance(shape, int):
        shape = [shape]  # A single integer implies a rank 1 tensor
    return random_data(len(shape))


def randargs(test_count, *args):
    '''
    Generate a list of random numerical data for each `arg` in `args`
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


class CLibrary(ctypes.CDLL):
    '''
    CTypes interface to a C library
    '''
    fcns = {}  # Used to define argtypes and restype

    def __init__(self, path, name):
        '''
        Generate a compiled C library file, load it into memory, and delete the compiled file
        '''
        self.name = name
        self.src_dir = path
        self.dst_dir = pathlib.Path(tempfile.mkdtemp(prefix=f'{self.name}-'))
        self._create()
        super().__init__(f'{self.dst_dir/self.name}.so')
        self._set_fcn_types()
        self._delete()
        atexit.register(self._delete)

    def _create(self):
        '''
        Generate compiled library file for this library
        '''
        subprocess.run(['gcc', '-std=c11', '-fPIC', '-shared', '-o', f'{self.name}.so', self.src_dir/f'{self.name}.c'], cwd=self.dst_dir)

    def _delete(self):
        '''
        Delete compiled library file and tmpdir
        '''
        if self.dst_dir.exists():
            subprocess.run(['rm', '-f', f'{self.name}.so'], cwd=self.dst_dir)
            self.dst_dir.rmdir()

    def _set_fcn_types(self):
        '''
        Specify argument and return types for the functions in the library
        '''
        for fcn, types in self.fcns.items():
            argtypes, restype = types
            getattr(self, fcn).argtypes = argtypes
            if restype:
                getattr(self, fcn).restype = restype

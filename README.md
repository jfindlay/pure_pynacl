# pure_pynacl

This library is intended to be an exact as possible python translation of the [TweetNaCl](https://tweetnacl.cr.yp.to/) minimal
elliptic curve cryptography library.  Interested parties are invited to compare the contents of `pure_pynacl/tweetnacl.py` and
`tweetnacl/TweetNaCl.c`.  `tweetnacl/TweetNaCl.c` has been carefully and deliberately modified from the original in the first
several commits of this repo, mostly to remove the unnecessary preprocessor statements.

## Motivation

The original goal of `pure_pynacl` was to provide a limited but sufficient crypto library for arcane or obscure platforms, for
which porting, adopting, or maintaining dependencies would be challenging.  Using
[`pypy`](https://doc.pypy.org/en/latest/introduction.html) could make execution slightly faster, however, `pypy` [is
not](https://doc.pypy.org/en/latest/faq.html#couldn-t-the-jit-dump-and-reload-already-compiled-machine-code) bytecode-equivalent
to CPython or any other python runtime.  The bytecode incompatibility of `pypy` with CPython and also the inability of
[translating down to C](https://rpython.readthedocs.io/en/latest/faq.html#can-rpython-compile-normal-python-programs-to-c) for
`RPython` circumscribes its potential as a passive optimizer for expensive parts of large programs that cannot feasibly platform
on `pypy`.  (Evidently [doing this](https://stackoverflow.com/questions/60792018/build-python-file-with-pypy) is anathema to the
project, which seems to have more rigorous than convenience goals.)  If python (CPython) has been ported to an exotic or unusual
platform, or even if it could be, porting pypy will likely be at least as challenging as porting a standard crypto library like
{open|libre}ssl.  Any performance gains from using `pure_pynacl` combined with the convenience of a complete python source are
likely not going to exceed the benefit of porting a standard crypto library to the platform.

There are critical junctures in history where momentous conventions are set by often unwitting actors.  The creation of C and
the subsequent popularity and open nature of the C/Unix ecosystem is one of them.  Supposing some other generic language family,
lisp, smalltalk, ocaml, eiffel, erlang, forth, or any purported language most excellent for systems programming were better than
C, it would still be irrelevant.  Macroeconomic inertia dictates that C be the universal language of platforms and the volume
and depth of its mindshare could not be diverted by expense of fortune or force of decree.  Any platform that wants more than
irrelevance will market itself with a C-compatible operating system or driver and associated libraries.  Thus, any python
project wanting to port to such an obscure platform (for which CPython has already been ported), would likely be wiser to port a
C-based crypto lib than run `pure_pynacl` even as a fallback.

For non-obscure platforms, python has very good CFFI with CTypes and there are several python crypto libraries that use this
internally if not SWIG.

Finally, [`NaCl`](https://nacl.cr.yp.to/), the superset of `TweetNaCl`, [does not even provide](https://nacl.cr.yp.to/box.html)
the complete set of crypto features expected from a modern crypto library.  Among other caveats throughout the docs: "On the
contrary: the [public key] `crypto_box` function *guarantees* repudiability [emph. original]."  Scraping standard crypto library
output with `import subprocess` would still likely be better than `import pure_pynacl`.

What remains then is the crypto learning and intellectual exercise I enjoyed creating this library, the C-compatible types, and
multidimensional random data factories used for testing.  You are welcome to use this project however you desire as governed by
the license.  GPLv[latest] is my default, but Apache 2.0 was requested and I am fine keeping it that way.

## Testing

`tox run -e ALL`

## Building

`python -m build --build-wheel`

## Installation

### From PyPI

`pip install pure_pynacl`

### From source

`git clone https://github.com/jfindlay/pure_pynacl.git`

## Using pure_pynacl

Consult the [`NaCl` documentation](https://nacl.cr.yp.to/box.html) for complete details of correct usage.
```python
import pure_pynacl as pynacl
...
result = pynacl.crypto_sign_ed25519_tweet(sm, smlen, m, n, sk)
```

## Comparison tests

Unit tests that verify the parity of TweetNaCl and pure_pynacl are located in a file called `tests/ref_test.py`.  This file also
contains tests that compare the parity of C bitwise operations and bitwise operations on the `Int` type defined in `NaCl.py`.
These tests can be run with the following command.
```console
$ tox run -e unit
```

Currently, the parity testing is only parallel, meaning that for each function in the libraries, identical input data is
supplied and the output data is expected to be identical.

### Parallel testing

```
TweetNaCl.c     NaCl.py

     .------in-----.
     |             |
     v             v
    fcn           fcn
     |             |
     v             v
    out     ==    out
```

### Antiparallel testing

Antiparallel testing is much less symmetric and only covers the external API as the implementation of the internal utilities are
not necessarily invertible.  Input data is sent through each function in one library and then through the corresponding counter
function in the other library such that the output data is identical to the input data.
```
          in                     in
          |                      |
          v                      v
     TweetNacl.fcn       TweetNacl.inv_fcn
          |                      |
          v                      v
 pure_pynacl.inv_fcn      pure_pynacl.fcn
          |                      |
          v                      v
         out == in              out == in


          in                     in
          |                      |
          v                      v
   pure_pynacl.fcn      pure_pynacl.inv_fcn
          |                      |
          v                      v
  TweetNacl.inv_fcn         TweetNacl.fcn
          |                      |
          v                      v
         out == in              out == in
```

## C99 bit shifting operations

Right-shifts of negative signed numbers are implementation-defined. All of the other cases that are not explicitly undefined are
specified.

### From C99

The integer promotions are performed on each of the operands. The type of the result is that of the promoted left operand. If
the value of the right operand is negative or is greater than or equal to the width of the promoted left operand, the behavior
is undefined.

The result of `E1 << E2` is `E1` left-shifted `E2` bit positions; vacated bits are filled with zeros. If `E1` has an unsigned
type, the value of the result is `E1 x 2^E2`, reduced modulo one more than the maximum value representable in the result type.
If `E1` has a signed type and nonnegative value, and `E1 x 2^E2` is representable in the result type, then that is the resulting
value; otherwise, the behavior is undefined.

The result of `E1 >> E2` is `E1` right-shifted `E2` bit positions. If `E1` has an unsigned type or if `E1` has a signed type and
a nonnegative value, the value of the result is the integral part of the quotient of `E1 / 2^E2`. If `E1` has a signed type and
a negative value, the resulting value is implementation-defined.

### `a << b and a >> b`

0. `a` and `b` are promoted before operation; the result has the type of
`promoted(a)`

1. `if b < 0`
  `a << b and a >> b` are undefined

2. `if b > len(a)`
  `a << b and a >> b` are undefined

3. `if a < 0`
  `a << b` and `a >> b` are undefined

`a << b`
4. `if a >= 0 and b >= 0`
  `if a not signed`
    `a << b == a*2**b%bits(a)`
  `elif a is signed`
    `if a*2**b in type(a)`
      `a << b == a*2**b`
    `else`
      `a << b` is undefined

`a >> b`
5. `if a >= 0 and b >= 0`
  `a >> b == a//2**b`

## `ctypes` multidimensional pointers

- https://stackoverflow.com/a/4101777
- https://stackoverflow.com/a/13821520

C99 bit shifting operations
===========================

Right-shifts of negative signed numbers are implementation-defined. All of the
other cases that are not explicitly undefined are specified.

From C99
--------

The integer promotions are performed on each of the operands. The
type of the result is that of the promoted left operand. If the value of the
right operand is negative or is greater than or equal to the width of the
promoted left operand, the behavior is undefined.

The result of E1 << E2 is E1 left-shifted E2 bit positions; vacated bits are
filled with zeros. If E1 has an unsigned type, the value of the result is E1 x
2^E2, reduced modulo one more than the maximum value representable in the
result type. If E1 has a signed type and nonnegative value, and E1 x 2^E2 is
representable in the result type, then that is the resulting value; otherwise,
the behavior is undefined.

The result of E1 >> E2 is E1 right-shifted E2 bit positions. If E1 has an
unsigned type or if E1 has a signed type and a nonnegative value, the value of
the result is the integral part of the quotient of E1 / 2^E2. If E1 has a
signed type and a negative value, the resulting value is
implementation-defined.

`a << b and a >> b`
-------------------

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


ctypes multidimensional pointers
================================

https://stackoverflow.com/a/4101777
https://stackoverflow.com/a/13821520


TODO
====

- tests
  - unit
    - antiparallel tests
  - integration
    - parallel and antiparallel tests on the API
    - antiparallel tests against other NaCl implementations
      - libsodium
      - libNaCl
      - pyNaCl
      - others
  - performance
    - for pure_pynacl types
    - comparison between TweetNaCl.c via ctypes and tweetnacl.py
    - pypy compiled pure_pynacl
    - tweetnacl.py against other NaCl implementations
- implement full NaCl library in pure_pynacl

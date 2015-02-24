# pure_pynacl

This library is intended to be a complete, pure python implementation of
[NaCl](http://nacl.cr.yp.to/).  Initially, only the methods and functionality
condensed into [TweetNaCl](http://tweetnacl.cr.yp.to/) have been implemented as
TweetNaCl is a minimal but still usable and fairly complete elliptic curve
cryptographic library.

The documentation available at [NaCl](http://nacl.cr.yp.to/) should be
sufficient for pure_pynacl inasmuch as it correctly describes TweetNaCl also,
since great effort has been expended to establish and ensure exhaustive parity
between TweetNaCl and pure_pynacl.

## Using pure_pynacl

```python
import pure_pynacl as pynacl
...
result = pynacl.crypto_sign_ed25519_tweet(sm, smlen, m, n, sk)
```

## Comparison tests

Unit tests that verify the parity of TweetNaCl and pure_pynacl are located in a
file called `tests/compare.py`.  This file also contains tests that compare the
parity of C bitwise operations and bitwise operations on the `Int` type defined
in `NaCl.py`.  These tests can be run with the following command.
```console
$ python test/compare.py -v
```

Currently, the parity testing is only parallel, meaning that for each function
in the libraries, identical input data is supplied and the output data is
expected to be identical.  I intend to add antiparallel tests, meaning that
input data is sent through each function in one library and then through the
corresponding counter function in the other library such that the output data
is identical to the input data.

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

Antiparallel testing is much less symmetric and only covers the external API as
the implementation of the internal utilities are not necessarily invertible.
```
          in
          |
          v
     TweetNacl.fcn
          |
          v
 pure_pynacl.inv_fcn
          |
          v
         out == in
```
```
          in
          |
          v
  TweetNacl.inv_fcn
          |
          v
   pure_pynacl.fcn
          |
          v
         out == in
```
```
          in
          |
          v
   pure_pynacl.fcn
          |
          v
  TweetNacl.inv_fcn
          |
          v
         out == in
```
```
          in
          |
          v
 pure_pynacl.inv_fcn
          |
          v
     TweetNacl.fcn
          |
          v
         out == in
```

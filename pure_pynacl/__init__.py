from array import array


class TypeEnum:
    '''
    Order types used by pure_pynacl for rapid type promotion.
    '''
    u8 = 1
    u32 = 2
    u64 = 3
    Int = 5
    i64 = 7
    int = 11


class Int(int):
    '''
    Integer types.
    '''
    bits = array('i').itemsize*8
    mask = (1 << bits - 1) - 1
    signed = True
    order = TypeEnum.Int

    def __str__(self):
        return int.__str__(self)

    def __repr__(self):
        return f'{type(self).__name__}({int.__repr__(self)})'

    def __new__(self, val=0):
        '''
        Ensure that new instances have the correct size and sign.
        '''
        if val < 0:
            residue = int(-val) & self.mask
            if self.signed:
                residue = -residue
        else:
            residue = int(val) & self.mask
        return int.__new__(self, residue)

    def __promote_type(self, other, result):
        '''
        Determine the largest type from those in self and other; if result is
        negative and both self and other are unsigned, promote it to the least
        signed type.
        '''
        self_order = self.order
        other_order = other.order if isinstance(other, Int) else TypeEnum.int

        if result < 0 and self_order < 5 and other_order < 5:
            return Int
        return self.__class__ if self_order > other_order else other.__class__

    def __unary_typed(oper):
        '''
        Return a function that redefines the operation oper such that the
        result conforms to the type of self.
        '''
        def operate(self):
            '''
            Type the result to self.
            '''
            return self.__class__(oper(self))
        return operate

    def __typed(oper):
        '''
        Return a function that redefines the operation oper such that the
        result conforms to the type of self or other, whichever is larger if
        both are strongly typed (have a bits attribute); otherwise return the
        result conforming to the type of self.
        '''
        def operate(self, other):
            '''
            Type and bitmask the result to either self or other, whichever is
            larger.
            '''
            result = oper(self, other)
            return self.__promote_type(other, result)(result)
        return operate

    def __shift(oper):
        '''
        Return a function that performs bit shifting, but preserves the type of
        the left value.
        '''
        def operate(self, other):
            '''
            Emulate C bit shifting.
            '''
            return self.__class__(oper(self, other))
        return operate

    def __invert():
        '''
        Return a function that performs bit inversion.
        '''
        def operate(self):
            '''
            Emulate C bit inversion.
            '''
            if self.signed:
                return self.__class__(int.__invert__(self))
            else:
                return self.__class__(int.__xor__(self, self.mask))
        return operate

    # bitwise operations
    __lshift__  = __shift(int.__lshift__)
    __rlshift__ = __shift(int.__rlshift__)
    __rshift__  = __shift(int.__rshift__)
    __rrshift__ = __shift(int.__rrshift__)
    __and__     = __typed(int.__and__)
    __rand__    = __typed(int.__rand__)
    __or__      = __typed(int.__or__)
    __ror__     = __typed(int.__ror__)
    __xor__     = __typed(int.__xor__)
    __rxor__    = __typed(int.__rxor__)
    __invert__  = __invert()

    # arithmetic operations
    __ceil__      = __unary_typed(int.__ceil__)
    __floor__     = __unary_typed(int.__floor__)
    __int__       = __unary_typed(int.__int__)
    __abs__       = __unary_typed(int.__abs__)
    __pos__       = __unary_typed(int.__pos__)
    __neg__       = __unary_typed(int.__neg__)
    __add__       = __typed(int.__add__)
    __radd__      = __typed(int.__radd__)
    __sub__       = __typed(int.__sub__)
    __rsub__      = __typed(int.__rsub__)
    __mod__       = __typed(int.__mod__)
    __rmod__      = __typed(int.__rmod__)
    __mul__       = __typed(int.__mul__)
    __rmul__      = __typed(int.__rmul__)
    __floordiv__  = __typed(int.__floordiv__)
    __rfloordiv__ = __typed(int.__rfloordiv__)
    __pow__       = __typed(int.__pow__)
    __rpow__      = __typed(int.__rpow__)


class IntArray(list):
    '''
    Arrays of int types.
    '''
    def __init__(self, typ, init=(), size=0):
        '''
        Create array of ints.
        '''
        self.typ = typ

        if size:
            init_size = len(init)
            if init_size < size:
                list.__init__(self, [typ(i) for i in init] + [typ() for i in range(size - init_size)])
            else:
                list.__init__(self, [typ(i) for i in init[:size]])
        else:
            list.__init__(self, [typ(i) for i in init])

    def __str__(self):
        return list.__str__(self)

    def __repr__(self):
        return f'{type(self)}({self.typ}, init={list.__repr__(self)})'


# TweetNaCl external functions
from pure_pynacl.tweetnacl import (
    crypto_box_curve25519xsalsa20poly1305_tweet,
    crypto_box_curve25519xsalsa20poly1305_tweet_afternm,
    crypto_box_curve25519xsalsa20poly1305_tweet_beforenm,
    crypto_box_curve25519xsalsa20poly1305_tweet_keypair,
    crypto_box_curve25519xsalsa20poly1305_tweet_open,
    crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm,
    crypto_core_hsalsa20_tweet, crypto_core_salsa20_tweet,
    crypto_hash_sha512_tweet, crypto_hashblocks_sha512_tweet,
    crypto_onetimeauth_poly1305_tweet,
    crypto_onetimeauth_poly1305_tweet_verify,
    crypto_scalarmult_curve25519_tweet,
    crypto_scalarmult_curve25519_tweet_base,
    crypto_secretbox_xsalsa20poly1305_tweet,
    crypto_secretbox_xsalsa20poly1305_tweet_open, crypto_sign_ed25519_tweet,
    crypto_sign_ed25519_tweet_keypair, crypto_sign_ed25519_tweet_open,
    crypto_stream_salsa20_tweet, crypto_stream_salsa20_tweet_xor,
    crypto_stream_xsalsa20_tweet, crypto_stream_xsalsa20_tweet_xor,
    crypto_verify_16_tweet, crypto_verify_32_tweet)

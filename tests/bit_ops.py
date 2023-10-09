#!/usr/bin/env python

from pure_pynacl.tweetnacl import i64, u8, u32, u64

# unsigned 8 bit tests

def lshift_u8(x, c):
    return u8(x) << u8(c)

def rshift_u8(x, c):
    return u8(x) >> u8(c)

def and_u8(x, y):
    return u8(x) & u8(y)

def or_u8(x, y):
    return u8(x) | u8(y)

def xor_u8(x, y):
    return u8(x) ^ u8(y)

def not_u8(x):
    return ~u8(x)

# unsigned 32 bit tests

def lshift_u32(x, c):
    return u32(x) << u8(c)

def rshift_u32(x, c):
    return u32(x) >> u8(c)

def and_u32(x, y):
    return u32(x) & u32(y)

def or_u32(x, y):
    return u32(x) | u32(y)

def xor_u32(x, y):
    return u32(x) ^ u32(y)

def not_u32(x):
    return ~u32(x)

# unsigned 64 bit tests

def lshift_u64(x, c):
    return u64(x) << u8(c)

def rshift_u64(x, c):
    return u64(x) >> u8(c)

def and_u64(x, y):
    return u64(x) & u64(y)

def or_u64(x, y):
    return u64(x) | u64(y)

def xor_u64(x, y):
    return u64(x) ^ u64(y)

def not_u64(x):
    return ~u64(x)

# signed 64 bit tests

def lshift_i64(x, c):
    return i64(x) << u8(c)

def rshift_i64(x, c):
    return i64(x) >> u8(c)

def and_i64(x, y):
    return i64(x) & i64(y)

def or_i64(x, y):
    return i64(x) | i64(y)

def xor_i64(x, y):
    return i64(x) ^ i64(y)

def not_i64(x):
    return ~i64(x)

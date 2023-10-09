typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];


// unsigned 8 bit tests

u8 lshift_u8(const u8 x, const u8 c)
{ return x << c; }

u8 rshift_u8(const u8 x, const u8 c)
{ return x >> c; }

u8 and_u8(const u8 x, const u8 y)
{ return x & y; }

u8 or_u8(const u8 x, const u8 y)
{ return x | y; }

u8 xor_u8(const u8 x, const u8 y)
{ return x ^ y; }

u8 not_u8(const u8 x)
{ return ~x; }

// unsigned 32 bit tests

u32 lshift_u32(const u32 x, const u8 c)
{ return x << c; }

u32 rshift_u32(const u32 x, const u8 c)
{ return x >> c; }

u32 and_u32(const u32 x, const u32 y)
{ return x & y; }

u32 or_u32(const u32 x, const u32 y)
{ return x | y; }

u32 xor_u32(const u32 x, const u32 y)
{ return x ^ y; }

u32 not_u32(const u32 x)
{ return ~x; }

// unsigned 64 bit tests

u64 lshift_u64(const u64 x, const u8 c)
{ return x << c; }

u64 rshift_u64(const u64 x, const u8 c)
{ return x >> c; }

u64 and_u64(const u64 x, const u64 y)
{ return x & y; }

u64 or_u64(const u64 x, const u64 y)
{ return x | y; }

u64 xor_u64(const u64 x, const u64 y)
{ return x ^ y; }

u64 not_u64(const u64 x)
{ return ~x; }

// signed 64 bit tests

i64 lshift_i64(const i64 x, const u8 c)
{ return x << c; }

i64 rshift_i64(const i64 x, const u8 c)
{ return x >> c; }

i64 and_i64(const i64 x, const i64 y)
{ return x & y; }

i64 or_i64(const i64 x, const i64 y)
{ return x | y; }

i64 xor_i64(const i64 x, const i64 y)
{ return x ^ y; }

i64 not_i64(const i64 x)
{ return ~x; }

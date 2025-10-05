import struct
import hashlib
import random
import os

def md4(message: bytes) -> bytes:
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def left_rotate(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff

    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    ml = len(message) * 8
    message += b"\x80"
    while (len(message) * 8) % 512 != 448:
        message += b"\x00"
    message += struct.pack("<Q", ml)  # little endian, length 64

    for offset in range(0, len(message), 64):
        X = list(struct.unpack("<16I", message[offset:offset+64]))
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        S = [3, 7, 11, 19]
        for i in range(16):
            k = i
            s = S[i % 4]
            if i % 4 == 0:
                A = left_rotate((A + F(B, C, D) + X[k]) & 0xffffffff, s)
            elif i % 4 == 1:
                D = left_rotate((D + F(A, B, C) + X[k]) & 0xffffffff, s)
            elif i % 4 == 2:
                C = left_rotate((C + F(D, A, B) + X[k]) & 0xffffffff, s)
            else:
                B = left_rotate((B + F(C, D, A) + X[k]) & 0xffffffff, s)

        # Round 2
        S = [3, 5, 9, 13]
        order = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
        for i in range(16):
            k = order[i]
            s = S[i % 4]
            if i % 4 == 0:
                A = left_rotate((A + G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, s)
            elif i % 4 == 1:
                D = left_rotate((D + G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, s)
            elif i % 4 == 2:
                C = left_rotate((C + G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, s)
            else:
                B = left_rotate((B + G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, s)

        # Round 3
        S = [3, 9, 11, 15]
        order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for i in range(16):
            k = order[i]
            s = S[i % 4]
            if i % 4 == 0:
                A = left_rotate((A + H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            elif i % 4 == 1:
                D = left_rotate((D + H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            elif i % 4 == 2:
                C = left_rotate((C + H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            else:
                B = left_rotate((B + H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, s)

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff

    return struct.pack("<4I", A, B, C, D)

message = b"test_message"
h = hashlib.new("md4")
h.update(message)
assert h.digest() == md4(message)

# HLE attack

def md4_ext(message:bytes, states:list, full_len:int) -> bytes:
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def left_rotate(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
    
    assert len(states) == 4
    A, B, C, D = states
    assert (full_len - len(message)) % 64 == 0
    ml = full_len * 8
    message += b"\x80" + b"\x00" * (((448 - (ml + 8)) % 512) // 8)
    message += struct.pack("<Q", ml)  # little endian, length 64

    for offset in range(0, len(message), 64):
        X = list(struct.unpack("<16I", message[offset:offset+64]))
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        S = [3, 7, 11, 19]
        for i in range(16):
            k = i
            s = S[i % 4]
            if i % 4 == 0:
                A = left_rotate((A + F(B, C, D) + X[k]) & 0xffffffff, s)
            elif i % 4 == 1:
                D = left_rotate((D + F(A, B, C) + X[k]) & 0xffffffff, s)
            elif i % 4 == 2:
                C = left_rotate((C + F(D, A, B) + X[k]) & 0xffffffff, s)
            else:
                B = left_rotate((B + F(C, D, A) + X[k]) & 0xffffffff, s)

        # Round 2
        S = [3, 5, 9, 13]
        order = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
        for i in range(16):
            k = order[i]
            s = S[i % 4]
            if i % 4 == 0:
                A = left_rotate((A + G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, s)
            elif i % 4 == 1:
                D = left_rotate((D + G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, s)
            elif i % 4 == 2:
                C = left_rotate((C + G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, s)
            else:
                B = left_rotate((B + G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, s)

        # Round 3
        S = [3, 9, 11, 15]
        order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for i in range(16):
            k = order[i]
            s = S[i % 4]
            if i % 4 == 0:
                A = left_rotate((A + H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            elif i % 4 == 1:
                D = left_rotate((D + H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            elif i % 4 == 2:
                C = left_rotate((C + H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            else:
                B = left_rotate((B + H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, s)

        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff
    return struct.pack("<4I", A, B, C, D)

def pad(l):
    ml = l * 8
    p =  b"\x80"
    r = ml + 8
    p += b"\x00" * (((448 - r) % 512) // 8)
    p += int.to_bytes(ml, 8, "little") 
    return p

kl = random.randint(0, 32)
KEY = os.urandom(kl)
def md4_mac(message):
    return md4(KEY + message)

text = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon" 
text_mac = md4_mac(text)
A, B, C, D = struct.unpack("<4I", text_mac)
states = [A, B, C, D]
text_add = b";admin=true;"

for i in range(33):
    forged = text + pad(i + len(text)) + text_add
    forged_mac = md4_ext(text_add, states, len(forged)+i)
    if md4_mac(forged) == forged_mac:
        print(f"Found, key length is {i}")
        break

assert i == len(KEY)
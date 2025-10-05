# Note 1: All variables are unsigned 32-bit quantities and wrap modulo 2^32 when calculating, except for
#         ml, the message length, which is a 64-bit quantity, and
#         hh, the message digest, which is a 160-bit quantity.
# Note 2: All constants in this pseudo code are in big endian.
#         Within each word, the most significant byte is stored in the leftmost byte position

# Initialize variables:

from hashlib import sha1

def custom_sha1(message):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    #message length in bits (always a multiple of the number of bits in a character).
    ml = len(message) * 8
    message = message + b"\x80"
    r = ml + 8
    message += b"\x00" * (((448 - r) % 512) // 8)
    message += int.to_bytes(ml, 8, "big") 
    chunks = [message[i:i+64] for i in range(0, len(message), 64)]

    # Pre-processing:
    # append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
    # append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
    #    is congruent to −64 ≡ 448 (mod 512)
    # append ml, the original message length in bits, as a 64-bit big-endian integer. 
    #    Thus, the total length is a multiple of 512 bits.
    # Process the message in successive 512-bit chunks:
    
    for chunk in chunks:
        assert len(chunk) == 64
        w = [int.from_bytes(chunk[i:i+4], "big") for i in range(0, len(chunk), 4)]
        
    # break message into 512-bit chunks
    # for each chunk
    #     break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15

    #     Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        for i in range(16, 80):
            # Note 3: SHA-0 differs by not having this leftrotate.
            x = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            w.append(((x << 1) | (x >> 31)) & 0xFFFFFFFF)

    # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19: 
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) ^ (b & d) ^ (c & d) 
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (((a << 5) | (a >> 27)) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = ((b << 30) | (b >> 2)) & 0xFFFFFFFF
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF 
        h1 = (h1 + b) & 0xFFFFFFFF 
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return int.to_bytes(hh, 20, "big")

key = b"YELLOW_SUBMARINE"
def mac(message):
    return custom_sha1(key + message)

text = b"I do not care what you is talking about. I need to finish this!!!" 

print(mac(text) == sha1(key + text).digest())
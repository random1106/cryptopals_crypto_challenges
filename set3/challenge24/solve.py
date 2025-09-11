import random
import time

# recommended seed = 19650218
class MT19937:

    n = 624
    m = 397
    w = 32
    r = 31
    UMASK = 0xffffffff << r
    LMASK = 0xffffffff >> (w-r)
    a = 0x9908b0df
    u = 11
    s = 7
    t = 15
    l = 18
    b = 0x9d2c5680
    c = 0xefc60000
    f = 1812433253

    def __init__(self, seed):
        self.seed = seed & ((1 << self.w) - 1)
        self.state_array = [0] * self.n
        self.state_index = 0

# state = {"state_array":[0]*n, "state_index":0}

    def initialize_state(self):
        self.state_array[0] = self.seed
        for i in range(1, self.n):
            self.seed = (self.f * (self.seed ^ (self.seed >> self.w-2)) + i) & ((1 << self.w) - 1)
            self.state_array[i] = self.seed

        self.state_index = 0

    def twister(self):
        k = self.state_index

        j = k - (self.n-1)
        if j < 0:
            j += self.n

        x = ((self.state_array[k] & self.UMASK) | (self.state_array[j] & self.LMASK)) & ((1 << self.w) - 1)

        xA = x >> 1
        if (x & 0x00000001):
            xA ^= self.a

        j = k - (self.n - self.m)
        if j < 0:
            j += self.n 

        x = self.state_array[j] ^ xA
        self.state_array[k] = x
        k += 1

        if (k >= self.n):
            k = 0
        
        self.state_index = k

        return x

    def temper(self):
        x = self.twister()
        y = (x^(x >> self.u)) & ((1 << self.w) - 1)
        y = (y ^ ((y << self.s) & self.b)) & ((1 << self.w) - 1)
        y = (y ^ ((y << self.t) & self.c)) & ((1 << self.w) - 1)
        z = y ^ (y >> self.l)

        return z
    
seed = random.randint(0, 2**16 - 1)
num = random.randint(5, 20)
prefix = bytes([random.randint(0, 255) for _ in range(num)])
text = prefix + b"A" * 14

def encrypt_MT19937(text, seed):
    RNG = MT19937(seed)
    RNG.initialize_state()
    res = []
    for k in range(len(text) // 4):
        key = RNG.temper()
        for i in range(4):
            res.append(((key >> (3-i)*8) & 0xFF) ^ text[4*k + i])

    for i in range(len(text) % 4):
        key = RNG.temper()
        res.append(((key >> (3-i)*8) & 0xFF) ^ (text[4*(len(text) // 4) + i]))

    return bytes(res)

encrypted_text = encrypt_MT19937(text, seed)

def crack_seed(encrypted_text, a, b):
    for seed in range(a, b):
        RNG = MT19937(seed)
        RNG.initialize_state()
        res = []
        for k in range(len(encrypted_text) // 4):
            key = RNG.temper()
            for i in range(4):
                res.append(((key >> (3-i)*8) & 0xFF) ^ encrypted_text[4*k + i])

        for i in range(len(encrypted_text) % 4):
            key = RNG.temper()
            res.append(((key >> (3-i)*8) & 0xFF) ^ (encrypted_text[4*(len(encrypted_text) // 4) + i]))

        assert len(res) == len(encrypted_text)
        if bytes(res)[-14:] == b"A" * 14:
            return seed
    return "Do not find seed"

cracked_seed = crack_seed(encrypted_text, a=0, b=2**16)
print("brute-force regime, the seed is cracked:", cracked_seed == seed)
print("The cracked seed", cracked_seed)

seed = int(time.time())
encrypted_text = encrypt_MT19937(text, seed)

cracked_seed = crack_seed(encrypted_text, a=int(time.time()) - 1000, b=int(time.time()) + 1000)
print("time based attack, the seed is cracked:", cracked_seed == seed)
print("The cracked seed", cracked_seed)
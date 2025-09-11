import time
from datetime import datetime, timezone
import random
from collections import deque
import numpy as np

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
        y = x^(x >> self.u) 
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        z = y ^ (y >> self.l)
        return z
    
class MT19937_cracker:

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

    state_array = [0] * n
    state_index = 0
    p = 0
    
    def untemper(self, RNGs):
        assert len(RNGs) == self.n
        
        for z in RNGs:  
            # step 1
            y_digits = [int(d) for d in bin(z >> (self.w-self.l))[2:].zfill(self.l)]
            z_digits = [int(d) for d in bin(z)[2:].zfill(self.w)]
            i = 0
            while i < self.w-self.l:
                y_digits.append(z_digits[i+self.l] ^ y_digits[i])
                i += 1
            y = int("".join([str(d) for d in y_digits]), 2)

            y_digits = [int(d) for d in bin(y)[2:].zfill(self.w)]
            c_digits = [int(d) for d in bin(self.c)[2:].zfill(self.w)]

            # step 2
            y_digits_reversed = [(y_digits[-i-1])^(c_digits[-i-1]) for i in range(self.t)]
            i = 0
            while i < self.w-self.t:
                y_digits_reversed.append((y_digits[-i-1-self.t])^(y_digits_reversed[i] & c_digits[-i-1-self.t]))
                i += 1
            y = int("".join([str(d) for d in y_digits_reversed])[::-1], 2)

            # step 3
            y_digits = [int(d) for d in bin(y)[2:].zfill(self.w)]
            b_digits = [int(d) for d in bin(self.b)[2:].zfill(self.w)]

            y_digits_reversed = [(y_digits[-i-1])^(b_digits[-i-1]) for i in range(self.s)]
            i = 0
            while i < self.w-self.s:
                y_digits_reversed.append((y_digits[-i-1-self.s])^(y_digits_reversed[i] & b_digits[-i-1-self.s]))
                i += 1
            y = int("".join([str(d) for d in y_digits_reversed])[::-1], 2)

            # step 4
            x_digits = [int(d) for d in bin(y >> (self.w-self.u))[2:].zfill(self.u)]
            y_digits = [int(d) for d in bin(y)[2:].zfill(self.w)]
            i = 0
            while i < self.w-self.u:
                x_digits.append(y_digits[i+self.u] ^ x_digits[i])
                i += 1
            x = int("".join([str(d) for d in x_digits]), 2)

            self.state_array[self.p] = x
            self.p += 1

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
    
n = 624
N = 2000

RNG = MT19937(seed = 19650218)
RNG.initialize_state()

output = []

for _ in range(N):
    output.append(RNG.temper())

RNG_cracker = MT19937_cracker()
cloned_output = output[:n]

RNG_cracker.untemper(cloned_output)

for _ in range(N-n):
    cloned_output.append(RNG_cracker.temper())

print(cloned_output == output)
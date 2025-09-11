import time
from datetime import datetime, timezone
import random

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
    
utc_time = datetime(2025, 5, 31, 4, 0, 0, tzinfo=timezone.utc).timestamp()
wait_time = random.randint(40, 300)
time.sleep(wait_time)
seed = int(wait_time + utc_time)

RNG = MT19937(seed)
RNG.initialize_state()
target =  RNG.temper()

start_utc = datetime(2025, 5, 31, 4, 0, 0, tzinfo=timezone.utc)
end_utc = datetime(2025, 5, 31, 4, 5, 0, tzinfo=timezone.utc)
start = int(start_utc.timestamp())
end = int(end_utc.timestamp())

def crack_seed(start_time, end_time, target):
    for t in range(start_time, end_time+1):
        RNG = MT19937(t)
        RNG.initialize_state()
        if RNG.temper() == target:
            return t
    return "Seed not found"

cracked_seed = crack_seed(start, end, target)

print(cracked_seed == seed)
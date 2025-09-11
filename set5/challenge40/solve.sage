from Crypto.Util.number import getPrime
import random

m = random.getrandbits(512)
print(m)

def encrypt_once(m):
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        if p != q and p % 3 != 1 and q % 3 != 1:
            break

    n = p * q
    e = 3
    et = (p-1) * (q-1)
    d = pow(e, -1, et)

    ct = pow(m, e, n)
    return ct, n

ct1, n1 = encrypt_once(m)
ct2, n2 = encrypt_once(m)
ct3, n3 = encrypt_once(m)

x = crt([ct1, ct2, ct3], [n1, n2, n3])
x = x % lcm([n1, n2, n3])

print(x^(1/3)) # should be the same as m
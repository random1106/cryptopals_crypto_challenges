from Crypto.Util.number import getPrime

while True:
    p = getPrime(1024)
    q = getPrime(1024)
    if p != q and p % 3 != 1 and q % 3 != 1:
        break

n = p * q
e = 3
et = (p-1) * (q-1)

d = pow(e, -1, et)

m = 42

ct = pow(m, e, n)
dt = pow(ct, d, n)

assert dt == m


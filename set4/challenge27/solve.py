from Crypto.Cipher import AES
import os

def xor(a, b):
    return bytes(x^y for x, y in zip(a, b))

key = os.urandom(16)
iv = key
cipher = AES.new(key, AES.MODE_CBC, iv=iv)

m = cipher.encrypt(b"A" * 16)

forged = m + b"\x00" * 16 + m
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
dt =  cipher.decrypt(forged)

print(xor(dt[:16], dt[-16:]) == key)
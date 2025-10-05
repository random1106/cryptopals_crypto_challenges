from Crypto.Cipher import AES
from Crypto.Util import Counter
import os
import base64
import numpy as np

data = np.loadtxt("https://cryptopals.com/static/challenge-data/25.txt", dtype="str")
data = base64.b64decode(data)
KEY = b"YELLOW SUBMARINE"
cipher = AES.new(KEY, AES.MODE_ECB)
MESSAGE = cipher.decrypt(data)

nonce = os.urandom(8)
KEY = os.urandom(16)
ctr = Counter.new(64, prefix=nonce)
cipher = AES.new(KEY, AES.MODE_CTR, nonce=nonce)
ct = cipher.encrypt(MESSAGE)

def edit(ct, offset, nt, key=KEY):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    dt = cipher.decrypt(ct)
    assert offset + len(nt) <= len(dt)
    mt = dt[:offset] + nt + dt[offset + len(nt):]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(mt)

def decrypt_CTR(ct):
    xor_key = []
    for i in range(len(ct)):
        xor_key.append(edit(ct, i, b"\x00")[i] ^ 0)
    return xor(bytes(xor_key), ct)

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

assert MESSAGE == decrypt_CTR(ct)
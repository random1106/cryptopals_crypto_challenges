from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

STRING_TO_PREPEND = b"comment1=cooking%20MCs;userdata="
STRING_TO_APPEND = b";comment2=%20like%20a%20pound%20of%20bacon"

key = os.urandom(16)
nonce = os.urandom(8)
def encrypt(message):
    cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)
    ct = cipher.encrypt(STRING_TO_PREPEND + message + STRING_TO_APPEND)
    return ct

def find_inj_loc():
    m1 = encrypt(b"")
    m2 = encrypt(b"\x00")
    for i in range(len(m1)):
        if m1[i] != m2[i]:
            return i

def forge():
    loc = find_inj_loc()
    target = b"pig;admin=true"
    attack_message = b"\x00" * len(target)
    m = encrypt(attack_message)
    forged = bytes([m[loc+i]^target[i] for i in range(len(target))])
    return forged

l = find_inj_loc()
t = b"pig;admin=true"
head = encrypt(t)[:l]  
tail = encrypt(t)[l + len(t):]
forged_full = head + forge() + tail

cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

print(cipher.decrypt(forged_full))
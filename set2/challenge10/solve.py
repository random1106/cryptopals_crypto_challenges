from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import numpy as np

def xor(a, b):
    assert len(a) == len(b)
    return bytes([x^y for x, y in zip(a, b)])

def encrypt_CBC(message, key, iv, block_len):
    assert len(key) == block_len
    padded_message = pad(message, block_len)
    n_blocks = len(padded_message) // block_len
    message_block = iv
    encrypted_message = b""
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(n_blocks):
        xored_message = xor(padded_message[i*block_len:(i+1)*block_len], message_block)
        message_block = cipher.encrypt(xored_message)
        encrypted_message += message_block
    return encrypted_message

def decrypt_CBC(message, key, iv, block_len):
    assert len(key) == block_len
    assert len(message) % block_len == 0
    n_blocks = len(message) // block_len
    dmessage_block = iv
    cipher = AES.new(key, AES.MODE_ECB)
    original_message = b""
    for i in range(n_blocks):
        message_block = message[i*block_len:(i+1)*block_len]
        xored_message_block = cipher.decrypt(message_block) 
        original_message_block = xor(xored_message_block, dmessage_block)
        original_message += original_message_block
        dmessage_block = message_block
    return original_message

iv = b"\x00" * 16
block_len = 16
key=b"YELLOW SUBMARINE"
encrypted_message = base64.b64decode(np.loadtxt("https://cryptopals.com/static/challenge-data/10.txt", dtype="str"))
print(unpad(decrypt_CBC(encrypted_message, key, iv, block_len), block_len).decode())
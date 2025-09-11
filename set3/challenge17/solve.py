import base64
import secrets
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

BLOCK_LENGTH = 16
KEY = generate_random_bytes(BLOCK_LENGTH)
IV = generate_random_bytes(BLOCK_LENGTH)

STRINGS_B64 = [b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

STRINGS = [base64.b64decode(s) for s in STRINGS_B64]
STRING_TO_ENCODE = np.random.choice(STRINGS)

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

def encrypt_CBC(message, key=KEY, iv=IV, block_len=BLOCK_LENGTH):
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

def decrypt_CBC(message, key=KEY, iv=IV, block_len=BLOCK_LENGTH):
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

def is_encrypted_message_correct_padding(encrypted_message, key=KEY, iv=IV, block_len=BLOCK_LENGTH):
    padded_message = decrypt_CBC(encrypted_message, key=key, iv=iv, block_len=block_len)
    if not padded_message:
        return False
    if padded_message[-1] > 16 or padded_message[-1] < 1:
        return False
    if len(padded_message) % block_len != 0:
            return False
    for i in range(padded_message[-1]):
        if padded_message[-i-1] != padded_message[-1]:
            return False
            
    return True
    
def attack_padding_oracle(encrypted_message, key=KEY, block_len=BLOCK_LENGTH):
    n_blocks = len(encrypted_message) // block_len
    res = b""
    for block_num in range(n_blocks):
        if block_num == 0:
            previous_block = IV[:]
        else:
            previous_block = encrypted_message[(block_num-1)*block_len:block_num*block_len]

        decrypted_with_xor = b""
        for i in range(1, block_len+1):
            to_append = bytes([c^i for c in decrypted_with_xor])
            for j in range(256):
                # avoid the accident collison with last block which itself is a valid padding
                if block_num == n_blocks - 1 and j == previous_block[-1] and i == 1:
                    continue
                adjusted_block = b"\x00" * (block_len - i) + bytes([j]) + to_append
                if is_encrypted_message_correct_padding(encrypted_message[block_num*block_len:(block_num+1)*block_len], key=key, iv=adjusted_block):
                    ch = bytes([j^i])
                    decrypted_with_xor = ch + decrypted_with_xor
                    break
        res += decrypted_with_xor
    res = [xor(IV, res[block_num * 16:(block_num + 1) * 16]) if block_num == 0 else xor(encrypted_message[(block_num-1)*block_len:block_num*block_len], res[block_num * 16:(block_num + 1) * 16])  for block_num in range(n_blocks)]

    return unpad(b"".join(res), block_len)

encrypted_message = encrypt_CBC(STRING_TO_ENCODE)
decrypted_message = attack_padding_oracle(encrypted_message)

print("original message:", STRING_TO_ENCODE)
print("decrypted message:", decrypted_message)
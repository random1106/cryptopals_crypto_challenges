import secrets
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

def xor(a, b):
    assert len(a) == len(b)
    return bytes([x^y for x, y in zip(a, b)])

def add_random_bytes(message):
    n_front_bytes = np.random.randint(5, 10)
    n_end_bytes = np.random.randint(5, 10)
    bytes_added_to_front = generate_random_bytes(bytes_length=n_front_bytes)
    bytes_added_to_end = generate_random_bytes(bytes_length=n_end_bytes)
    message_with_random_bytes = bytes_added_to_front + message + bytes_added_to_end
    return message_with_random_bytes

def encrypt_ECB(message, key, block_len):
    assert len(key) == block_len
    padded_message = pad(message, block_len)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(padded_message) 
    return encrypted_message

def encrypt_CBC(message, key, block_len, iv):
    assert len(key) == block_len
    padded_message = pad(message, block_len)
    n_blocks = len(padded_message) // block_len
    message_block = iv
    message = b""
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(n_blocks):
        xored_message = xor(padded_message[i*block_len:(i+1)*block_len], message_block)
        message_block = cipher.encrypt(xored_message)
        message += message_block
    return message
    
def encrypt_and_detect(message, block_len, iv):
    message_with_random_bytes = add_random_bytes(message)
    key = generate_random_bytes(BLOCK_LENGTH)
    padded_message = pad(message_with_random_bytes, block_len)
    if RANDOM_NUMBER == 0:
        encrypted_message = encrypt_ECB(padded_message, key, block_len)
    if RANDOM_NUMBER == 1:
        encrypted_message = encrypt_CBC(padded_message, key, block_len, iv)

    if encrypted_message[block_len:2*block_len] == encrypted_message[2*block_len:3*block_len]:
        return "ECB", RANDOM_NUMBER
    else:
        return "CBC", RANDOM_NUMBER

BLOCK_LENGTH = 16
ENCRYPTION_METHODS = ["ECB", "CBC"]
RANDOM_NUMBER = np.random.randint(2)
IV = generate_random_bytes(BLOCK_LENGTH)

test_message = b"a" * 43

for _ in range(1000):
    mode, rn = encrypt_and_detect(test_message, BLOCK_LENGTH, IV)
    assert (mode, rn) in [("ECB", 0), ("CBC", 1)]
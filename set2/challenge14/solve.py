import base64
import secrets
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

BLOCK_LENGTH = 16
RANDOM_NUMBER = np.random.randint(5, 20)
RANDOM_PREDIX = generate_random_bytes(RANDOM_NUMBER)

UNKNOWN_MESSAGE = base64.b64decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
KEY = generate_random_bytes(BLOCK_LENGTH)

def encrypt_ECB(message):
    assert len(KEY) == BLOCK_LENGTH
    padded_message = pad(RANDOM_PREDIX + message + UNKNOWN_MESSAGE, BLOCK_LENGTH)
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(padded_message) 
    return encrypted_message

def find_repeat_start_location():
    message = encrypt_ECB(b"A"*(BLOCK_LENGTH*3))
    for i in range(0, len(message) - 2*BLOCK_LENGTH, 16):
        if message[i:i+BLOCK_LENGTH] == message[i+BLOCK_LENGTH:i+2*BLOCK_LENGTH]:
            return i

def find_input_location():
    loc = find_repeat_start_location()
    start_length = BLOCK_LENGTH * 3
    while start_length > 0:
        message = encrypt_ECB(b"A"*(start_length))
        if message[loc:loc+BLOCK_LENGTH] == message[loc+BLOCK_LENGTH:loc+2*BLOCK_LENGTH]:
            start_length -= 1
        else:
            break
    return start_length

PREFIX_TO_MESSAGE = b"A" * ((find_input_location() +1) % BLOCK_LENGTH)
OFFSET = find_repeat_start_location() // BLOCK_LENGTH

def get_unknown_string_length(prefix=b""):
    unknown_string_length_approx = len(encrypt_ECB(prefix))
    unknown_string_length = unknown_string_length_approx - 1 - find_repeat_start_location()
    for i in range(1, BLOCK_LENGTH):
        unknown_string_length_test = len(encrypt_ECB(prefix + b"A"*i))
        if unknown_string_length_test == unknown_string_length_approx:
            unknown_string_length -= 1
            return unknown_string_length
    return unknown_string_length

def decrypt_unknown_string(prefix=b"", offset=0):
    unknown_string_length = get_unknown_string_length(prefix)
    n_blocks = unknown_string_length // BLOCK_LENGTH 
    buffer_string = b"A" * BLOCK_LENGTH
    unknown_string = b"" 
    for i in range(n_blocks+1):  
        for j in range(BLOCK_LENGTH):
            if i * BLOCK_LENGTH + j >= unknown_string_length:
                break
            message = buffer_string[j+1:]
            original_encrypted_message = encrypt_ECB(prefix+message)
            for k in range(256):
                l_unknown_string = len(unknown_string)
                test_message = message + unknown_string[l_unknown_string-j:] + bytes([k])
                test_encypted_message =  encrypt_ECB(prefix+test_message)
                if test_encypted_message[offset*BLOCK_LENGTH:(offset+1)*BLOCK_LENGTH] == original_encrypted_message[(i+offset)*BLOCK_LENGTH:(i+offset+1)*BLOCK_LENGTH]:
                    unknown_string = unknown_string + bytes([k])
                    break
        buffer_string = unknown_string[-BLOCK_LENGTH:]
    return unknown_string

print(decrypt_unknown_string(prefix=PREFIX_TO_MESSAGE, offset=OFFSET).decode())

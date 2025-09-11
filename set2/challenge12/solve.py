import base64
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

def encrypt_ECB(message):
    assert len(KEY) == BLOCK_LENGTH
    padded_message = pad(message + UNKNOWN_MESSAGE, BLOCK_LENGTH)
    cipher = AES.new(KEY, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(padded_message) 
    return encrypted_message

def detect_block_length():
    bytes_length = 0
    empty_encrpytion_length = len(encrypt_ECB(b""))
    while bytes_length < 100:
        bytes_length += 1
        encryption_length = len(encrypt_ECB(b"a" * bytes_length))
        if encryption_length > empty_encrpytion_length:
            return encryption_length - empty_encrpytion_length

def is_ecb():
    block_len = 16 # smallest block length to start
    encrypted_message = encrypt_ECB(b"A" * 100)
    if encrypted_message[:block_len] == encrypted_message[block_len:2*block_len]:
        return "ECB"
    else:
        return "Not ECB"
    
UNKNOWN_MESSAGE = base64.b64decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
BLOCK_LENGTH = 16
KEY = generate_random_bytes(BLOCK_LENGTH)

# print("block length:", detect_block_length())
# print("encryption method:", is_ecb())

def get_unknown_string_length():
    unknown_string_length = len(encrypt_ECB(b"")) - 1
    for i in range(1, BLOCK_LENGTH):
        unknown_string_length_test = len(encrypt_ECB(b"A" * i))
        if unknown_string_length_test == len(encrypt_ECB(b"")):
            unknown_string_length -= 1
        else:
            return unknown_string_length
    return unknown_string_length
            
def decrypt_unknown_string():
    unknown_string_length = get_unknown_string_length()
    n_blocks = unknown_string_length // BLOCK_LENGTH 
    buffer_string = b"A" * BLOCK_LENGTH
    unknown_string = b"" 
    for i in range(n_blocks+1):  
        for j in range(BLOCK_LENGTH):
            if i * BLOCK_LENGTH + j >= unknown_string_length:
                break
            message = buffer_string[j+1:]
            original_encrypted_message = encrypt_ECB(message)
            for k in range(256):
                l_unknown_string = len(unknown_string)
                test_message = message + unknown_string[l_unknown_string-j:] + bytes([k])
                test_encypted_message =  encrypt_ECB(test_message)
                if test_encypted_message[:BLOCK_LENGTH] == original_encrypted_message[i*BLOCK_LENGTH:(i+1)*BLOCK_LENGTH]:
                    unknown_string = unknown_string + bytes([k])
                    break
        buffer_string = unknown_string[-BLOCK_LENGTH:]
    return unknown_string

print(decrypt_unknown_string().decode())
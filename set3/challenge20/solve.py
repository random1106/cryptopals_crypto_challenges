import base64
from collections import Counter
import secrets
import numpy as np
from Crypto.Cipher import AES

datas = np.loadtxt("https://cryptopals.com/static/challenge-data/20.txt", dtype="str")

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

BLOCK_LENGTH = 16
KEY = generate_random_bytes(BLOCK_LENGTH)

def crypt_CTR(message, key=KEY, block_len=BLOCK_LENGTH):
    message_len = len(message)
    crypted_message = b""
    for i in range((message_len - 1) // block_len + 1):
        num = i
        nonce = b"\x00" * 8
        block_index = num.to_bytes(8, byteorder="little")
        cipher = AES.new(key, AES.MODE_ECB)
        if i < (message_len - 1) // block_len:
            encrypted_block = message[i*block_len:(i+1)*block_len]
        else:
            encrypted_block = message[i*block_len:]
        key_stream = cipher.encrypt(nonce+block_index)
        decrypted_block = bytes([c1^c2 for c1, c2 in zip(encrypted_block, key_stream[:len(encrypted_block)])])
        crypted_message += decrypted_block
    return crypted_message

datas = [base64.b64decode(data) for data in datas]
encrypted_datas = [crypt_CTR(message) for message in datas]

def find_max_size(datas):
    max_size = max(len(data) for data in datas)
    return max_size

max_size = find_max_size(encrypted_datas)

def assign_score(output_string):
    string_score = 0
    freq = [' ', 'e', 't', 'a', 'o', 'i']
    # freq = [' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u']
    for letter in output_string:
        if letter in freq:
            string_score += 1
    return string_score

def find_single_key(message):
    string_score = 0
    key = None
    for k in range(256):
        res = []
        for i in range(0, len(message)):
            res.append(chr(k ^ message[i]))
        if assign_score("".join(res)) > string_score:
            key = k
            string_score = assign_score("".join(res))
    return key

def find_repeated_key(messages, max_size):
    keys = []
    for i in range(max_size):
        col = [message[i] for message in messages if i < len(message)]
        keys.append(find_single_key(bytes(col)))
    return keys

def decrypt_repeated_key_xor(messages, max_size):
    decrypted_messages = []
    keys= find_repeated_key(messages, max_size)
    for message in messages:
        decrypted_message = []
        assert len(message) <= max_size
        for i in range(len(message)):
            decrypted_message.append(message[i] ^ keys[i])
        decrypted_messages.append(bytes(decrypted_message).decode())
    return decrypted_messages        

decrypt_repeated_key_xor(encrypted_datas, max_size)
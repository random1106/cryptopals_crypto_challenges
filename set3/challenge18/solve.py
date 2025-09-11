import base64
from Crypto.Cipher import AES

STRING_TO_DECODE = base64.b64decode(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
KEY = b"YELLOW SUBMARINE"
BLOCK_LENGTH = 16

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

def crypt_CTR(message, key=KEY, block_len=BLOCK_LENGTH):
    crypted_message = b""
    for i in range((len(message) - 1) // block_len + 1):
        num = i
        nonce = b"\x00" * 8
        block_index = num.to_bytes(8, byteorder="little")
        cipher = AES.new(key, AES.MODE_ECB)
        if i < (len(message) - 1) // block_len:
            encrypted_block = message[i*block_len:(i+1)*block_len]
        else:
            encrypted_block = message[i*block_len:]
        key_stream = cipher.encrypt(nonce+block_index)
        decrypted_block = xor(encrypted_block, key_stream[:len(encrypted_block)])
        crypted_message += decrypted_block
    return crypted_message

print(crypt_CTR(STRING_TO_DECODE))
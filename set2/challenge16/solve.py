import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

STRING_TO_PREPEND = b"comment1=cooking%20MCs;userdata="

STRING_TO_APPEND = b";comment2=%20like%20a%20pound%20of%20bacon"

BLOCK_LENGTH = 16
KEY = generate_random_bytes(BLOCK_LENGTH)
IV = generate_random_bytes(BLOCK_LENGTH)

def filter(message):
    res = []
    for i in range(len(message)):
        if message[i:i+1] == b";":
            res.append(b"%3B")
        elif message[i:i+1] == b"=":
            res.append(b"%3D")
        else:
            res.append(message[i:i+1])
    return b"".join(res)

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

# encrypt with padding first
def encrypt_CBC(message, key=KEY, iv=IV, block_len=BLOCK_LENGTH):
    message = filter(message)
    assert len(key) == block_len
    padded_message = pad(STRING_TO_PREPEND + message + STRING_TO_APPEND, block_len)
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

def find_common_block_num(message1, message2):
    start = 0
    while start * BLOCK_LENGTH < min(len(message1), len(message2)):
        if message1[start * BLOCK_LENGTH:(start+1) * BLOCK_LENGTH] == message2[start * BLOCK_LENGTH:(start+1) * BLOCK_LENGTH]:    
             start += 1
        else:
            break
    return start
         
def find_input_start_location():
    n_common = find_common_block_num(encrypt_CBC(b""), encrypt_CBC(b"A"))
    for i in range(1, BLOCK_LENGTH+1):
        n_common_update = find_common_block_num(encrypt_CBC(b"A"*i), encrypt_CBC(b"A"*(i+1)))
        if n_common_update == n_common + 1:
            break
    return n_common * BLOCK_LENGTH + BLOCK_LENGTH - i     

def verify_admin(encrypted_message):
    decrypted_message = decrypt_CBC(encrypted_message)
    if b";admin=true;" in decrypted_message:
        return True
    else:
        return False
    
find_input_start_location()

message1 = encrypt_CBC(b"")[BLOCK_LENGTH:2*BLOCK_LENGTH]
message2 = b";admin=true;" + b"aaaa"
message = bytes([s1^s2 for (s1, s2) in zip(message1, message2)])
encrypted_message = encrypt_CBC(message)[2*BLOCK_LENGTH:3*BLOCK_LENGTH]

crafted_message = b"\x00" * 16 + encrypted_message
print(verify_admin(crafted_message)) 
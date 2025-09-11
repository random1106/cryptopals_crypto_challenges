
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def parse_to_dict(data):
    data_splits = [data_block.split("=") for data_block in data.split("&")]
    encoded_data = {data_split[0]:data_split[1] for data_split in data_splits}
    return encoded_data

def parse_from_dict(message):
    res = []
    for key, value in message.items():
        res.append(f"{key}"+"="+f"{value}")
    return "&".join(res)

# test_data = b"foo=bar&baz=qux&zap=zazzle"
# dict_data = parse_to_dict(test_data.decode())
# back_data = parse_from_dict(dict_data)
# print("The encoded data is", dict_data)
# print("The decoded data is", back_data)

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

def reject_input(data):
    if b"&" in data or b"=" in data:
        return False
    else:
        return True
    
def encode_profile(email):
    assert reject_input(email) 
    parsed_profile = b"email=" + email + b"&uid=10&role=user"
    return parsed_profile
    
def profile_for(email):    
    parsed_profile = encode_profile(email)
    return parse_to_dict(parsed_profile)

def encrypt_ECB(email, key):
    message= encode_profile(email) 
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message, BLOCK_LENGTH))

def decrypt(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), BLOCK_LENGTH)
    return decrypted_message

def find_repeat_start_location(key):
    message = encrypt_ECB(b"A"*BLOCK_LENGTH*3, key)
    for i in range(0, len(message) - 2*BLOCK_LENGTH, 16):
        if message[i:i+BLOCK_LENGTH] == message[i+BLOCK_LENGTH:i+2*BLOCK_LENGTH]:
            return i

def find_input_location(key):
    loc = find_repeat_start_location(key)
    start_length = BLOCK_LENGTH * 3
    while start_length > 0:
        message = encrypt_ECB(b"A"*start_length, key)
        if message[loc:loc+BLOCK_LENGTH] == message[loc+BLOCK_LENGTH:loc+2*BLOCK_LENGTH]:
            start_length -= 1
        else:
            break
    return start_length

BLOCK_LENGTH = 16
KEY = generate_random_bytes(BLOCK_LENGTH)

location_idx = find_input_location(key=KEY)
n_As = location_idx + 1 - BLOCK_LENGTH

MESSAGE_PIECE1 = encrypt_ECB(b"max@gmail.", key=KEY)[:BLOCK_LENGTH] # email=max@gmail. 16 bytes                  
MESSAGE_PIECE2 = encrypt_ECB(b"A"*(n_As) + b"com", key=KEY)[2*BLOCK_LENGTH:3*BLOCK_LENGTH] # com&uid=10&role=
MESSAGE_PIECE3 = encrypt_ECB(b"A"*n_As + b"admin" + b"\x0b"*11, key=KEY)[2*BLOCK_LENGTH:3*BLOCK_LENGTH] # admin 

FORGED_MESSAGE = MESSAGE_PIECE1 + MESSAGE_PIECE2 + MESSAGE_PIECE3
print(decrypt(FORGED_MESSAGE, key=KEY))



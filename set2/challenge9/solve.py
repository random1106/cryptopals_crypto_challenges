def pad(message, block_len):
    pad_value = block_len - (len(message) % block_len) 
    pad_bytes = bytes.fromhex("{:02x}".format(pad_value)) * pad_value
    return message + pad_bytes

message = b"YELLOW SUBMARINE"
print(pad(message, 20))
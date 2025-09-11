class BadPaddingError(Exception):
    pass

def is_correct_padding(padded_message, block_len):
    if not padded_message:
        raise BadPaddingError()
    if len(padded_message) % block_len != 0:
            raise BadPaddingError()
    if padded_message[-1] > 16 or padded_message[-1] < 1:
        raise BadPaddingError()
    
    for i in range(padded_message[-1]):
        if padded_message[-i-1] != padded_message[-1]:
            raise BadPaddingError()    
    return True
    
CORRECT_PADDING = b"ICE ICE BABY\x04\x04\x04\x04"
INCORRECT_PADDING1 = b"ICE ICE BABY\x05\x05\x05\x05"
INCORRECT_PADDING2 = b"ICE ICE BABY\x01\x02\x03\x04"
BLOCK_LENGTH = 16

print(is_correct_padding(CORRECT_PADDING, block_len=BLOCK_LENGTH))

# bad padding
# print(is_correct_padding(INCORRECT_PADDING1, block_len=BLOCK_LENGTH))
# print(is_correct_padding(INCORRECT_PADDING2, block_len=BLOCK_LENGTH))
        
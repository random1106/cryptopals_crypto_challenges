msg1 = "1c0111001f010100061a024b53535009181c"
msg2 = "686974207468652062756c6c277320657965"

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

print(xor(bytes.fromhex(msg1), bytes.fromhex(msg2)))
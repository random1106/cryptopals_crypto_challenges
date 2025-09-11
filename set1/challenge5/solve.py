message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
xor_key = b"ICE"
emsg = bytes([xor_key[i%3]^message[i] for i in range(len(message))])
print(emsg.hex())
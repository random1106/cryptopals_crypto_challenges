from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import numpy as np
import base64

msg = np.loadtxt("https://cryptopals.com/static/challenge-data/7.txt", dtype="str")
msg = base64.b64decode(msg)
key = b"YELLOW SUBMARINE"
cipher = AES.new(key, AES.MODE_ECB)
decrypted_message = unpad(cipher.decrypt(msg), 16)  
print(decrypted_message.decode())

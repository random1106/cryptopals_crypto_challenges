import numpy as np
import base64

msgs = np.loadtxt("https://cryptopals.com/static/challenge-data/8.txt", dtype="str")
msgs = [base64.b64decode(msg) for msg in msgs]

def isrepetitive(message):
    for i in range(len(message) // 16):
        for j in range(i+1, len(message) // 16):
            if message[i*16:i*16+16] == message[j*16:j*16+16]:
                return True
    return False

for i, msg in enumerate(msgs):
    if isrepetitive(msg):
        print(i, msg)
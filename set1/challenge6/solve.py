import base64
import numpy as np
import pandas as pd

def hammingdistance(msg1, msg2):
    assert len(msg1) == len(msg2)
    distance = 0
    for c1, c2 in zip(bytes(msg1), bytes(msg2)):
        distance += str(bin(c1^c2)).count("1")
    return distance    

msg1 = ("this is a test").encode()
msg2 = ("wokka wokka!!!").encode()
# print(hammingdistance(msg1, msg2))

msgs = np.loadtxt("https://cryptopals.com/static/challenge-data/6.txt", dtype="str")
msgs = base64.b64decode(msgs)

def selfHammingdistrance(message, keysize):
    distance1 = hammingdistance(message[:keysize], message[keysize:2*keysize])
    distance2 = hammingdistance(message[keysize:2*keysize], message[2*keysize:3*keysize])
    distance3 = hammingdistance(message[2*keysize:3*keysize], message[3*keysize:4*keysize])
    distance = (distance1 + distance2 + distance3) / 3
    return distance / keysize

keysizetodistance = {}

for keysize in range(2, 41):
    keysizetodistance[keysize] = selfHammingdistrance(message=msgs, keysize=keysize)

# print(pd.Series(keysizetodistance).sort_values().index)

# from print result, select size keysize = 29

def assign_score(output_string):
    score = 0
    freq = b" etaoinshrdlu"
    for letter in output_string:
        if letter in freq:
            score += 1
    return score

def decrypt(message):
    score = 0
    for cipher in range(256):
        cand_msg = bytes([cipher^x for x in message])
        if assign_score(cand_msg) > score:
            score = assign_score(cand_msg)
    result = []
    for cipher in range(256):
        cand_msg = bytes([cipher^x for x in message])
        if assign_score(cand_msg) == score:
            result.append((cand_msg, cipher))
    return result

results = []
ciphers = []
for i in range(29):
    result = decrypt(msgs[i::29])
    assert len(result) == 1
    results.append(result[0][0])
    ciphers.append(result[0][1])

final_msgs = []

for i in range(len(msgs)):
    final_msgs.append(results[i % 29][i // 29])

print(bytes(final_msgs).decode())
print(bytes(ciphers[:29]).decode())
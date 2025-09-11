import numpy as np

def assign_score(cand_msg):
    string_score = 0
    freq = b" etaoinshrdlu"
    for letter in cand_msg:
        if letter in freq:
            string_score += 1
    return string_score

msgs = np.loadtxt("https://cryptopals.com/static/challenge-data/4.txt", dtype='str')
msgs = [bytes.fromhex(msg) for msg in msgs]


score = 0
for msg in msgs:
    for cipher in range(256):
        cand_msg = bytes([cipher^x for x in msg])
        if assign_score(cand_msg) > score:
            score = assign_score(cand_msg)
result = []
for msg in msgs:
    for cipher in range(256):
        cand_msg = bytes([cipher^x for x in msg])
        if assign_score(cand_msg) == score:
            result.append(cand_msg)

print(result)
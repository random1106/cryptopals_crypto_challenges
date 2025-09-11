# this function is borrowed from https://dev.to/wrongbyte/cryptography-basics-breaking-repeated-key-xor-ciphertext-1fm2
def assign_score(cand_msg):
    string_score = 0
    freq = b" etaoinshrdlu"
    for letter in cand_msg:
        if letter in freq:
            string_score += 1
    return string_score

msg = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
msg = bytes.fromhex(msg)

score = 0
final_msg = b""

def decrypt(message):
    score = 0    
    for cipher in range(256):
        cand_msg = bytes([cipher^x for x in msg])
        if assign_score(cand_msg) > score:
            score = assign_score(cand_msg)
    
    result = []
    for cipher in range(256):
        cand_msg = bytes([cipher^x for x in msg])
        if assign_score(cand_msg) == score:
            result.append(cand_msg)

    return result

print(decrypt(msg))

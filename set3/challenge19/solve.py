import base64
from collections import Counter
import secrets
import numpy as np
from Crypto.Cipher import AES

data = b"""SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
""".splitlines()

# Remove any empty strings (e.g., from the first line)
data = [base64.b64decode(line) for line in data if line]

def generate_random_bytes(bytes_length):
    random_bytes = secrets.token_bytes(bytes_length)
    return random_bytes

BLOCK_LENGTH = 16
KEY = generate_random_bytes(BLOCK_LENGTH)

def crypt_CTR(message, key=KEY, block_len=BLOCK_LENGTH):
    message_len = len(message)
    crypted_message = b""
    for i in range((message_len - 1) // block_len + 1):
        num = i
        nonce = b"\x00" * 8
        block_index = num.to_bytes(8, byteorder="little")
        cipher = AES.new(key, AES.MODE_ECB)
        if i < (message_len - 1) // block_len:
            encrypted_block = message[i*block_len:(i+1)*block_len]
        else:
            encrypted_block = message[i*block_len:]
        key_stream = cipher.encrypt(nonce+block_index)
        decrypted_block = bytes([c1^c2 for c1, c2 in zip(encrypted_block, key_stream[:len(encrypted_block)])])
        crypted_message += decrypted_block
    return crypted_message

def assign_score(output_string):
    score = 0
    freq = [' ', "e", "t"]
    for letter in output_string:
        if letter in freq:
            score += 1
    return score

encrypted_data = [crypt_CTR(message) for message in data]
keys = []

for i in range(3*BLOCK_LENGTH):
    letter_list = []
    for line in encrypted_data:
        if i < len(line):
            letter_list.append(line[i])
    best_score = 0
    
    for j in range(256):
        decrypted_letter = [chr(j^letter) for letter in letter_list]
        score = assign_score(decrypted_letter) 
        if score > best_score:
            best_score = score
            k = j

    keys.append(k)

decrypted_message = []

for message in encrypted_data:
    res = []
    for i, key in enumerate(keys):
        if i < len(message):
            res.append(key^(message[i]))
    decrypted_message.append(bytes(res))

# print(decrypted_message)

# adjust the key
#'iehave met them at close *ftdah' -> 'i have met them at close of day'

message = b'he, too, has been changed in his turn.'
for i in range(len(message)):
    keys[i] = encrypted_data[37][i] ^ message[i]

decrypted_message = []

for message in encrypted_data:
    res = []
    for i, key in enumerate(keys):
        if i < len(message):
            res.append(key^(message[i]))
    decrypted_message.append(bytes(res).decode())

print(decrypted_message)
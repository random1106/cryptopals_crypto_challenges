import requests
import time

url = "http://localhost:9000/test"

# params = {
#     "file": "foo",
#     "signature": "46b4ec586117154dacd49d664e5d63fdc88efb51",
# }

def get_time(sig):
    params = {
        "file": "foo",
        "signature": sig,
    }
    start = time.time()
    r = requests.get(url, params)
    return time.time() - start

hmac = []

for _ in range(32):
    gap = []
    print(hmac)
    for i in range(256):
        sig = bytes(hmac + [i] + [0]).hex()
        gap.append((get_time(sig), i))
    hmac.append(sorted(gap)[-1][1])

cracked_sig = bytes(hmac).hex()
print(cracked_sig)

params = {
    "file": "foo",
    "signature": cracked_sig,
}

r = requests.get(url, params)
print(r.status_code)
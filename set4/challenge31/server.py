# server.py
import web
import time
import hmac
import hashlib
from wsgiref.simple_server import make_server

key = b"secret"

def custom_hmac(key, message: bytes):
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha1(key).digest()
    key = key.ljust(block_size, b'\x00')

    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5c) for x in key)

    inner = hashlib.sha1(ipad + message).digest()
    hmac_result = hashlib.sha1(opad + inner).hexdigest()
    return hmac_result

urls = (
    '/test', 'Test'
)

def insecure_compare(a: bytes, b: bytes, delay=0.05):
    min_len = min(len(a), len(b))
    for i in range(min_len):
        time.sleep(delay)
        if a[i] != b[i]:
            return False
    if len(a) != len(b):
        return False
    return True

app = web.application(urls, globals())

class Test:
    def GET(self):
        i = web.input(file=None, signature=None)
        if i.file is None or i.signature is None:
            return web.badrequest("missing file or signature")

        file_bytes = i.file.encode()
        expected_hex = custom_hmac(key, file_bytes)
        provided_hex = i.signature.lower()

        provided_bytes = bytes.fromhex(provided_hex)
        expected_bytes = bytes.fromhex(expected_hex)

        if insecure_compare(expected_bytes, provided_bytes):
            return web.ok("OK")
        else:
            return web.internalerror("Invalid signature")

if __name__ == "__main__":
    print(custom_hmac(key, b"foo"))
    host = "127.0.0.1"   # WSL 下用 0.0.0.0 可以让 Windows 主机通过 localhost 访问
    port = 9000
    wsgi_app = app.wsgifunc()
    httpd = make_server(host, port, wsgi_app)
    print(f"Serving on http://{host}:{port}/ ...")
    httpd.serve_forever()
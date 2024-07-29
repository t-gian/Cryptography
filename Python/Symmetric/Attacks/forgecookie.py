from pwn import *

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import json, base64


server = remote("130.192.5.212",6521)
challenge = server.recvuntil(b">").decode()
print(challenge)
server.sendline(b'admin')
plain_text = server.recvline().strip()
print("plaintext: ",plain_text)
token = server.recvline().decode().strip().split(": ")[1]
print("token:", token)
nonce = token.split(".")[0].encode()
print("nonce: ", nonce)
ciphertext = base64.b64decode(token.split(".")[1].encode())
print("ciphertext: ",ciphertext)
bait = json.dumps({
    "admin": True
}).encode()
key = bytearray()
for c,p in zip(ciphertext,plain_text):
    key.append(c^p)
fool = bytearray()
for k, b in zip(key,bait):
    fool.append(k^b)
fool = base64.b64encode(fool)
print(server.recvuntil(b">").decode())
server.sendline(b'flag')
print(server.recvuntil(b">").decode())
# same keystream, I also have seed -> reverse in order to find mask for json valid
server.sendline(nonce+b'.'+fool)

print(server.recvline())
print(server.recvline())
print(server.recvline().decode())
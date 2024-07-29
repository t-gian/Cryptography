from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import *
aim = b'username=aaaaaaaaaaaaaaaa&admin=true'
bait = b"a"*7
real_shit = pad(b'true',AES.block_size)
print(real_shit)
bait = bait + real_shit + b"a"*9
server = remote("130.192.5.212",6552)
print(server.recvuntil(b'Username: ').decode().strip())
server.sendline(bait)
ct = server.recvline().strip()
print(ct)
real_ct = bytearray(long_to_bytes(int(ct)))
print("real_ct: ", real_ct)
real_real_ct = real_ct[:48] + real_ct[16:32]
print("real_real_ct:", real_real_ct)
challenge = server.recvuntil(b"> ").decode()
print(challenge)
server.sendline(b'flag')
print(server.recvuntil(": ").decode())
server.sendline(str(bytes_to_long(real_real_ct)).encode())
print(server.recvlines(2))
""" challenge = server.recvuntil(b"> ").decode()
print(challenge)
server.sendline(b'flag')
server.recvuntil(": ").decode()
server.sendline()
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

server.sendline(nonce+b'.'+fool)

print(server.recvline())
print(server.recvline())
print(server.recvline().decode()) """
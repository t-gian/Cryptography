import json
import os
import pwn
from Crypto.Cipher import AES
import base64

server = pwn.remote("130.192.5.212", 6551)

true = b'true,'

username = b'{"username": "'
role = b'", "admin": '

pad1 = b'.' * (AES.block_size - len(username))
block2 = true + b' ' * (AES.block_size-len(true))
block3 = b' ' * (AES.block_size - 1) + b'"' + b' ' * (AES.block_size - 1)  # -1 -> to remove the \ put in front of the "
block4 = b'dummy' + b' ' * (AES.block_size - len(b'dummy'))
block5 = b':' + b' ' * (AES.block_size - 1)
pad6 = b'a' * (AES.block_size - len(role))

tosend = pad1 + block2 + block3 + block4 + block5 + pad6

# see what happens on server
js = json.dumps({
    "username": tosend.decode(),
    "admin": False
})
print(js)

#       0                 1               2               3               4               5                6             7
#      0:16             16:32           32:48           48:64           64:80           80:96            96:112       112:128
#       16       |       16      |       16      |       16      |       16      |       16      |        16     |     16 (pad)  |
# {"username": "..true,                          \"               dummy           :               aaaa", "admin": false}

# Hi, please tell me your name! -> provide name
print(server.recvline().decode())
server.sendline(tosend)

# Get the plaintext token
token = server.recvline().decode().strip().split(" ")[-1]
token = base64.b64decode(token)
print(len(token))

# compose token
#        0       |        6      |       1       |       3       |       4       |        3      |        5      |      7+(pad)     |
# {"username": "..aaaa", "admin": true,           "               dummy           "               :               false}
token = token[:16] + token[96:112] + token[16:32] + token[48:64] + token[64:80] + token[48:64] + token[80:96] + token[112:128]
token = base64.b64encode(token).decode()

# skip the menu
for output in server.recvlines(4):
    print(output.decode())
server.sendline(b"flag")

# skip "What is your token"
print(server.recvline().decode())
server.sendline(token.encode())

for output in server.recvlines(3):
    print(output.decode())

server.close()

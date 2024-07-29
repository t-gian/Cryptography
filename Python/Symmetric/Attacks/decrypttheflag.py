from pwn import *
import random
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes

server = remote("130.192.5.212",6561)
challenge = server.recvuntil(b"> ").decode()
print(challenge)
server.sendline(b'1')
print(server.recvline().strip())
encrypted_key = bytes.fromhex(server.recvline().strip().decode())
print(server.recvuntil(b")"))
server.sendline(b'y')
print(server.recvuntil(b"?"))
plaintext_dummy = b'a' *len(encrypted_key)
server.sendline(plaintext_dummy)
ciphertext_dummy = bytes.fromhex(server.recvline().strip().decode())
print(ciphertext_dummy)

key = bytearray()

#get keystream by reversing xor with known plaintext-ciphertext pair.
for c,p in zip(plaintext_dummy, ciphertext_dummy):
    key.append(c^p)
result_string = bytearray()
for c,p in zip(encrypted_key, key):
    result_string.append(c^p)
print("decrypted: ",result_string)
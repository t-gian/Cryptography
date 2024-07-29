from pwn import *

secret = b'mynamesuperadmin'
plaintext = b'AAAAAAAAAAAAAAAA'
server = remote("130.192.5.212",6523)
for message in server.recvlines(5):
    print(message)
    
server.sendline(b"enc")
print(server.recvline().decode())

server.sendline(plaintext.hex().encode())

iv = bytes.fromhex( server.recvline().decode().strip().split(": ")[1] )
print(iv)
cypertext = bytes.fromhex( server.recvline().decode().strip().split(": ")[1] )
print(cypertext)
print(server.recvline().decode())
# plaintext ^ IV = block before encryption -> notice (bbe = baftencbeforexor)
# block before encryption ^ secret = IV' -> needed to flip.
# block before encryption ^ IV' = secret!!!!
# 1. find bbe value 2. find IV' (mask value) to flip (bbe) -> decrypted value = secret
block0 = bytearray()
for i,p in zip(iv,plaintext):
    block0.append(i^p)       #CBC: block0 before encryption = plaintext0 ^ IV
print("block0=",block0)
mask = bytearray()
for s,b in zip (secret,block0):
    mask.append(s^b)       #  mask needed to flip!
print(mask)
""" shit = bytearray()
for s,b in zip(mask,secret):
    shit.append(s^b)
print("block0?:",shit)
for message in server.recvlines(5):
    print(message) """

server.sendline(b"dec")

print(server.recvline().decode())
print("sending cyphertext")
server.sendline(cypertext.hex().encode())

print(server.recvline().decode())

server.sendline(mask.hex().encode())
print("sending tosend")
print(server.recvline().decode())


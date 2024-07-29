import pwn
from Crypto.Util.number import long_to_bytes

server = pwn.remote("130.192.5.212", 6645)

n = int(server.recvline().decode())
c = int(server.recvline().decode())
e = 65537

tosend = (pow(2, e, n) * c) % n

server.sendline(b'd'+str(tosend).encode())

bit = int(server.recvline().decode())
bit = bit // 2

print(long_to_bytes(bit).decode())
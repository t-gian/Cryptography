from pwn import remote
from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes

server = remote("130.192.5.212", 6646)

c = server.recvline(1024).decode()

c = int(c)
e = 65537

server.sendline(b'd' + str(-1).encode())

n1 = int(server.recvline(2000).decode())
n = n1 + 1


to_send = (pow(2, e, n) * c) %n

server.send(b'd' + str(to_send).encode() + b'\n')

x = server.recvline(2000).decode()

x = int(x)
x = x // 2

print(long_to_bytes(x))
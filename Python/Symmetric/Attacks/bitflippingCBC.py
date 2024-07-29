from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HOST=1
PORT=1

if __name__=="__main__":
    """  server=remote(HOST,PORT)
    username=b'gian'
    server.send(username)
    enc_cookie = server.recv(1024)
    edt = bytearray(enc_cookie)
    edt[-1] = 0 """

    #steal cookie
    username=b'giannnnn' #select username long enough so that admin all in 2nd block
    cookie = pad(b'username=' + username + b',admin=0',AES.block_size)
    print(cookie) #how many blocks? -> pad?
    print(cookie[:16], end=' || ') #1st block
    print(cookie[16:]) #we want to flip the value from 0 -> 1 LOOK BLOCK BEFORE!!
    index = cookie.index(b'0') - AES.block_size
    print(index) #24 - block_size -> we need to modify the correspondent byte in the prev block
    mask = ord(b'1') ^ ord(b'0')
    server=remote(HOST,PORT)
    server.send(username)
    enc_cookie = server.recv(1024)
    edt = bytearray(enc_cookie)
    edt[index] = edt[index] ^ mask #bit flip attack
    server.send(edt)
    ans = server.recv(1024)
    print(ans)

    
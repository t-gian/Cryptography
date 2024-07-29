#  nc 130.192.5.212 6544 
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import string
IP="130.192.5.212"
PORT=6544
BLOCK_SIZE = AES.block_size
LEN = 36 + len("CRYPTO24{}")
STOP_BLOCK3 = LEN % BLOCK_SIZE
server = remote(IP, PORT)

for try_len in range(1, 7):
    # loop in order to find the right pad sizes.
    pad1 = try_len
    pad2 = 10 - try_len
    secret = ''
    for i in range(LEN):
        fill_pad1 = b"A" * (BLOCK_SIZE - pad1)
        # pad1 + "AA..." -> first block filled.
        fill_data = b"A" * (BLOCK_SIZE - pad2)
        # "AA..." (data) + pad2 -> second block filled.
        cmp = b"A" * (BLOCK_SIZE - STOP_BLOCK3)
        #compare block
        bait = b"A" * (i + 1)
        # i < BSIZE: "AA..."*(BL-i-1)
        # i >= BSIZE: secret (BLsize-1:---)
        
        #          1st block                  2nd block(check length secret found)                    3rd block (check len)  + flag -> need to compare 1 bit of 2nd block with 3*2 block (flag) 1 bit of it.
        #payload = [padding1 (fill_pad1)] +                 [guess(1) + secret]                  + [bait(A...) +  fill_pad2] + ...cmp ------ -> move flag bit inversely than size
        flag = 0
        for guess in string.printable:
            if i < BLOCK_SIZE - 1:
                send = fill_pad1 + pad((guess + secret).encode(), BLOCK_SIZE) + bait + fill_data + cmp
            else:
                send = fill_pad1 + guess.encode() + secret[:15].encode() + bait + fill_data + cmp
            
            server.recvlines(4)
            server.sendline(b"enc")
            server.sendline(send.hex().encode())
            res = server.recvline().decode().strip()
            ciphertext = bytes.fromhex(res.split("> ")[2])
            if ciphertext[16:32] == ciphertext[96: 112]:
                secret = guess + secret
                print(secret)
                flag = 1
                break
        if flag==0:
            break
    if len(secret) == LEN:
        print(secret)
        break


import pwn
from Crypto.Cipher import AES
import string
import dis

server = pwn.remote("130.192.5.212", 6543)
blocksize = AES.block_size
secret_len = len("CRYPTO24{}") + 36

blocks = (secret_len // blocksize + 1) * blocksize # non dimenticare il pad!
# 48 bytes di padding
# 1 blocco 16 try
# 3 blocchi vuoti 
#il 4 nel quale shifti il flag
#5 in poi c'è il flag
# 1 blocco -> ultimo byte a sinistra minore 16 paddo
# sul 4 blocco -> ti entra un carattere shiftato a sinsitra del flag
# compleot tutto 1 primo blocco
#1 blocco = 4 blocco > 1a parte flag.
#riempti o\1 blocco -> 1 blocco shifti di 1 verso dx 
# da parte già ok, spazio per 1 nuovo carattere 
secret = ''
for _ in range(1,16):
    stupid_padd = _
    for i in range(secret_len):
        stupid_pad = "A" * (blocksize - stupid_padd)
        pad = "0" * (blocks - i - 1)
        if (i < blocksize):
            dummy = "0" * (blocksize - 1 - i)
        else:
            dummy = secret[-(blocksize - 1):]
        for guess in string.printable:
            if i < blocksize:
                message = stupid_pad + dummy + secret + guess + pad
            else:
                message = stupid_pad + dummy + guess + pad
            server.recvlines(4)
            server.sendline(b"enc")
            server.sendline(message.encode().hex().encode())

            out = server.recvline().decode().strip()
            cyphertext = bytes.fromhex(out.split("> ")[2])
            if cyphertext[16:32] == cyphertext[blocks + 16: blocks + 32]:
                secret += guess
                print(secret)
                break
        if len(secret) <1:
            break
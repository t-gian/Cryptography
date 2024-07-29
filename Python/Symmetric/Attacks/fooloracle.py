import pwn
from Crypto.Cipher import AES
import string

server = pwn.remote("130.192.5.212", 6541)
blocksize = AES.block_size
secret_len = len("CRYPTO24{}") + 36
blocks = (secret_len // blocksize + 1) * blocksize # non dimenticare il pad!
# 48 bytes di padding
# 1 blocco 16 try
# 3 blocchi vuoti 
#il 4 nel quale shifti il flag
#5 in poi c'è il flag
# 1 blocco -> ultimo byte a sinistra minore 16 paddo
# sul 4 blocco -> entra un carattere shiftato a sinsitra del flag
# compleot tutto 1 primo blocco
#1 blocco = 4 blocco > 1a parte flag.
#riempti o\1 blocco -> 1 blocco shifti di 1 verso dx 
# da parte già ok, spazio per 1 nuovo carattere 
secret = ''

for i in range(secret_len):
    pad = "0" * (blocks - i - 1)
    if (i < blocksize):
        dummy = "0" * (blocksize - 1 - i)
        print("dummy1:",dummy)
    else:
        dummy = secret[-(blocksize - 1):]
        print("dummy2:",dummy)
    for guess in string.printable:
        if i < blocksize:
            message = dummy + secret + guess + pad
            print("msg1:", message)
        else:
            message = dummy + guess + pad
            print("msg2:", message)
        server.recvlines(4)
        server.sendline(b"enc")
        server.sendline(message.encode().hex().encode())

        out = server.recvline().decode().strip()
        cyphertext = bytes.fromhex(out.split("> ")[2])
        print("cyphertext:", cyphertext)
        if cyphertext[0:16] == cyphertext[blocks: blocks + 16]:
            secret += guess
            print(secret)
            break
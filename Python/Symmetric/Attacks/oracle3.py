from pwn import *
from Crypto.Cipher import AES
import math
HOST = 1
PORT = 1

if __name__ =='__main__':
    """   server = remote(HOST,PORT)
        message = b"A"*10
        server.send(message)
        ciphertext = server.recv(1024)

        server.close()
        print(ciphertext.hex())
        print(len(ciphertext))
    """

    prefix = b'Here is the msg:'
    postfix = b' - and the sec:'

    print(len(prefix))
    print(len(postfix))

    for guess in string.printable:
        message = postfix + guess.encode()
        full_string = prefix + message + postfix + b'?'
        print(full_string)
        for i in range(math.ceil(len(full_string)/AES.block_size)):
            print(full_string[i*16:(i+1)*16])


    for guess in string.printable:
        message = postfix + guess.encode()
        server = remote(HOST, PORT)
        server.send(message)
        ciphertext = server.recv(1024)
        server.close()
        if ciphertext[16:32] == ciphertext[32:48]:
            print("Find 1st char:" + guess)
            break
       
    for guess in string.printable:
        message = postfix[1:] + b'H' + guess.encode() + b'A'*(AES.block_size-1) #padding, able to guess 1st byte in this way, throw away 1 byte from padding so 1st char here
        full_string = prefix + message + postfix + b'??'
        print(full_string)
        for i in range(math.ceil(len(full_string)/AES.block_size)):
            print(full_string[i*16:(i+1)*16])

        #everytime guess new chat, throw away 1 char from postfix, remove as many char from padding as one discovered in secret.
    
    #real shit.
    secret = b''

    for i in range(AES.block_size):
        pad = (AES.block_size - i) * b'A'
        for guess in string.printable:
            message = postfix + secret + guess.encode() + pad
            print(message)
            sever = remote(HOST,PORT)
            server.send(message)
            ciphertext = server.recv(1024)
            server.close()
            if ciphertext[16:32] == ciphertext[48:64]:
                print("Found:" + guess)
                secret+= guess.encode()
                postfix = postfix[1:]
                break

    print(secret)
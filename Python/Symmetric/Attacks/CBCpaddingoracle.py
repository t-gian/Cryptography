# oracle leaking 1 bit -> pad ok, pad ko
from pwn import *

from Crypto.Cipher import AES

HOST = 1
PORT = 1

if __name__=="__main__":
    server = remote(HOST,PORT)
    iv = 0
    ciphertext = 0
    server.send(iv)
    server.send(ciphertext)
    response = server.recv(1024)
    # edt = bytearray(ciphertext)
    # edt[-1] = 0


    print(len(ciphertext)//AES.block_size)
    N = len(ciphertext)//AES.block_size # n blocks
    initial_part = ciphertext[:(N-2)*AES.block_size]
    block_to_modify = bytearray(ciphertext[(N-2)*AES.block_size:(N-1)*AES.block_size])
    last_block = ciphertext[(N-1)*AES.block_size:]

    byte_index = AES.block_size -1
    # modify last byte block to modify
    c15 = block_to_modify[byte_index] #save original
    for c_prime_15 in range(256): # byte
        block_to_modify[byte_index] = c_prime_15
        to_send = initial_part + block_to_modify + last_block
        server = remote(HOST,PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        if response == b'OK':
            print("c_prime_15", str(c_prime_15))
            p_prime_15 = c_prime_15 ^ 1
            p_15 = p_prime_15 ^ c15
            print("p_prime_15=", str(p_prime_15))
            print("p_15",str(p_15))

    p_prime_15 = 191 #result found before.
    c_second_15 = p_prime_15 ^ 2
    block_to_modify[byte_index]=c_second_15
    byte_index -=1
    #block_to_modify[byte_index+1]=c_second_15
    c_14 = block_to_modify[byte_index]
    for c_prime_14 in range(256): # byte
        block_to_modify[byte_index] = c_prime_14
        to_send = initial_part + block_to_modify + last_block
        server = remote(HOST,PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        if response == b'OK':
            print("c_prime_14", str(c_prime_14))
            p_prime_14 = c_prime_14 ^ 2
            p_14 = p_prime_14 ^ c_14
            print("p_prime_14=", str(p_prime_14))
            print("p_14",str(p_14))

# _client.py





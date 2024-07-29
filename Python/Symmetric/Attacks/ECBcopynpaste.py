from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from attacks import profile_for, encode_profile 

HOST = 1
PORT = 1

if __name__=='__main__':
    server_gencookies = remote(HOST,PORT)
    email = b'aaaa@b.com'

    server_gencookies.sendline(email)
    encrypted_cookie = server_gencookies.recv(1024)
    print(encrypted_cookie)

    cookie_info = encode_profile(profile_for(email.decode()))
    print(cookie_info)
    print(cookie_info[0:16])
    print(cookie_info[16:32])

    # 2 block needs to be properly generated finish with role=


    #align at second block the admin stirng with padding -> build another cokkie info
    #chiudi il primo con *10

    padded_admin = b'A'*10 +pad(b'admin', AES.block_size) #-> such that second block only admin and pad"""chiudi il primo""")
    cookie_info = encode_profile(profile_for(email.decode()))
    print(cookie_info[0:16])
    print(cookie_info[16:32].encode())

    server_gencookies.close()

    server_gencookies = remote(HOST,PORT)

    server_gencookies.send(padded_admin)

    encrypted_cookie_2 = server_gencookies.recv(1024)
    server_gencookies.close()
    print(encrypted_cookie_2)

    auth_cookie = encrypted_cookie[0:32] + encrypted_cookie_2[16:32]

    server_test = remote(HOST,PORT)
    server_test.send(auth_cookie)
    answer = server_test.recv(1024)
    print(answer.decode())








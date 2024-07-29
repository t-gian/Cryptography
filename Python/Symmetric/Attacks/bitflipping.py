# introduce modification block n-1 -> XOR feedback in CBC

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

if __name__ == "__main__":
    #stream algo
    plaintext = b'THis is the message to encrypt but the attacker knows there is a specific sequence of number 12345'
    #attacker knows that b'1' is in a specific position

    index = plaintext.index(b'1')

    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext=plaintext)


    #ciphertext, index, b'1' that's what attacker knows

    new_value = b'9'
    new_int = ord(new_value) #ASCII code

    mask = ord(b'1') ^ new_int #transofmrning from 1 to 9 into plaintext

    edt_ciphertext = bytearray(ciphertext) #to modify

    edt_ciphertext[index] = ciphertext[index] ^ mask

    # edt_ciphertext is received by the recipient instead of ciphertext

    cipher_dec = ChaCha20.new(key =key,nonce=nonce)
    decrypted_text = cipher_dec.decrypt(edt_ciphertext)
    print(decrypted_text)

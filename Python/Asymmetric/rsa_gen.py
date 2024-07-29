from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_OAEP
rsa_key = RSA.generate(1024)

print(rsa_key.exportKey(format='PEM',pkcs=8))

f = open('myprivatekey.pem','wb')

f.write(rsa_key.exportKey(format='PEM',pkcs=8, passphrase='loggpasssecure'))
f.close()


print(rsa_key.n)
print(rsa_key.e)
print(rsa_key.d)
print(rsa_key.p)
print(rsa_key.q)

recovered_key = RSA.construct((rsa_key.n, rsa_key.e, rsa_key.d,rsa_key.p, rsa_key.q), consistency_check=True)

public_rsa_key = rsa_key.public_key()

print(public_rsa_key.exportKey())

###############



message = b'This is the message to sign'

h = SHA256.new(message)
signature = pss.new(rsa_key).sign(h)

print(signature)


############### verifiy at verifier


hv = SHA256.new(message)

verifier = pss.new(public_rsa_key)
try:
    verifier.verify(hv,signature=signature)
    print("sig is okay")
except (ValueError, TypeError):
    print("sig is invalid")

##############################




message = b'This is the message to encrypt'
cipher_pub = PKCS1_OAEP.new(public_rsa_key)
ciphertext = cipher_pub.encrypt(message=message)


cipher_priv = PKCS1_OAEP.new(rsa_key)

message_dec = cipher_priv.decrypt(ciphertext)
print(message_dec.decode())





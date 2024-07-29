from Crypto.Util.number import getPrime

n_length = 1024

p1 = getPrime(n_length) #generation prime number
p2 = getPrime(n_length)

n = p1*p2 #modulus

phi = (p1-1)*(p2-1) 


#define public exponent
 
e = 65537
#find coprime
from math import gcd
g = gcd(e,phi)
if g!=1:
    raise ValueError

d = pow(e, -1, phi) #inverse of e modulus phi.

public_rsa_key = (e,n)
private_rsa_key = (d,n)

#encryption

msg = b'this is the message to encrypt'

msg_int = int.from_bytes(msg,byteorder='big') #bigEndian

if msg_int > n-1:
    raise ValueError

C = pow(msg_int, e, n) #ciphertext

decryption = pow(C,d,n) #private exponent

msg_dec = decryption.to_bytes(n_length,byteorder='big')
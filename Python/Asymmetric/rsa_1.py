from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes
p = 16785115384266113939
q = 18298266505798310279
n = p*q

e = 65537
phi = (p-1) * (q - 1)

d = pow(e, -1, phi)
c = 264966476759035445244404927418681913397

m = pow(c, d, n)

f = long_to_bytes(m)
print(f)
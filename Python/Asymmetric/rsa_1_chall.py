from Crypto.Util.number import bytes_to_long, getPrime
#from secret import flag

p, q = getPrime(64), getPrime(64)
n = p*q
e = 65537
print(n)
#m = bytes_to_long(flag)
#print(pow(m,e,n))

#180210299477107234107018310851575181787
#27280721977455203409121284566485400046

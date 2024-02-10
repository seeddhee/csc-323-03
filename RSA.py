from math import gcd
import random
from Crypto.Util import number

e=65537


def computeGCD(x, y):
    while(y):
       x, y = y, x % y
    return abs(x)
 
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

# Implement multiplacation inverse modulus
def multiplicative_inverse_modulo(number, modulus):
    gcd, x, _ = extended_gcd(number, modulus)
    
    if gcd != 1:
        raise ValueError(f"The multiplicative inverse does not exist for {number} modulo {modulus}.")
    
    return x % modulus

#Implement modular exponentiaition
def power(x, y, p) :
	res = 1	
	x = x % p 
	
	if (x == 0) :
		return 0

	while (y > 0) :

		if ((y & 1) == 1) :
			res = (res * x) % p

		y = y >> 1	
		x = (x * x) % p
		
	return res

#Generating 2048 bit p and q

p = number.getPrime(2048)
q = number.getPrime(2048)
n = p * q
t = (p-1) * (q-1)

alpha = computeGCD(t,e)

d = multiplicative_inverse_modulo(e , t)

PU = [e , n]
PR = [d , n]

#encryption

#plaintext = 88

cipher = power(88 , e , n)

decrypted = power(cipher , d , n)

# Observation :
# =>  Time consuming
print(decrypted) 

#an active attacker can change the meaning of the plaintext message by performing an operation on the respective ciphertext. 

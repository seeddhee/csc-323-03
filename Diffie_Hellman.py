import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import re

#prime number
q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",16)

#primitive root of q
a = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

# Private keys (<q)
Xa = q-1
Xb = q-2


def pkcs_padding(data, block_size):
    data = data.encode('utf-8')  #need to encode string to bytes
    padding_size = block_size - len(data) % block_size
    padding = bytes([padding_size] * padding_size)
    return data + padding


def pkcs_unpadding(padded_data):
    padding_size = padded_data[-1]
    unpadded_data = padded_data[:-padding_size]
    return unpadded_data

def xor_blocks(block, previous_block):
    return bytes(bit1 ^ bit2 for bit1, bit2 in zip(block, previous_block))

def encrypt_cbc(data, key, iv):
    padding = pkcs_padding(data, 16)
    previous_block = iv

    encrypted_content = b""
    cipher = AES.new(key, AES.MODE_ECB)

    for i in range(0, len(padding), 16):
        block = padding[i:i+16]
        xor_block = xor_blocks(block, previous_block)
        encrypted_block = cipher.encrypt(xor_block)
        encrypted_content += encrypted_block
        previous_block = encrypted_block

    return encrypted_content

def verify(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the ciphertext
    decrypted_data = pkcs_unpadding(cipher.decrypt(ciphertext))
    decoded_data = decrypted_data.decode('utf-8')
    print(decoded_data)

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
	

#Public Keys (Visible)
Ya = power(a, Xa, q)
Yb = power(a, Xb, q)

#Shared secret (same)
s1 = power(Yb , Xa , q) #Alice generates it with Bobs public key and her private key
s2 = power(Ya , Xb , q)


sha256_hash_1 = hashlib.sha256()
sha256_hash_2 = hashlib.sha256()

# Convert the integer to bytes
s1_bytes = str(s1).encode('utf-8')
s2_bytes = str(s2).encode('utf-8')


sha256_hash_1.update(s1_bytes)
sha256_hash_2.update(s2_bytes)

k1= sha256_hash_1.hexdigest()[:32]
k2= sha256_hash_2.hexdigest()[:32]

k1 = bytes.fromhex(k1)
k2 = bytes.fromhex(k2)


iv = get_random_bytes(16)

c0 = encrypt_cbc("Hi Bob!", k1 , iv)
c1 = encrypt_cbc("Hi Alice!", k2 , iv)


# verify(c0,k1,iv)
# verify(c1,k1,iv)

#Man in the middle attack

#Frank is impersonating Alice and Bob and providing their public keys as q

#Shared secret (same)
s1 = power(q , Xa , q) #Alice generates it with "Frank's" public key and her private key
s2 = power(q , Xb , q)

sha256_hash_1 = hashlib.sha256()
sha256_hash_2 = hashlib.sha256()

# Convert the integer to bytes
s1_bytes = str(s1).encode('utf-8')
s2_bytes = str(s2).encode('utf-8')

sha256_hash_1.update(s1_bytes)
sha256_hash_2.update(s2_bytes)

k1= sha256_hash_1.hexdigest()[:32]
k2= sha256_hash_2.hexdigest()[:32]

k1 = bytes.fromhex(k1)
k2 = bytes.fromhex(k2)


iv = get_random_bytes(16)

c0 = encrypt_cbc("Hi Bob!", k1 , iv)
c1 = encrypt_cbc("Hi Alice!", k2 , iv)


# verify(c0,k1,iv)
# verify(c1,k1,iv)




#Frank is impersonating Alice and Bob and providing their public keys as q

#Shared secret (same)
s1 = power(1 , Xa , q) #Alice generates it with "Frank's" public key and her private key
s2 = power(1 , Xb , q)



sha256_hash_1 = hashlib.sha256()
sha256_hash_2 = hashlib.sha256()


# Convert the integer to bytes
s1_bytes = str(s1).encode('utf-8')
s2_bytes = str(s2).encode('utf-8')

#as a is 1 the shared secret will always be 1 so mallory will always have access to the key 
#unsure about the decryption because cbc requires iv and how will she predict that

sha256_hash_1.update(s1_bytes)
sha256_hash_2.update(s2_bytes)

k1= sha256_hash_1.hexdigest()[:32]
k2= sha256_hash_2.hexdigest()[:32]

k1 = bytes.fromhex(k1)
k2 = bytes.fromhex(k2)


iv = get_random_bytes(16)

c0 = encrypt_cbc("Hi Bob!", k1 , iv)
c1 = encrypt_cbc("Hi Alice!", k2 , iv)


verify(c0,k1,iv)
verify(c1,k1,iv)


# 1 % anything is 1
# a = q modulus is always 0
# a = q-1 the result is always a or 1

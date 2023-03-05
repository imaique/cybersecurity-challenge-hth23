import rsa

# Use at least 2048 bit keys nowadays, see e.g. https://www.keylength.com/en/4/
publicKey, privateKey = rsa.newkeys(2048) 

# Export public key in PKCS#1 format, PEM encoded 
publicKeyPkcs1PEM = publicKey.save_pkcs1().decode('utf8') 
# Export private key in PKCS#1 format, PEM encoded 
privateKeyPkcs1PEM = privateKey.save_pkcs1().decode('utf8') 

f = open('./keys/public.txt', 'w')
f.write(publicKeyPkcs1PEM)

f = open('./keys/private.txt', 'w')
f.write(privateKeyPkcs1PEM)


f = open('./keys/public.txt')


# Import public key in PKCS#1 format, PEM encoded 
publicKeyReloaded = rsa.PublicKey.load_pkcs1(f.read().encode('utf8')) 
# Import private key in PKCS#1 format, PEM encoded 
f = open('./keys/private.txt')
privateKeyReloaded = rsa.PrivateKey.load_pkcs1(privateKeyPkcs1PEM.encode('utf8')) 

plaintext = "vinay kumar shukla".encode('utf8')
print("Plaintext: ", plaintext)

ciphertext = rsa.encrypt(plaintext, publicKeyReloaded)
print("Ciphertext: ", ciphertext)
 
decryptedMessage = rsa.decrypt(ciphertext, privateKeyReloaded)
print("Decrypted message: ", decryptedMessage)

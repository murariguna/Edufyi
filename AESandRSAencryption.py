from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def encrypt_file(input_file, output_file, rsa_public_key_file):
    aes_key = get_random_bytes(16)

    with open(rsa_public_key_file, 'rb') as key_file:
        rsa_public_key = RSA.import_key(key_file.read())

    rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    with open(input_file, 'rb') as file:
        file_data = file.read()
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)

    with open(output_file, 'wb') as file:
        file.write(encrypted_aes_key)
        file.write(aes_cipher.nonce)
        file.write(tag)
        file.write(ciphertext)

def decrypt_file(input_file, output_file, rsa_private_key_file):
    with open(rsa_private_key_file, 'rb') as key_file:
        rsa_private_key = RSA.import_key(key_file.read())
        
    with open(input_file, 'rb') as file:
        encrypted_aes_key = file.read(256)
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()
    rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    file_data = aes_cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_file, 'wb') as file:
        file.write(file_data)

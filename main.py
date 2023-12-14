from Crypto.Random import get_random_bytes
from enc_dec.symmetric import Symmetric
from base64 import b64encode, b64decode
import binascii

data = b'secret data'
# Bkey = get_random_bytes(16)  # random key
# hexaKey = binascii.hexlify(Bkey).decode('utf-8')
# outKeyFile = open('keys/secKey.txt', "w")
# outKeyFile.write(hexaKey)
# print(hexaKey)
aes_handler = Symmetric('keys/secKey.txt')

# Encrypt
encrypted_data = aes_handler.aes_encrypt(data)
print("Encrypted Data:", binascii.hexlify(encrypted_data).decode('utf-8'))

# Decrypt
aes_handler.aes_decrypt(encrypted_data)

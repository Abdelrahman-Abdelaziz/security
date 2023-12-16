from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
from Crypto.Random import get_random_bytes

# generate 16 bytes shared key 
def genSymKey():
    Bkey = get_random_bytes(16)                         # random key 
    hexaKey = binascii.hexlify(Bkey).decode('utf-8')    #from bytes to hexadecimal
    
    outKeyFile = open('keys/symKey.txt', "w")           #save key to file
    outKeyFile.write(hexaKey)
    
    print(hexaKey)
    
def aes_encrypt(data, key):
    iv = b'This is an IV456'
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return ct_bytes

def aes_decrypt(cipherText, key):
    iv = b'This is an IV456'
    
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        plainText = unpad(cipher.decrypt(cipherText), AES.block_size)
        return plainText
    except (ValueError, KeyError):
        print("Incorrect decryption")
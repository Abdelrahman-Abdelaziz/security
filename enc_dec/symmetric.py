from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

class Symmetric:
    def __init__(self, keyPath):
        key_file = open(keyPath, "r")
        Bkey = key_file.read()
        self.key = bytes.fromhex(Bkey)
        # self.key = keyPath
        self.iv = b'This is an IV456'
        
    def genSharedKey(self, keyPath):
        pass
    
    def aes_encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return ct_bytes
    
    def aes_decrypt(self, cipherText):
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            pt = unpad(cipher.decrypt(cipherText), AES.block_size)
            return pt.decode('utf-8')
        except (ValueError, KeyError):
            print("Incorrect decryption")
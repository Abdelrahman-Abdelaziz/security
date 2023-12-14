from Crypto.Random import get_random_bytes
from enc_dec.symmetric import Symmetric
from base64 import b64encode, b64decode
import binascii

def are_files_equal(file1_path, file2_path):
    try:
        with open(file1_path, 'rb') as file1, open(file2_path, 'rb') as file2:
            content1 = file1.read()
            content2 = file2.read()

            # Compare the content
            return content1 == content2

    except FileNotFoundError:
        print("One or both files not found.")
        return False

def main():
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
    dec_data = aes_handler.aes_decrypt(encrypted_data)
    
    if data.decode('utf-8') == dec_data:
        print('correct')
    else:
        print('incorrect')

if __name__ == "__main__":
    main()



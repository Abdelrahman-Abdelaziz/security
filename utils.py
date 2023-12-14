from base64 import b64encode, b64decode
import binascii
from Crypto.Random import get_random_bytes

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
    
# -----------------------------------------
# -------- gen & save symmetric key -------
# -----------------------------------------
def genSymKey():
    Bkey = get_random_bytes(16)                         # random key
    hexaKey = binascii.hexlify(Bkey).decode('utf-8')    #from bytes to hexadecimal
    outKeyFile = open('keys/symKey.txt', "w")           #save key to file
    outKeyFile.write(hexaKey)
    print(hexaKey)
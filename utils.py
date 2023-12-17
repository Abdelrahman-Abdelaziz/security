from base64 import b64encode, b64decode
import binascii
from Crypto.Random import get_random_bytes
import os

def are_files_equal(file1_path, file2_path):
    try:
        with open(file1_path, 'rb') as file1, open(file2_path, 'rb') as file2:
            content1 = file1.read()
            content2 = file2.read()

            # Compare the content
            if (content1 == content2):
                return "The Two Files Are Identical."
            else:
                return "The Two Files Are Different."

    except FileNotFoundError:
        return "One or both files not found."


def save_key_to_file(byteKey, keyFilePath):
    # Extract the directory and filename from the given file path
    dirname = os.path.dirname(keyFilePath)

    # Check if the directory exists, create it if not
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    with open(keyFilePath, 'w') as f:
        hexKey = binascii.hexlify(byteKey).decode('utf-8')      #convert output to hexadecimal
        f.write(hexKey)

def load_key_from_file(keyFilePath):
    with open(keyFilePath, "r") as key_file:
        hexKey = key_file.read()
    byteKey = bytes.fromhex(hexKey)     #convert from hex to byte
    return byteKey

def load_data_from_file(filePath):
    with open(filePath, 'rb') as dataFile:
        data = dataFile.read()
    return data

def save_data_to_file(data, filePath):
    # Extract the directory and filename from the given file path
    dirname = os.path.dirname(filePath)

    # Check if the directory exists, create it if not
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    with open(filePath, 'wb') as outputFile:
        outputFile.write(data)
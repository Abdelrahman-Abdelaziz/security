from base64 import b64encode, b64decode
import binascii
from Crypto.Random import get_random_bytes
import os
import re
from datetime import datetime



def are_files_equal(file1_path, file2_path):
    try:
        with open(file1_path, 'rb') as file1, open(file2_path, 'rb') as file2:
            content1 = file1.read()
            content2 = file2.read()

            # Compare the content
            if (content1 == content2):
                return True
            else:
                return False

    except FileNotFoundError:
        return "One or both files not found."


def save_key_to_file(byteKey, keyFilePath):
    # Extract the directory and filename from the given file path
    dirname, filename = os.path.split(keyFilePath)
    
    # Check if the directory exists, create it if not
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    # Add date and time to the filename
    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_filename = f"{current_datetime}_{filename}"
    new_filepath = os.path.join(dirname, new_filename)

    with open(new_filepath, 'w') as f:
        hexKey = binascii.hexlify(byteKey).decode('utf-8')  # convert output to hexadecimal
        f.write(hexKey)
    return new_filename

def load_key_from_file(keyFilePath):
    with open(keyFilePath, "r") as key_file:
        key_data = key_file.read()
    if not is_hexadecimal(key_data.strip()):
        return None
    byteKey = bytes(int(key_data[i:i+2], 16) for i in range(0, len(key_data), 2))
    return byteKey

def load_data_from_file(filePath):
    with open(filePath, 'rb') as dataFile:
        data = dataFile.read()
    return data

def save_data_to_file(data, filePath):
    # Extract the directory and filename from the given file path
    dirname, filename = os.path.split(filePath)

    # Check if the directory exists, create it if not
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    # Add date and time to the filename
    current_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_filename = f"{current_datetime}_{filename}"
    new_filepath = os.path.join(dirname, new_filename)

    with open(new_filepath, 'wb') as outputFile:
        outputFile.write(data)
    return new_filename

def is_hexadecimal(data):
    # Use a regular expression to check if the string consists of valid hexadecimal characters
    return bool(re.match(r'^[0-9a-fA-F]+$', data))
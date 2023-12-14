from Crypto.Hash import SHA256
import os

def hash_file(file_path):
    try:
        # Open the file for binary reading
        with open(file_path, 'rb') as file:
            # Initialize the SHA-256 hash object
            h = SHA256.new()

            # Read the file in chunks and update the hash
            chunk_size = 8192  # You can adjust this based on your needs
            while chunk := file.read(chunk_size):
                h.update(chunk)

            # Return the hexadecimal digest of the hash
            h.digest()
            print(h.digest_size)
            return h
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error: {e}")

def hash_data(input_data):
    try:
        # If input_data is not a file path, treat it as raw data
        h = SHA256.new()
        h.update(input_data.encode())  # Assuming input_data is a string, encode it to bytes
        return h.hexdigest()
    except Exception as e:
        print(f"Error: {e}")

# Hashing a file
file_path = './test.txt'
hashed_result_file = hash_file(file_path)
print(f"SHA-256 hash of '{file_path}': {hashed_result_file}")

# Hashing a string
input_data = 'this is a test'
hashed_result_data = hash_data(input_data)
print(f"SHA-256 hash of data: {hashed_result_data}")

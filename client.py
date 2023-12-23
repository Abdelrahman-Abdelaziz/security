import socket
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from enc_dec.symmetric import *
from enc_dec.asymmetric import *
from base64 import b64encode, b64decode
import binascii
from sign_verify import *
from utils import *
import sys
from part3 import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def client():
    host = '127.0.0.1'  # localhost
    port = 8080

    # Generate RSA key pair for the client
    client_private_key, client_public_key = generate_RSA_key_pair()

    # Setup client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")

    # Perform handshake and get shared key
    shared_key, server_public_key = perform_client_handshake(client_socket, client_private_key, client_public_key)

    # Secure Communication Loop
    while True:
        # Take input from the user
        message_to_server = get_user_input()

        hashed_message = hash_message(message_to_server)
        encrypted_hash = encrypt_hash_with_private_key(client_private_key, hashed_message)

        # Step 4: Append the encrypted hash to the original message
        combined_message = message_to_server + encrypted_hash
        
        enc_combined_msg = aes_encrypt(combined_message, shared_key)

        # Send the signed and encrypted message to the server
        client_socket.sendall(enc_combined_msg)

        # Receive the server's response
        signed_response = receive_data(client_socket)

        # Verify the signature using the server's public RSA key
        decrypted_combined_message = aes_decrypt(signed_response, shared_key)
        
        if decrypted_combined_message is not None and len(decrypted_combined_message) >= 256:
            decrypted_message = decrypted_combined_message[:-256]  # Remove the encrypted hash
            decrypted_hash = decrypted_combined_message[-256:]     # Extract the encrypted hash
        else:
            decrypted_message = b'Unable to decrypt message'
            decrypted_hash = b'error with hash'
        
        hashed_message = hash_message(decrypted_message)

        # Verify the hash
        is_verified = verify_with_public_key(server_public_key, decrypted_hash, hashed_message)
        
        if is_verified:
            # Decrypt the response using AES
            print(f"Server response: {decrypted_message}")
        else:
            print("Received unverified response from server.")
            break

    # Close the connection with the server
    client_socket.close()
    print("Connection closed")

def perform_client_handshake(client_socket, client_private_key, client_public_key):
    # Step 1: Client generates RSA key pair
    client_socket.sendall(client_public_key)

    # Step 3: Client receives the server's public key
    server_public_key_bytes = receive_data(client_socket)

    # Step 5: Client receives the encrypted shared AES key from the server
    encrypted_shared_key = receive_data(client_socket)

    # Step 6: Client decrypts the shared AES key using its private key
    decrypted_shared_key = rsa_decrypt(encrypted_shared_key, client_private_key)

    return decrypted_shared_key, server_public_key_bytes

def receive_data(socket):
    data = b""
    while True:
        chunk = socket.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(chunk) < 1024:
            break  # Break the loop if we received less data than the buffer size, indicating the end of transmission
    return data

def get_user_input():
    user_input = input("Enter 'text' to input a message or 'file' to input a file path: ").lower()
    if user_input == 'text':
        return input("Enter your message to the server: ").encode('utf-8')
    elif user_input == 'file':
        file_path = input("Enter the path to the file: ")
        try:
            with open(file_path, 'rb') as file:
                return file.read()
        except FileNotFoundError:
            print(f"File not found at {file_path}. Please try again.")
            return get_user_input()
    else:
        print("Invalid input. Please enter 'text' or 'file'.")
        return get_user_input()

if __name__ == "__main__":
    client()

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

def server():
    host = '127.0.0.1'  # localhost
    port = 8080

    # Generate RSA key pair for the server
    server_private_key, server_public_key = generate_RSA_key_pair()

    # Setup server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    while True:
        # Accept a connection from a client
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        # Perform handshake and get shared key
        shared_key, client_public_key = perform_server_handshake(client_socket, server_private_key, server_public_key)

        # Secure Communication Loop
        while True:
            # Receive encrypted message from the client
            encrypted_message = receive_data(client_socket)

            # Decrypt the message using AES
            decrypted_combined_message = aes_decrypt(encrypted_message, shared_key)
            
            if decrypted_combined_message is not None and len(decrypted_combined_message) >= 256:
                decrypted_message = decrypted_combined_message[:-256]  # Remove the encrypted hash
                decrypted_hash = decrypted_combined_message[-256:]     # Extract the encrypted hash
            else:
                decrypted_message = b'Unable to decrypt message'
                decrypted_hash = b'error with hash'
            
            hashed_message = hash_message(decrypted_message)

            # Verify the signature using the client's public RSA key
            is_verified = verify_with_public_key(client_public_key, decrypted_hash, hashed_message)

            if is_verified:
                print(f"Received message from client: {decrypted_message}")
                
                # Prepare response
                response_message = b"Server received your message."
                
                # Step 3: Calculate hash and encrypt with private key
                hashed_message = hash_message(response_message)
                encrypted_hash = encrypt_hash_with_private_key(server_private_key, hashed_message)
                
                 # Step 4: Append the encrypted hash to the original message
                combined_message = response_message + encrypted_hash

                # Encrypt the response using AES
                encrypted_response = aes_encrypt(combined_message, shared_key)

                # Send the signed and encrypted response to the client
                client_socket.sendall(encrypted_response)
            else:
                print("Received unverified message from client.")
                break

        # Close the connection with the client
        client_socket.close()
        print("Connection closed")

def perform_server_handshake(client_socket, server_private_key, server_public_key):
    # Step 2: Server sends its public key to the client
    client_socket.sendall(server_public_key)

    # Step 3: Server receives the client's public key
    client_public_key_bytes = receive_data(client_socket)

    # Step 4: Server generates shared AES key
    shared_key = get_random_bytes(16)
    
    # Step 5: Server encrypts the shared AES key with the client's public key
    encrypted_shared_key = rsa_encrypt(shared_key, client_public_key_bytes)

    # Step 6: Server sends the encrypted shared AES key to the client
    client_socket.sendall(encrypted_shared_key)

    return shared_key, client_public_key_bytes

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

if __name__ == "__main__":
    server()

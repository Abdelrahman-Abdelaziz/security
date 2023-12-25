import socket
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from enc_dec.symmetric import *
from enc_dec.asymmetric import *
from base64 import b64encode, b64decode
from sign_verify import *
from utils import *
import sys
from part3 import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("Chat Client")

        # GUI components
        self.message_log = scrolledtext.ScrolledText(master, height=15, width=60)
        self.message_log.pack(padx=10, pady=10)

        self.input_entry = tk.Entry(master, width=50)
        self.input_entry.pack(padx=10, pady=10)

        send_button = tk.Button(master, text="Send", command=self.send_message)
        send_button.pack(pady=10)

        # Initialize client
        self.init_client()

    def init_client(self):
        self.host = '127.0.0.1'  # localhost
        self.port = 8080

        # Generate RSA key pair for the client
        self.client_private_key, self.client_public_key = generate_RSA_key_pair()

        # Setup client socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")

        # Perform handshake and get shared key
        self.shared_key, self.server_public_key = self.perform_client_handshake()

        # Start receiving messages in a separate thread
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    def perform_client_handshake(self):
        # Client generates RSA key pair
        self.client_socket.sendall(self.client_public_key)

        # Client receives the server's public key
        server_public_key_bytes = self.receive_data(self.client_socket)

        # Client receives the encrypted shared AES key from the server
        encrypted_shared_key = self.receive_data(self.client_socket)

        # Client decrypts the shared AES key using its private key
        decrypted_shared_key = rsa_decrypt(encrypted_shared_key, self.client_private_key)

        return decrypted_shared_key, server_public_key_bytes

    def send_message(self):
        # Take input from the user
        message_or_filepath = self.input_entry.get()

        if message_or_filepath:
            if os.path.exists(message_or_filepath):  # Check if the input is a file path
                self.send_file(message_or_filepath)
            else:
                self.send_text_message(message_or_filepath)

            # Clear input entry
            self.input_entry.delete(0, tk.END)

    def send_text_message(self, message):
        # This method sends a text message as before
        hashed_message = hash_message(message.encode('utf-8'))
        encrypted_hash = encrypt_hash_with_private_key(self.client_private_key, hashed_message)
        combined_message = b'text' + message.encode('utf-8') + encrypted_hash
        enc_combined_msg = aes_encrypt(combined_message, self.shared_key)
        self.client_socket.sendall(enc_combined_msg)

    def send_file(self, filepath):
        try:
            # Read the file as binary
            with open(filepath, 'rb') as file:
                file_data = file.read()

            subString = filepath.split(".")
            extension = subString[1] 
            while (len(extension) < 10):
                extension += '0'
        
            hashed_message = hash_message(file_data)
            encrypted_hash = encrypt_hash_with_private_key(self.client_private_key, hashed_message)
            combined_message = b'file' + extension.encode('utf-8') + file_data + encrypted_hash
            enc_combined_msg = aes_encrypt(combined_message, self.shared_key)
            self.client_socket.sendall(enc_combined_msg)

        except Exception as e:
            print(f"Error sending file: {e}")

    def receive_messages(self):
        try:
            while True:
                # Receive the server's response
                signed_response = self.receive_data(self.client_socket)

                # aes decrypt message using shared key
                decrypted_combined_message = aes_decrypt(signed_response, self.shared_key)

                if decrypted_combined_message is not None and len(decrypted_combined_message) >= 256:
                    decrypted_message = decrypted_combined_message[:-256]  # Remove the encrypted hash
                    decrypted_hash = decrypted_combined_message[-256:]     # Extract the encrypted hash
                else:
                    decrypted_message = b'Unable to decrypt message'
                    decrypted_hash = b'error with hash'

                hashed_message = hash_message(decrypted_message)

                # Verify the hash
                is_verified = verify_with_public_key(self.server_public_key, decrypted_hash, hashed_message)

                if is_verified:
                    self.message_log.insert(tk.END, f"Server: {decrypted_message.decode('utf-8')}\n")
                else:
                    messagebox.showwarning("Verification Error", "Received unverified response from server.")

        except Exception as e:
            print(e)
            
    def receive_data(self, socket):
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
    root = tk.Tk()
    client_app = ChatClient(root)
    root.mainloop()

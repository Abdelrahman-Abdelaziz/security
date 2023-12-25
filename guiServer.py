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
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime


class ServerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Server")

        self.received_messages_text = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, width=60, height=15, state='disabled')
        self.received_messages_text.pack(padx=10, pady=20)

        self.start_server()

    def start_server(self):
        threading.Thread(target=self.server_thread).start()

    def server_thread(self):
        host = '127.0.0.1'  # localhost
        port = 8080
        
        server_private_key, server_public_key = generate_RSA_key_pair()

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        self.append_message(f"Server listening on {host}:{port}")

        while True:
            client_socket, client_address = server_socket.accept()
            self.append_message(f"Connection from {client_address}")

            shared_key, client_public_key = self.perform_server_handshake(client_socket, server_public_key)

            while True:
                encrypted_message = self.receive_data(client_socket)

                decrypted_combined_message = aes_decrypt(encrypted_message, shared_key)

                if decrypted_combined_message is not None and len(decrypted_combined_message) >= 256:
                    data_type = decrypted_combined_message[:4]
                    
                    if (data_type == b'text'):
                        decrypted_message = decrypted_combined_message[4:-256]
                        decrypted_hash = decrypted_combined_message[-256:]
                        
                    elif (data_type == b'file'):
                        ext = decrypted_combined_message[4:14].decode('utf-8')
                        while ('0' in ext):
                            ext = ext.replace('0', '')
                        
                        decrypted_message = decrypted_combined_message[14:-256]
                        decrypted_hash = decrypted_combined_message[-256:]
                        
                    elif (data_type == b'exit'):
                        os._exit(0)
                else:
                    decrypted_message = b'Unable to decrypt message'
                    decrypted_hash = b'error with hash'

                hashed_message = hash_message(decrypted_message)

                is_verified = verify_with_public_key(client_public_key, decrypted_hash, hashed_message)

                if is_verified:
                    if (data_type == b'text'):
                        self.append_message(f"Received a from client: {decrypted_message.decode('utf-8')}")

                        response_message = b'The server received your message succesfully.'

                        hashed_message = hash_message(response_message)
                        encrypted_hash = encrypt_hash_with_private_key(server_private_key, hashed_message)

                        combined_message = response_message + encrypted_hash
                        encrypted_response = aes_encrypt(combined_message, shared_key)

                        client_socket.sendall(encrypted_response)
                        
                    elif (data_type == b'file'):
                        self.append_message(f"Received a file from client. Found in server_received_files folder")

                        response_message = b'The server received your message succesfully.'

                        hashed_message = hash_message(response_message)
                        encrypted_hash = encrypt_hash_with_private_key(server_private_key, hashed_message)

                        combined_message = response_message + encrypted_hash
                        encrypted_response = aes_encrypt(combined_message, shared_key)
                        
                        # Get the current date and time
                        current_datetime = datetime.now()

                        # Format the date and time to create a timestamp for the file name
                        timestamp = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")

                        # Use the timestamp in the file name
                        file_name = f"server_received_files/{timestamp}.txt"
                        
                        save_data_to_file(decrypted_message, file_name)

                        client_socket.sendall(encrypted_response)   
                    else:
                        self.append_message(f"not file or text")                              
                else:
                    self.append_message("Received unverified message from client.")
                    break

            client_socket.close()
            self.append_message("Connection closed")

    def perform_server_handshake(self, client_socket, server_public_key):
        client_socket.sendall(server_public_key)
        client_public_key_bytes = self.receive_data(client_socket)
        shared_key = get_random_bytes(16)
        encrypted_shared_key = rsa_encrypt(shared_key, client_public_key_bytes)
        client_socket.sendall(encrypted_shared_key)
        return shared_key, client_public_key_bytes

    def receive_data(self, socket):
        data = b""
        while True:
            chunk = socket.recv(1024)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 1024:
                break
        return data

    def get_user_input(self):
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
                return self.get_user_input()
        else:
            print("Invalid input. Please enter 'text' or 'file'.")
            return self.get_user_input()

    def append_message(self, message):
        self.received_messages_text.config(state="normal")
        self.received_messages_text.insert(tk.END, message + "\n")
        self.received_messages_text.config(state="disabled")
        self.received_messages_text.yview(tk.END)
        
        
import tkinter as tk
from tkinter import filedialog, messagebox

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
from Certificate.certificate import *
from guiClient import *
from guiServer import *
from threading import Thread

import os

class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Project")

        # Set the window size and center it
        window_width = 400
        window_height = 700
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 3

        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

        # Use a custom font for labels and buttons
        self.custom_font = ("Arial", 12)
        
        self.current_frame = None
        self.selected_file_label = None
        self.selected_signature_label = None
        self.file_path = None
        self.key_path = None
        self.file = None
        self.signature_path = None
        self.signature_file = None

        # Initialize key_choice_var_rsa as an instance variable
        self.key_choice_var_rsa = tk.IntVar(value=0)

        self.create_main_frame()


    ####################################################################################################
    ####################                             FRAME CREATION                 ####################
    ####################################################################################################
    def create_main_frame(self):
        if self.current_frame is not None:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Are you a Sender or Receiver?", font=self.custom_font)
        label.pack(pady=20)

        sender_button = tk.Button(self.current_frame, text="Sender", font=self.custom_font, command=self.create_sender_frame)
        sender_button.pack(pady=10)

        receiver_button = tk.Button(self.current_frame, text="Receiver", font=self.custom_font, command=self.create_receiver_frame)
        receiver_button.pack(pady=10)

        certificate_button = tk.Button(self.current_frame, text="Generate Certificate", font=self.custom_font, command=self.create_certificate_frame)
        certificate_button.pack(pady=10)

        chat_button = tk.Button(self.current_frame, text="Start Chat", font=self.custom_font, command=self.create_chat_frame)
        chat_button.pack(pady=10)

        self.current_frame.pack()

    def create_sender_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Sender Options", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_main_frame)
        back_button.pack(pady=10)

        Enc_button = tk.Button(self.current_frame, text="Encrypt File", font=self.custom_font, command=self.create_encrypt_options_frame)
        Enc_button.pack(pady=10)

        Sign_button = tk.Button(self.current_frame, text="Sign File", font=self.custom_font, command=self.create_sign_frame)
        Sign_button.pack(pady=10)

        SignEnc_button = tk.Button(self.current_frame, text="Sign & Encrypt File", font=self.custom_font, command=self.create_sign_encrypt_frame)
        SignEnc_button.pack(pady=10)

        self.current_frame.pack()

    def create_receiver_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Receiver Options", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_main_frame)
        back_button.pack(pady=10)

        SignEnc_button = tk.Button(self.current_frame, text="Compare", font=self.custom_font, command=self.create_compare_frame)
        SignEnc_button.pack(pady=10)

        Enc_button = tk.Button(self.current_frame, text="Decrypt File", font=self.custom_font, command=self.create_decrypt_options_frame)
        Enc_button.pack(pady=10)

        Sign_button = tk.Button(self.current_frame, text="Verify File", font=self.custom_font, command=self.create_verify_frame)
        Sign_button.pack(pady=10)

        Sign_button = tk.Button(self.current_frame, text="Verify & Decrypt File", font=self.custom_font, command=self.create_verify_decrypt_frame)
        Sign_button.pack(pady=10)


        self.current_frame.pack()

    def create_encrypt_options_frame(self):
        if self.current_frame is not None:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Choose Your Encryption Method", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_sender_frame)
        back_button.pack(pady=10)

        aes_button = tk.Button(self.current_frame, text="AES Encryption", font=self.custom_font, command=self.create_aes_encrypt_frame)
        aes_button.pack(pady=10)

        button1_label = tk.Label(self.current_frame, text="Symmetric Encryption for message\n", font=self.custom_font)
        button1_label.pack(pady=20)

        rsa_button = tk.Button(self.current_frame, text="AES & RSA Encryption", font=self.custom_font, command=self.create_rsa_encrypt_frame)
        rsa_button.pack(pady=10)

        button2_label = tk.Label(self.current_frame, text="Symmetric Encryption for message\n + \nAssymetric Encryption for key", font=self.custom_font)
        button2_label.pack(pady=20)

        self.current_frame.pack()

    def create_aes_encrypt_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="AES File Encryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_encrypt_options_frame)
        back_button.pack(pady=10)

        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)

        # Radio buttons for choosing key generation or manual entry
        self.key_choice_var = tk.IntVar(value=1)  # Set the default value to 1 (Generate Key)
        generate_key_radio = tk.Radiobutton(self.current_frame, text="Generate Key", font=self.custom_font, variable=self.key_choice_var, value=1)
        generate_key_radio.pack(pady=5)
        enter_key_radio = tk.Radiobutton(self.current_frame, text="Enter Key", font=self.custom_font, variable=self.key_choice_var, value=2)
        enter_key_radio.pack(pady=5)

        # Choose a file that has the key
        self.choose_key_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, state=tk.DISABLED, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font, state=tk.DISABLED)
        self.selected_key_label.pack(pady=10)

        # Encryption Process for AES
        encrypt_key_button = tk.Button(self.current_frame, text="Encrypt File", font=self.custom_font, command=self.encrypt_button)
        encrypt_key_button.pack(pady=10)

        # Add a trace to the variable to call a function when its value changes
        self.key_choice_var.trace_add("write", self.update_key_entry_state)

        self.current_frame.pack()

    def create_rsa_encrypt_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        # Section 1: Frame Title
        label = tk.Label(self.current_frame, text="AES & RSA Encryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_encrypt_options_frame)
        back_button.pack(pady=10)


        # Section 2: Uploading the file to be encrypted with AES
        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)


        # Section 3: To choose type of entry of symmetric key
        # Radio buttons for choosing key generation or manual entry for SYMMETRIC KEY
        self.symmetric_label = tk.Label(self.current_frame, text="Symmetric Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.symmetric_label.pack(pady=5)


        self.key_choice_var = tk.IntVar(value=1)  # Set the default value to 1 (Generate Key)
        generate_key_radio = tk.Radiobutton(self.current_frame, text="Generate Key", font=self.custom_font, variable=self.key_choice_var, value=1)
        generate_key_radio.pack(pady=5)
        enter_key_radio = tk.Radiobutton(self.current_frame, text="Enter Key", font=self.custom_font, variable=self.key_choice_var, value=2)
        enter_key_radio.pack(pady=5)

        # Choose a file that has the key
        self.choose_key_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, state=tk.DISABLED, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font, state=tk.DISABLED)
        self.selected_key_label.pack(pady=10)


        # Section 4: To choose type of entry of Assymetric Key
        # Radio buttons for choosing key generation or manual entry for SYMMETRIC KEY
        self.asymmetric_label = tk.Label(self.current_frame, text="Asymmetric Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.asymmetric_label.pack(pady=5)

        self.key_choice_var_rsa = tk.IntVar(value=1)  # Set the default value to 1 (Generate Key)
        generate_key_radio = tk.Radiobutton(self.current_frame, text="Generate Key Pair", font=self.custom_font, variable=self.key_choice_var_rsa, value=1)
        generate_key_radio.pack(pady=5)
        enter_key_radio = tk.Radiobutton(self.current_frame, text="Enter Public Key", font=self.custom_font, variable=self.key_choice_var_rsa, value=2)
        enter_key_radio.pack(pady=5)

        # Choose a file that has the key
        self.choose_key2_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, state=tk.DISABLED, command=self.choose_key2_file)
        self.choose_key2_button.pack(pady=10)

        self.selected_key2_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font, state=tk.DISABLED)
        self.selected_key2_label.pack(pady=10)

        # Encryption Process for AES
        encrypt_key_button = tk.Button(self.current_frame, text="Encrypt File", font=self.custom_font, command=self.encrypt_rsa_button)
        encrypt_key_button.pack(pady=10)

        # Add a trace to the variable to call a function when its value changes
        self.key_choice_var.trace_add("write", self.update_key_entry_state)
        self.key_choice_var_rsa.trace_add("write", self.update_key_entry_state)


        self.current_frame.pack()
    
    def create_decrypt_options_frame(self):
        if self.current_frame is not None:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Choose Your Decryption Method", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_receiver_frame)
        back_button.pack(pady=10)

        aes_button = tk.Button(self.current_frame, text="AES Decryption", font=self.custom_font, command=self.create_aes_decrypt_frame)
        aes_button.pack(pady=10)

        button1_label = tk.Label(self.current_frame, text="Symmetric Decryption for message\n", font=self.custom_font)
        button1_label.pack(pady=20)

        rsa_button = tk.Button(self.current_frame, text="AES & RSA Decryption", font=self.custom_font, command=self.create_rsa_decrypt_frame)
        rsa_button.pack(pady=10)

        button2_label = tk.Label(self.current_frame, text="Symmetric Decryption for message\n + \nAssymetric Decryption for key", font=self.custom_font)
        button2_label.pack(pady=20)

        self.current_frame.pack()
    
    def create_aes_decrypt_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="File Decryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_decrypt_options_frame)
        back_button.pack(pady=10)

        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)

        # Choose a file that has the key
        self.choose_key_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font)
        self.selected_key_label.pack(pady=10)

        # Button to Decrypt
        decrypt_key_button = tk.Button(self.current_frame, text="Decrypt File", font=self.custom_font, command=self.decrypt_button)
        decrypt_key_button.pack(pady=10)

        self.current_frame.pack()

    def create_rsa_decrypt_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        # Section 1: Title and back button
        label = tk.Label(self.current_frame, text="AES & RSA File Decryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_decrypt_options_frame)
        back_button.pack(pady=10)

        # Section 2: Uploading the file to be decrypted with AES
        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)

        # Section 3: Uploading the encrypted symmetric key to be decrypted with RSA
        self.symmetric_label = tk.Label(self.current_frame, text="Symmetric Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.symmetric_label.pack(pady=5)

        choose_key_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_key_file)
        choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_key_label.pack(pady=10)

        self.asymmetric_label = tk.Label(self.current_frame, text="Asymmetric Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.asymmetric_label.pack(pady=5)

        # Choose a file that has the key
        self.choose_key2_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, command=self.choose_key2_file)
        self.choose_key2_button.pack(pady=10)

        self.selected_key2_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font)
        self.selected_key2_label.pack(pady=10)

        # Button to Decrypt
        decrypt_key_button = tk.Button(self.current_frame, text="Decrypt File", font=self.custom_font, command=self.decrypt_rsa_button)
        decrypt_key_button.pack(pady=10)

        self.current_frame.pack()
    def create_compare_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        # Section 1: Title and back button
        label = tk.Label(self.current_frame, text="Compare between Original & Decrypted file", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_receiver_frame)
        back_button.pack(pady=10)

        # Section 2: Uploading the encrypted symmetric key to be decrypted with RSA
        self.symmetric_label = tk.Label(self.current_frame, text="Choose First File", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.symmetric_label.pack(pady=5)

        # Section 3: Uploading the file to be decrypted with AES
        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)

        # Section 4: Uploading the encrypted symmetric key to be decrypted with RSA
        self.symmetric_label = tk.Label(self.current_frame, text="Choose Second File", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.symmetric_label.pack(pady=5)

        choose_key_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_key_file)
        choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_key_label.pack(pady=10)


        # Button to Decrypt
        decrypt_key_button = tk.Button(self.current_frame, text="Compare Files", font=self.custom_font, command=self.compare_button)
        decrypt_key_button.pack(pady=10)

        self.current_frame.pack()
    def create_sign_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="File Signing", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_sender_frame)
        back_button.pack(pady=10)

        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)

        # Radio buttons for choosing key generation or manual entry
        self.key_choice_var = tk.IntVar(value=1)  # Set the default value to 1 (Generate Key)
        generate_key_radio = tk.Radiobutton(self.current_frame, text="Generate Key Pairs", font=self.custom_font, variable=self.key_choice_var, value=1)
        generate_key_radio.pack(pady=5)
        enter_key_radio = tk.Radiobutton(self.current_frame, text="Enter Private Key", font=self.custom_font, variable=self.key_choice_var, value=2)
        enter_key_radio.pack(pady=5)

        # Choose a file that has the key
        self.choose_key_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, state=tk.DISABLED, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font, state=tk.DISABLED)
        self.selected_key_label.pack(pady=10)

        # Encryption Process for AES
        sign_key_button = tk.Button(self.current_frame, text="Sign File", font=self.custom_font, command=self.sign_button)
        sign_key_button.pack(pady=10)

        # Add a trace to the variable to call a function when its value changes
        self.key_choice_var.trace_add("write", self.update_key_entry_state)

        self.current_frame.pack()
    
    def create_verify_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="File Verifying", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_receiver_frame)
        back_button.pack(pady=10)

        # Chose original message
        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)

        # Choose signature
        choose_signature_button = tk.Button(self.current_frame, text="Choose Signature File", font=self.custom_font, command=self.choose_signature)
        choose_signature_button.pack(pady=10)

        self.selected_signature_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_signature_label.pack(pady=10)

        # Choose a file that has the public key
        self.choose_key_button = tk.Button(self.current_frame, text="Public Key/Certificate File", font=self.custom_font, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key/Certificate File: None", font=self.custom_font)
        self.selected_key_label.pack(pady=10)

        # Button to Decrypt
        decrypt_key_button = tk.Button(self.current_frame, text="Verify File", font=self.custom_font, command=self.verify_button)
        decrypt_key_button.pack(pady=10)

        self.current_frame.pack()
    
    def create_sign_encrypt_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        # Section 1: Frame Title
        label = tk.Label(self.current_frame, text="File Signing & Encryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_sender_frame)
        back_button.pack(pady=10)


        # Section 2: Uploading the file that has the message
        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)


        # Section 3: To choose type of entry of symmetric key
        # Radio buttons for choosing key generation or manual entry for SYMMETRIC KEY
        self.symmetric_label = tk.Label(self.current_frame, text="Symmetric Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.symmetric_label.pack(pady=5)

        self.key_choice_var = tk.IntVar(value=1)  # Set the default value to 1 (Generate Key)
        generate_key_radio = tk.Radiobutton(self.current_frame, text="Generate Key", font=self.custom_font, variable=self.key_choice_var, value=1)
        generate_key_radio.pack(pady=5)
        enter_key_radio = tk.Radiobutton(self.current_frame, text="Enter Key", font=self.custom_font, variable=self.key_choice_var, value=2)
        enter_key_radio.pack(pady=5)

        # Choose a file that has the key
        self.choose_key_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, state=tk.DISABLED, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font, state=tk.DISABLED)
        self.selected_key_label.pack(pady=10)



        # Section 4: To choose type of entry of Assymetric Key
        # Radio buttons for choosing key generation or manual entry for SYMMETRIC KEY
        self.asymmetric_label = tk.Label(self.current_frame, text="Private Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.asymmetric_label.pack(pady=5)

        self.key_choice_var_rsa = tk.IntVar(value=1)  # Set the default value to 1 (Generate Key)
        generate_key_radio = tk.Radiobutton(self.current_frame, text="Generate Key Pair", font=self.custom_font, variable=self.key_choice_var_rsa, value=1)
        generate_key_radio.pack(pady=5)
        enter_key_radio = tk.Radiobutton(self.current_frame, text="Enter Private Key", font=self.custom_font, variable=self.key_choice_var_rsa, value=2)
        enter_key_radio.pack(pady=5)

        # Choose a file that has the key
        self.choose_key2_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, state=tk.DISABLED, command=self.choose_key2_file)
        self.choose_key2_button.pack(pady=10)

        self.selected_key2_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font, state=tk.DISABLED)
        self.selected_key2_label.pack(pady=10)

        # Encryption Process for AES
        encrypt_key_button = tk.Button(self.current_frame, text="Sign & Encrypt File", font=self.custom_font, command=self.sign_encrypt_button)
        encrypt_key_button.pack(pady=10)

        # Add a trace to the variable to call a function when its value changes
        self.key_choice_var.trace_add("write", self.update_key_entry_state)
        self.key_choice_var_rsa.trace_add("write", self.update_key_entry_state)


        self.current_frame.pack()

    def create_verify_decrypt_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        # Section 1: Title and back button
        label = tk.Label(self.current_frame, text="File Verifying & Decryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_receiver_frame)
        back_button.pack(pady=10)

        # Section 2: Uploading the file to be decrypted with AES
        choose_file_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_file)
        choose_file_button.pack(pady=10)

        self.selected_file_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_file_label.pack(pady=10)

        # Section 3: Uploading the symmetric key
        self.symmetric_label = tk.Label(self.current_frame, text="Symmetric Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.symmetric_label.pack(pady=5)

        choose_key_button = tk.Button(self.current_frame, text="Choose File", font=self.custom_font, command=self.choose_key_file)
        choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_key_label.pack(pady=10)

        # Section 4: Uploading the public key
        self.asymmetric_label = tk.Label(self.current_frame, text="Public Key", font=(self.custom_font[0], self.custom_font[1], 'bold'))
        self.asymmetric_label.pack(pady=5)

        # Choose a file that has the key
        self.choose_key2_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, command=self.choose_key2_file)
        self.choose_key2_button.pack(pady=10)

        self.selected_key2_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font)
        self.selected_key2_label.pack(pady=10)

        # Button to Decrypt
        decrypt_key_button = tk.Button(self.current_frame, text="Verify & Decrypt File", font=self.custom_font, command=self.verify_decrypt_button)
        decrypt_key_button.pack(pady=10)

        self.current_frame.pack()

    def create_certificate_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        # Section 1: Title and back button
        label = tk.Label(self.current_frame, text="Certificate Generation", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_main_frame)
        back_button.pack(pady=10)

        # Label and Entry for Field 1
        frame1 = tk.Frame(self.current_frame)
        frame1.pack(side="top", pady=(10, 0), fill="x")

        label1 = tk.Label(frame1, text="Country:             ")
        label1.pack(side="left", padx=(10, 5))

        self.country = tk.Entry(frame1)
        self.country.pack(side="left", padx=(0, 10))

        desc1 = tk.Label(self.current_frame, text="Expects only 2 letters in uppercase. EX: EG")
        desc1.pack(side="top", pady=(0, 10), padx=10, anchor="w")

        # Label and Entry for Field 2
        frame2 = tk.Frame(self.current_frame)
        frame2.pack(side="top", pady=(10, 0), fill="x")

        label2 = tk.Label(frame2, text="State/Province:  ")
        label2.pack(side="left", padx=(10, 5))

        self.state_or_province = tk.Entry(frame2)
        self.state_or_province.pack(side="left", padx=(0, 10))

        desc2 = tk.Label(self.current_frame, text="Ex: Cairo")
        desc2.pack(side="top", pady=(0, 10), padx=10, anchor="w")

        # Label and Entry for Field 3
        frame3 = tk.Frame(self.current_frame)
        frame3.pack(side="top", pady=(10, 0), fill="x")

        label3 = tk.Label(frame3, text="Locality:              ")
        label3.pack(side="left", padx=(10, 5))

        self.locality = tk.Entry(frame3)
        self.locality.pack(side="left", padx=(0, 10))

        desc3 = tk.Label(self.current_frame, text="Ex: Abdo Basha")
        desc3.pack(side="top", pady=(0, 10), padx=10, anchor="w")

        # Label and Entry for Field 4
        frame4 = tk.Frame(self.current_frame)
        frame4.pack(side="top", pady=(10, 0), fill="x")

        label4 = tk.Label(frame4, text="Organization:     ")
        label4.pack(side="left", padx=(10, 5))

        self.organization = tk.Entry(frame4)
        self.organization.pack(side="left", padx=(0, 10))

        desc4 = tk.Label(self.current_frame, text="Ex: Ain Shams University")
        desc4.pack(side="top", pady=(0, 10), padx=10, anchor="w")

        # Label and Entry for Field 5
        frame5 = tk.Frame(self.current_frame)
        frame5.pack(side="top", pady=(10, 0), fill="x")

        label5 = tk.Label(frame5, text="Common Name:")
        label5.pack(side="left", padx=(10, 5))

        self.common_name = tk.Entry(frame5)
        self.common_name.pack(side="left", padx=(0, 10))

        desc5 = tk.Label(self.current_frame, text="Ex: Ahmed")
        desc5.pack(side="top", pady=(0, 10), padx=10, anchor="w")
        
        # Radio buttons for choosing key generation or manual entry
        self.key_choice_var = tk.IntVar(value=1)  # Set the default value to 1 (Generate Key)
        generate_key_radio = tk.Radiobutton(self.current_frame, text="Generate Key Pairs", font=self.custom_font, variable=self.key_choice_var, value=1)
        generate_key_radio.pack(pady=5)
        enter_key_radio = tk.Radiobutton(self.current_frame, text="Enter Private Key", font=self.custom_font, variable=self.key_choice_var, value=2)
        enter_key_radio.pack(pady=5)

        # Choose a file that has the key
        self.choose_key_button = tk.Button(self.current_frame, text="Choose Key File", font=self.custom_font, state=tk.DISABLED, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font, state=tk.DISABLED)
        self.selected_key_label.pack(pady=10)

        # Submit button
        submit_button = tk.Button(self.current_frame, text="Generate Certificate", command=self.generate_certificate)
        submit_button.pack(side="top", pady=(10, 0))

        self.current_frame.pack()

    def create_chat_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Chat Window", font=self.custom_font)
        label.pack(pady=20)

        

        label = tk.Label(self.current_frame, text="You are now in chat mode\nIt is a kind of chat simulation to show\nthe secure chat functionality", font=self.custom_font)
        label.pack(pady=20)

        # Create a new thread for the server GUI
        server_thread = Thread(target=self.run_server_gui)
        server_thread.start()

        # Create a new thread for the client GUI
        client_thread = Thread(target=self.run_client_gui)
        client_thread.start()

        self.current_frame.pack()

    def run_server_gui(self):
        server_window = tk.Toplevel(self.root)
        ServerGUI(server_window)

    def run_client_gui(self):
        client_window = tk.Toplevel(self.root)

        # Position on the right of the main window, far from the server window
        x_position = self.root.winfo_x() + self.root.winfo_width() + 10
        y_position = self.root.winfo_y()
        client_window.geometry(f"+{x_position}+{y_position}")

        ChatClient(client_window)

    ########################################################################################################################
    ####################                            GUI HELP FUNCTIONS                                  ####################
    ########################################################################################################################
    def choose_file(self):
        self.file_path,self.file = self.choose_and_update_label(self.selected_file_label, "Selected File")
    
    def choose_signature(self):
        self.signature_path,self.signature_file = self.choose_and_update_label(self.selected_signature_label, "Selected File")

    def choose_key_file(self):
        self.key_path= self.choose_and_update_label(self.selected_key_label, "Selected Key File")

    def choose_key2_file(self):
        self.key2_path= self.choose_and_update_label(self.selected_key2_label, "Selected Key File")

    def choose_and_update_label(self, label_widget, label_text):
        file_path = filedialog.askopenfilename(title=f"Select a {label_text}", filetypes=[("All Files", "*.*")])
        file = ""  
        if file_path:
            file = file_path.split("/")[-1]  # Extracting the file name from the path
            label_widget.config(text=f"{label_text}: {file}")
        return file_path, file
    
    
    def update_key_entry_state(self, *args):
        # Update the state of the entry widget based on the selected radio button
        key_choice = self.key_choice_var.get()
        if key_choice == 2:  # Enter Key option
            self.choose_key_button.config(state=tk.NORMAL)
            self.selected_key_label.config(state=tk.NORMAL)
        else:
            self.choose_key_button.config(state=tk.DISABLED)
            self.selected_key_label.config(state=tk.DISABLED)

        # Update the state of the entry widget based on the selected radio button
        key_choice_rsa = self.key_choice_var_rsa.get()
        if key_choice_rsa != 0:
            if key_choice_rsa == 2:  # Enter Key option
                self.choose_key2_button.config(state=tk.NORMAL)
                self.selected_key2_label.config(state=tk.NORMAL)
            else:
                self.choose_key2_button.config(state=tk.DISABLED)
                self.selected_key2_label.config(state=tk.DISABLED)

    def file_not_exist(self, file_path):
        if file_path is None or file_path == "":
            messagebox.showerror("File Manager", "Please select required files")
            return True
    
    def destroy_chat_windows(self):
        # Destroy the chat windows when the Back button is pressed
        self.server_chat.destroy()
        self.client_chat.destroy()

        # Navigate back to the main frame
        self.create_main_frame()
    ########################################################################################################################
    ####################                            Security Functions                                  ####################
    ########################################################################################################################
        
    ################################
    ## To ENcrypt files using AES ##
    ################################
    def encrypt_button(self):
        key_choice = self.key_choice_var.get() # To track if user wants to generate or enter a key

        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        
        if key_choice == 1:  # Generate Key
            key = get_random_bytes(16)
            hexKey = binascii.hexlify(key).decode('utf-8')      #convert output to hexadecimal
            messagebox.showinfo("Key Generated", f"Generated Key: {hexKey}")
            keyfile_name = save_key_to_file(key, 'keys/symKey.pem')
            messagebox.showinfo("Key Generated", f"The Generated Key is at keys folder as: \"{keyfile_name}\"")

        elif key_choice == 2:  # Use Entered Key
            if self.file_not_exist(self.key_path):
                return
            # Loads data in uploaded key file and checks if it's hexa
            key = load_key_from_file(self.key_path[0])
            if key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
            
            hexKey = binascii.hexlify(key).decode('utf-8')      #convert output to hexadecimal
            # Checks if the key is 16 bye long
            if len(hexKey) != 32:
                messagebox.showerror("Error","Please enter a file that has a 16byte AES key")
                return
            messagebox.showinfo("Key Entered", f"Entered Key: {hexKey}")
        
        # AES Encrypt    
        data = load_data_from_file(self.file_path) 
        encrypted_data = aes_encrypt(data, key)
        # print("Encrypted Data:", binascii.hexlify(encrypted_data).decode('utf-8'))  #convert output to hexadecimal
        encfile_name = save_data_to_file(encrypted_data, f"outputs/{self.file}.enc")

        messagebox.showinfo("Success", f"Encryption was successful.\nEnc data in outputs folder as \"{encfile_name}\".")
        
    ################################
    ## To DEcrypt files using AES ##
    ################################
    def decrypt_button(self):
        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        
        ## If user didnt upload key, EXIT!
        if self.file_not_exist(self.key_path):
            return
        
        key = load_key_from_file(self.key_path[0])
        if key == None:
            messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
            return
            
        hexKey = binascii.hexlify(key).decode('utf-8')      #convert output to hexadecimal
        
        # Checks if the key is 16 bye long
        if len(hexKey) != 32:
            messagebox.showerror("Error","Please enter a file that has a 16byte key")
            return
        messagebox.showinfo("Key Entered", f"Entered Key: {hexKey}")

        # AES Decrypt
        ct = load_data_from_file(self.file_path)
        dec_data = aes_decrypt(ct, key)
        self.file = self.file.replace(".enc", "")
        decfile_name = save_data_to_file(dec_data, f"outputs/{self.file}")

        messagebox.showinfo("Success", f"Decryption was successful.\nDec data in outputs folder as \"{decfile_name}\".")

    
    ####################################################################
    ## To ENcrypt files using AES and ENcrypt symmetric key using RSA ##
    ####################################################################
    def encrypt_rsa_button(self):
        key_choice_aes = self.key_choice_var.get() # To track if user wants to generate or enter a symmetric key
        key_choice_rsa = self.key_choice_var_rsa.get() # To track if user wants to generate or enter a symmetric key

        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        
        ## To get user's choice for Symmetric key
        if key_choice_aes == 1:  # Generate Key
            aes_key = get_random_bytes(16)
            hexKey = binascii.hexlify(aes_key).decode('utf-8')      #convert output to hexadecimal
            messagebox.showinfo("Key Generated", f"Generated AES Key:\n {hexKey}")
            keyfile_name = save_key_to_file(aes_key, 'keys/symKey.pem')
            messagebox.showinfo("Key Generated", f"The Generated Key is at keys folder as: \"{keyfile_name}\"")

        elif key_choice_aes == 2:  # Use Entered Key
            if self.file_not_exist(self.key_path):
                return
            aes_key = load_key_from_file(self.key_path[0])
            if aes_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
                
            hexKey = binascii.hexlify(aes_key).decode('utf-8')      #convert output to hexadecimal
            
            # Checks if the key is 16 bye long
            if len(hexKey) != 32:
                messagebox.showerror("Error","Please enter a file that has a 16byte key")
                return
            messagebox.showinfo("Key Entered", f"Entered Key: {hexKey}")


        ## To get user's choice for Asymetric key
        if key_choice_rsa == 1:  # Generate Key Pairs
            private_key, public_key = generate_RSA_key_pair()
            messagebox.showinfo("Key Generated", f"Generated Private Key:\n {private_key}")
            messagebox.showinfo("Key Generated", f"Generated Public Key:\n {public_key}")
            prikey_name = save_key_to_file(private_key, 'keys/private.pem')
            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')
            messagebox.showinfo("Private Key Generated", f"The Generated Private Key is in keys folder as: \"{prikey_name}\"")
            messagebox.showinfo("Public Key Generated", f"The Generated Public Key is in keys folder as: \"{pubkey_name}\"")
            

        elif key_choice_rsa == 2:  # Use Entered Private Key
            if self.file_not_exist(self.key_path):
                return
            private_key = load_key_from_file(self.key_path[0])
            if private_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
                
            hexKey = binascii.hexlify(private_key).decode('utf-8')      #convert output to hexadecimal
            
            # Checks if the key is 256 bye long
            if len(hexKey) != 512:
                messagebox.showerror("Error","Please enter a file that has a 256 byte key")
                return
            # Extract and save the public key
            public_key = RSA.import_key(private_key).publickey().export_key()

            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')

            messagebox.showinfo("Key Entered", f"Entered Private Key:\n {private_key}")
            messagebox.showinfo("Public Key", f"Generated Corresponding Public Key: {public_key}")
            messagebox.showinfo("Public Key Generated", f"The Generated Corresponding Public Key is in keys folder as: \"{pubkey_name}\"")


        # Load data from file to be encrypted
        data = load_data_from_file(self.file_path) 

        # AES Encrypt    
        encrypted_data = aes_encrypt(data, aes_key)

        # RSA Encryption for AES key
        encrypted_aes_key = rsa_encrypt(aes_key, public_key)

        # Save data and all keys
        encdata_file = save_data_to_file(encrypted_data, f"outputs/{self.file}.enc")
        encaeskey_file = save_key_to_file(encrypted_aes_key, 'keys/encrypted_aes_key.pem')
        messagebox.showinfo("Success", f"You will find the ecrypted aes_key file in keys folder as: \"{encaeskey_file}\".")
        messagebox.showinfo("Success", f"Encryption was successful.\nEnc data in outputs folder as \"{encdata_file}\".")

    ####################################################################
    ## To DEcrypt files using AES and ENcrypt symmetric key using RSA ##
    ####################################################################
    def decrypt_rsa_button(self):
        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        ## If user didnt upload AES symmetric key, EXIT!
        if self.file_not_exist(self.key_path):
            return
        
        ## If user didnt upload RSA Public key, EXIT!
        if self.file_not_exist(self.key2_path):
            return
        
        # Loading the keys for decryption process
        ct_aes_key = load_key_from_file(self.key_path[0])
        public_key = load_key_from_file(self.key2_path[0])

        # Loading Decrypted data from file
        ct = load_data_from_file(self.file_path)

        # RSA Decrypt the AES Key
        dec_aes_key = rsa_decrypt(ct_aes_key, public_key)
        decaeskey_file = save_key_to_file(dec_aes_key, 'keys/dec_aes_key.pem')
        messagebox.showinfo("Success", f"You will find the decrypted aes_key file in keys folder as: \"{decaeskey_file}\".")

        # AES Decrypt
        dec_data = aes_decrypt(ct, dec_aes_key)
        self.file = self.file.replace(".enc", "")
        decdata_file = save_data_to_file(dec_data, f"outputs/{self.file}")

        messagebox.showinfo("Success", f"Decryption was successful.\nDec data in outputs folder as \"{decdata_file}\".")

    ###############################################################
    ##  Compare between original and decrypted file you choose   ##
    ###############################################################
    def compare_button(self):
        ## If user didnt upload first file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        
        ## If user didnt upload second file, EXIT!
        if self.file_not_exist(self.key_path):
            return
        
        ## Comparing the files
        if are_files_equal(self.file_path, self.key_path[0]):
            messagebox.showinfo("Success", "The files contents are identical!")
        else:
            messagebox.showerror("Failed", "The files contents are different!")

    ################################
    ##        To Sign Files       ##
    ################################
    def sign_button(self):
        key_choice = self.key_choice_var.get() # To track if user wants to generate or enter a key

        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        
        if key_choice == 1:  # Generate Key Pairs
            private_key, public_key = generate_RSA_key_pair()
            messagebox.showinfo("Key Generated", f"Generated Private Key:\n {private_key}")
            messagebox.showinfo("Key Generated", f"Generated Public Key:\n {public_key}")
            prikey_name = save_key_to_file(private_key, 'keys/private.pem')
            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')
            messagebox.showinfo("Private Key Generated", f"The Generated Private Key is in keys folder as: \"{prikey_name}\"")
            messagebox.showinfo("Public Key Generated", f"The Generated Public Key is in keys folder as: \"{pubkey_name}\"")
            

        elif key_choice == 2:  # Use Entered Private Key
            if self.file_not_exist(self.key_path):
                return
            private_key = load_key_from_file(self.key_path[0])

            if private_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
                
            hexKey = binascii.hexlify(private_key).decode('utf-8')      #convert output to hexadecimal
            
            # Checks if the key is valid
            if len(hexKey) != 3348:
                messagebox.showerror("Error","Please enter a valid private key")
                return

            # Extract and save the public key
            public_key = RSA.import_key(private_key).publickey().export_key()

            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')

            messagebox.showinfo("Key Entered", f"Entered Private Key:\n {private_key}")
            messagebox.showinfo("Public Key", f"Generated Corresponding Public Key: {public_key}")
            messagebox.showinfo("Public Key Generated", f"The Generated Corresponding Public Key is in keys folder as: \"{pubkey_name}\"")


        # Sign the message
        message = load_data_from_file(self.file_path)
        signature = sign_message(message, private_key)
        signature_name = save_data_to_file(signature, f"outputs/{self.file}.bin")
        messagebox.showinfo("Success", f"File Signing was successful.\nSignature is in outputs folder as \"{signature_name}\".")


    ##################################
    ##         To Verify Files      ##
    ##################################
    def verify_button(self):
        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        ## If user didnt upload Signature File, EXIT!
        if self.file_not_exist(self.signature_path):
            return
        
        ## If user didnt upload key, EXIT!
        if self.file_not_exist(self.key_path):
            return
        
        public_key = load_key_from_file(self.key_path[0])
        if public_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
        
        hexKey = binascii.hexlify(public_key).decode('utf-8')      #convert output to hexadecimal
        
        # Checks if the key is valid
        # if len(hexKey) != 900:
        #     messagebox.showerror("Error","Please enter a valid public key")
        #     return

        # Verify the signature
        message = load_data_from_file(self.file_path)
        signature_data = load_data_from_file(self.signature_path)
        if verify_signature(message, signature_data, public_key):
            messagebox.showinfo("Signature", "Signature is verified succesfully and is valid!")
        else:
            messagebox.showerror("Signature", "Signature verification failed and isn't valid!")

    ###################################
    ## To Sign and Encrypt a message ##
    ###################################
    def sign_encrypt_button(self):
        key_choice_aes = self.key_choice_var.get() # To track if user wants to generate or enter a symmetric key
        key_choice_rsa = self.key_choice_var_rsa.get() # To track if user wants to generate or enter an asymmetric key

        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        
        ## To get user's choice for Symmetric key
        if key_choice_aes == 1:  # Generate Key
            aes_key = get_random_bytes(16)
            hexKey = binascii.hexlify(aes_key).decode('utf-8')      #convert output to hexadecimal
            messagebox.showinfo("Key Generated", f"Generated Key: {hexKey}")
            keyfile_name = save_key_to_file(aes_key, 'keys/symKey.pem')
            messagebox.showinfo("Key Generated", f"The Generated Key is at keys folder as: \"{keyfile_name}\"")

        elif key_choice_aes == 2:  # Use Entered Key
            if self.file_not_exist(self.key_path):
                return
            aes_key = load_key_from_file(self.key_path[0])
            if public_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
        
            hexKey = binascii.hexlify(public_key).decode('utf-8')      #convert output to hexadecimal
            
            # Checks if the key is valid
            if len(hexKey) != 32:
                messagebox.showerror("Error","Please enter a file that has 16 byte AES key")
                return
            messagebox.showinfo("Key Entered", f"Entered Key: {hexKey}")


        ## To get user's choice for Asymetric key
        if key_choice_rsa == 1:  # Generate Key Pairs
            private_key, public_key = generate_RSA_key_pair()
            messagebox.showinfo("Key Generated", f"Generated Private Key:\n {private_key}")
            messagebox.showinfo("Key Generated", f"Generated Public Key:\n {public_key}")
            prikey_name = save_key_to_file(private_key, 'keys/private.pem')
            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')
            messagebox.showinfo("Private Key Generated", f"The Generated Private Key is in keys folder as: \"{prikey_name}\"")
            messagebox.showinfo("Public Key Generated", f"The Generated Public Key is in keys folder as: \"{pubkey_name}\"")

        elif key_choice_rsa == 2:  # Use Entered Private Key
            if self.file_not_exist(self.key_path):
                return
            private_key = load_key_from_file(self.key_path[0])
            if public_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
        
            hexKey = binascii.hexlify(public_key).decode('utf-8')      #convert output to hexadecimal
            
            # Checks if the key is valid
            if len(hexKey) != 3348:
                messagebox.showerror("Error","Please enter a valid private key")
                return

            # Extract and save the public key
            public_key = RSA.import_key(private_key).publickey().export_key()

            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')

            messagebox.showinfo("Key Entered", f"Entered Private Key:\n {private_key}")
            messagebox.showinfo("Public Key", f"Generated Corresponding Public Key: {public_key}")
            messagebox.showinfo("Public Key Generated", f"The Generated Corresponding Public Key is in keys folder as: \"{pubkey_name}\"")

        
        # Load data from file to be encrypted
        original_message = load_data_from_file(self.file_path) 

        # Step 3: Calculate hash and encrypt with private key
        hashed_message = hash_message(original_message)
        encrypted_hash = encrypt_hash_with_private_key(private_key, hashed_message)

        # Step 4: Append the encrypted hash to the original message
        combined_message = original_message + encrypted_hash

        # Step 6: Encrypt the combined message with the symmetric key
        encrypted_combined_message = aes_encrypt(combined_message, aes_key)

        # Save data and all keys
        enccombined_file = save_data_to_file(encrypted_combined_message, f"outputs/{self.file}.enc")
        messagebox.showinfo("Success", f"File Signing & Encryption was successful.\nEnc data in outputs as \"{enccombined_file}\".")

    ####################################################################
    ## To DEcrypt files using AES and ENcrypt symmetric key using RSA ##
    ####################################################################
    def verify_decrypt_button(self):
        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        ## If user didnt upload AES symmetric key, EXIT!
        if self.file_not_exist(self.key_path):
            return
        ## If user didnt upload Public key, EXIT!
        if self.file_not_exist(self.key2_path):
            return
        
        # Loading the keys for decryption process
        aes_key = load_key_from_file(self.key_path[0])
        if aes_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
        
        hexKey = binascii.hexlify(aes_key).decode('utf-8')      #convert output to hexadecimal
        
        # Checks if the key is valid
        if len(hexKey) != 32:
            messagebox.showerror("Error","Please enter a valid public key")
            return

        public_key = load_key_from_file(self.key2_path[0])
        if public_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
        
        hexKey = binascii.hexlify(public_key).decode('utf-8')      #convert output to hexadecimal
        
        # Checks if the key is valid
        if len(hexKey) != 900:
            messagebox.showerror("Error","Please enter a valid public key")
            return


        # Loading Decrypted data from file
        encrypted_combined_message = load_data_from_file(self.file_path)

        # Verifying & Decryption
        decrypted_combined_message = aes_decrypt(encrypted_combined_message, aes_key)
        decrypted_message = decrypted_combined_message[:-256]  # Remove the encrypted hash
        decrypted_hash = decrypted_combined_message[-256:]    # Extract the encrypted hash

        hashed_message = hash_message(decrypted_message)

        # Verify the hash
        if verify_with_public_key(public_key, decrypted_hash, hashed_message):
            messagebox.showinfo("Success", "Signature Verified Successfully")
        else:
            messagebox.showerror("Error", "Signature verification wasn't successful")
        # Saving file
        self.file = self.file.replace(".enc", "")
        decmessage_file = save_data_to_file(decrypted_message, f"outputs/{self.file}")
        messagebox.showinfo("Success", f"File Verifying & Decryption was successful.\nDec data in outputs as \"{decmessage_file}\".")

    ############################
    ## Certificate Generation ##
    ############################
    def generate_certificate(self):
        # Collecting values from Entry widgets
        country_value = self.country.get()
        state_or_province_value = self.state_or_province.get()
        locality_value = self.locality.get()
        organization_value = self.organization.get()
        common_name_value = self.common_name.get()

        user_info = [country_value, state_or_province_value, locality_value, organization_value, common_name_value]

        key_choice = self.key_choice_var.get() # To track if user wants to generate or enter a key
        
        if key_choice == 1:  # Generate Key Pairs
            private_key, public_key = generate_RSA_key_pair()
            messagebox.showinfo("Key Generated", f"Generated Private Key:\n {private_key}")
            messagebox.showinfo("Key Generated", f"Generated Public Key:\n {public_key}")
            prikey_name = save_key_to_file(private_key, 'keys/private.pem')
            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')
            messagebox.showinfo("Private Key Generated", f"The Generated Private Key is in keys folder as: \"{prikey_name}\"")
            messagebox.showinfo("Public Key Generated", f"The Generated Public Key is in keys folder as: \"{pubkey_name}\"")

        elif key_choice == 2:  # Use Entered Private Key
            if self.file_not_exist(self.key_path):
                return
            private_key = load_key_from_file(self.key_path[0])
            if private_key == None:
                messagebox.showerror("Error","Please enter a file that is in hexadecimal format")
                return
        
            hexKey = binascii.hexlify(private_key).decode('utf-8')      #convert output to hexadecimal
            
            # Checks if the key is valid
            if len(hexKey) != 3348:
                messagebox.showerror("Error","Please enter a valid private key")
                return


             # Extract and save the public key
            public_key = RSA.import_key(private_key).publickey().export_key()

            pubkey_name = save_key_to_file(public_key, 'keys/public.pem')

            messagebox.showinfo("Key Entered", f"Entered Private Key:\n {private_key}")
            messagebox.showinfo("Public Key", f"Generated Corresponding Public Key: {public_key}")
            messagebox.showinfo("Public Key Generated", f"The Generated Corresponding Public Key is in keys folder as: \"{pubkey_name}\"")


        # Generate a self-signed X.509 certificate and private key
        CA_private_key, CA_public_key, certificate = certification(private_key, user_info)
        
        save_key_to_file(certificate, 'keys/cert.pem')
        messagebox.showinfo("Success", "Certification was successful!\nYou will find the certificate in keys as \"cert.pem\"")
        # cert = x509.load_pem_x509_certificate(certificate, default_backend())
        
        # public_key = cert.public_key()
        # public_key_pem = public_key.public_bytes(
        # encoding=serialization.Encoding.PEM,
        # format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # save_data_to_file(signature, f"outputs/{self.file}.bin")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()
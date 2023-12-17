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
import os


class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Project")

        # Set the window size and center it
        window_width = 400
        window_height = 500
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2

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

        SignEnc_button = tk.Button(self.current_frame, text="Sign & Encrypt File", font=self.custom_font, command=self.create_sign_frame)
        SignEnc_button.pack(pady=10)

        self.current_frame.pack()

    def create_receiver_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="Receiver Options", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_main_frame)
        back_button.pack(pady=10)

        SignEnc_button = tk.Button(self.current_frame, text="Compare", font=self.custom_font, command=self.create_sign_frame)
        SignEnc_button.pack(pady=10)

        Enc_button = tk.Button(self.current_frame, text="Decrypt File", font=self.custom_font, command=self.create_rsa_encrypt_frame)
        Enc_button.pack(pady=10)

        Sign_button = tk.Button(self.current_frame, text="Verify File", font=self.custom_font, command=self.create_verify_frame)
        Sign_button.pack(pady=10)

        Sign_button = tk.Button(self.current_frame, text="Decrypt & Verify File", font=self.custom_font, command=self.create_sign_frame)
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

        rsa_button = tk.Button(self.current_frame, text="RSA Encryption", font=self.custom_font, command=self.create_rsa_encrypt_frame)
        rsa_button.pack(pady=10)

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

    ## TO BE EDITED
    def create_rsa_encrypt_frame(self):
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
    
    def create_aes_decrypt_frame(self):
        self.current_frame.destroy()
        self.current_frame = tk.Frame(self.root)

        label = tk.Label(self.current_frame, text="File Decryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_receiver_frame)
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

        label = tk.Label(self.current_frame, text="File Decryption", font=self.custom_font)
        label.pack(pady=20)

        back_button = tk.Button(self.current_frame, text="Back", font=self.custom_font, command=self.create_receiver_frame)
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

        # Chose signature
        choose_signature_button = tk.Button(self.current_frame, text="Choose Signature File", font=self.custom_font, command=self.choose_signature)
        choose_signature_button.pack(pady=10)

        self.selected_signature_label = tk.Label(self.current_frame, text="Selected File: None", font=self.custom_font)
        self.selected_signature_label.pack(pady=10)

        # Choose a file that has the public key
        self.choose_key_button = tk.Button(self.current_frame, text="Choose Public Key File", font=self.custom_font, command=self.choose_key_file)
        self.choose_key_button.pack(pady=10)

        self.selected_key_label = tk.Label(self.current_frame, text="Selected Key File: None", font=self.custom_font)
        self.selected_key_label.pack(pady=10)

        # Button to Decrypt
        decrypt_key_button = tk.Button(self.current_frame, text="Verify File", font=self.custom_font, command=self.verify_button)
        decrypt_key_button.pack(pady=10)

        self.current_frame.pack()
       
    ########################################################################################################################
    ####################                            GUI HELP FUNCTIONS                                  ####################
    ########################################################################################################################
    def choose_file(self):
        self.file_path,self.file = self.choose_and_update_label(self.selected_file_label, "Selected File")
    
    def choose_signature(self):
        self.signature_path,self.signature_file = self.choose_and_update_label(self.selected_signature_label, "Selected File")

    def choose_key_file(self):
        self.key_path= self.choose_and_update_label(self.selected_key_label, "Selected Key File")

    def choose_and_update_label(self, label_widget, label_text):
        file_path = filedialog.askopenfilename(title=f"Select a {label_text}", filetypes=[("All Files", "*.*")])
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

    def file_not_exist(self, file_path):
        if file_path is None:
            messagebox.showinfo("File Manager", "Please select required files")
            self.create_main_frame()
            return True
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
            messagebox.showinfo("Key Generated", f"Generated Key: {key}")
            save_key_to_file(key, 'keys/symKey.pem')
        elif key_choice == 2:  # Use Entered Key
            if self.file_not_exist(self.key_path):
                return
            key = load_key_from_file(self.key_path[0])
            messagebox.showinfo("Key Entered", f"Entered Key: {key}")
        else:
            messagebox.showerror("Error", "Please choose a key option.")
            self.create_aes_encrypt_frame()
            return
        
        # AES Encrypt    
        data = load_data_from_file(self.file_path) 
        encrypted_data = aes_encrypt(data, key)
        # print("Encrypted Data:", binascii.hexlify(encrypted_data).decode('utf-8'))  #convert output to hexadecimal
        save_data_to_file(encrypted_data, f"outputs/{self.file}.enc")

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
        messagebox.showinfo("Key Entered", f"Entered Key: {key}")

        # AES Decrypt
        ct = load_data_from_file(self.file_path)
        dec_data = aes_decrypt(ct, key)
        self.file = self.file.replace(".enc", "")
        save_data_to_file(dec_data, f"outputs/{self.file}")

    ################################
    ##         To Sign Files      ##
    ################################
    def sign_button(self):
        key_choice = self.key_choice_var.get() # To track if user wants to generate or enter a key

        ## If user didnt upload file, EXIT!
        if self.file_not_exist(self.file_path):
            return
        
        if key_choice == 1:  # Generate Key Pairs
            private_key, public_key = generate_RSA_key_pair()
            save_key_to_file(private_key, 'keys/private.pem')
            save_key_to_file(public_key, 'keys/public.pem')
            messagebox.showinfo("Key Generated", f"Generated Key: {private_key}")
            messagebox.showinfo("Key Generated", f"Generated Key: {public_key}")

        elif key_choice == 2:  # Use Entered Private Key
            if self.file_not_exist(self.key_path):
                return
            private_key = load_key_from_file(self.key_path[0])

            # Extract and save the public key
            public_key = RSA.import_key(private_key).publickey().export_key()

            save_key_to_file(public_key, 'keys/public.pem')

            messagebox.showinfo("Key Entered", f"Entered Private Key: {private_key}")
            messagebox.showinfo("Public Key", f"Generated Corresponding Public Key: {public_key}")
        else:
            messagebox.showerror("Error", "Please choose a key option.")
            self.create_aes_encrypt_frame()
            return

        # Sign the message
        message = load_data_from_file(self.file_path)
        signature = sign_message(message, private_key)
        # print("Signature:", binascii.hexlify(signature).decode('utf-8'))
        save_data_to_file(signature, f"outputs/{self.file}.bin")

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

        # Verify the signature
        message = load_data_from_file(self.file_path)
        signature_data = load_data_from_file(self.signature_path)
        if verify_signature(message, signature_data, public_key):
            messagebox.showinfo("Signature", "Signature is verified succesfully and is valid!")
        else:
            messagebox.showinfo("Signature", "Signature verification failed and isn't valid!")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()
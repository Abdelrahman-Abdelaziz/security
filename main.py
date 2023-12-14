from Crypto.Random import get_random_bytes
from enc_dec.symmetric import Symmetric
from base64 import b64encode, b64decode
import binascii
from signature.sign_verify import generate_key_pair, sign_message, verify_signature
from utils import are_files_equal, genSymKey

def main():
    
    # -----------------------------------------
    # -------------- aes enc/dec --------------
    # -----------------------------------------
    data = b'secret data'
    aes_handler = Symmetric('keys/symKey.txt')

    # AES Encrypt
    encrypted_data = aes_handler.aes_encrypt(data)
    print("Encrypted Data:", binascii.hexlify(encrypted_data).decode('utf-8'))  #convert output to hexadecimal

    # AES Decrypt
    dec_data = aes_handler.aes_decrypt(encrypted_data)
    
    if data.decode('utf-8') == dec_data:
        print('correct')
    else:
        print('incorrect')
    
    # -----------------------------------------
    # -------------- sign verify --------------
    # -----------------------------------------
    private_key, public_key = generate_key_pair()

    message = b"This is a test message."

    # Sign the message
    signature = sign_message(message, private_key)
    print("Signature:", binascii.hexlify(signature).decode('utf-8'))

    # Verify the signature
    verify_signature(message, signature, public_key)

if __name__ == "__main__":
    main()



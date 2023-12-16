from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from enc_dec.symmetric import genSymKey, aes_encrypt, aes_decrypt
from enc_dec.asymmetric import generate_key_pair, rsa_encrypt, rsa_decrypt
from base64 import b64encode, b64decode
import binascii
from sign_verify import sign_message, verify_signature
from utils import are_files_equal, save_key_to_file, load_key_from_file, load_data_from_file, save_data_to_file
import sys
from part3 import generate_key_pair, hash_message, encrypt_hash_with_private_key, encrypt_with_symmetric_key, decrypt_with_symmetric_key, verify_with_public_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def main():
    
    # key = get_random_bytes(16)
    # save_key_to_file(key, 'keys/symKey.txt')
    # key = load_key_from_file('keys/symKey.txt')
    
    # ----------------------------------------------------------------------------------
    # -------------- aes enc/dec -------------------------------------------------------
    # ----------------------------------------------------------------------------------

    # AES Encrypt    
    # data = load_data_from_file('tests/Mask7.webp') 
    # encrypted_data = aes_encrypt(data, key)
    # print("Encrypted Data:", binascii.hexlify(encrypted_data).decode('utf-8'))  #convert output to hexadecimal
    # save_data_to_file(encrypted_data, 'outputs/encData.bin')

    # AES Decrypt
    # ct = load_data_from_file('outputs/encData.bin')
    # dec_data = aes_decrypt(ct, key)
    # save_data_to_file(dec_data, 'outputs/decData.webp')
    
    # compare
    # print(are_files_equal('tests/Mask7.webp', 'outputs/decData.webp'))
    
    # ----------------------------------------------------------------------------------
    # -------------- rsa enc/dec -------------------------------------------------------
    # ----------------------------------------------------------------------------------
    
    # private_key = load_key_from_file('keys/private.pem')
    # public_key = load_key_from_file('keys/public.pem')
    
    # # # rsa encrypt
    # encKey = rsa_encrypt(key, public_key)
    # data = load_data_from_file('tests/Mask7.webp') 
    # encrypted_data = aes_encrypt(data, key)
    # save_data_to_file(encrypted_data, 'outputs/encData.bin')
    
    # # # rsa decrypt
    # decKey = rsa_decrypt(encKey, private_key)
    # ct = load_data_from_file('outputs/encData.bin')
    # dec_data = aes_decrypt(ct, decKey)
    # save_data_to_file(dec_data, 'outputs/decData.webp')
    
    # ----------------------------------------------------------------------------------
    # -------------- sign verify -------------------------------------------------------
    # ----------------------------------------------------------------------------------
    
    # private_key, public_key = generate_key_pair()
    # save_key_to_file(private_key, 'keys/private.pem')
    # save_key_to_file(public_key, 'keys/public.pem')
  
    # message = load_data_from_file('test.txt')
    
    # private_key = load_key_from_file('keys/private.pem')
    # public_key = load_key_from_file('keys/public.pem')

    # Sign the message
    # signature = sign_message(message, private_key)
    # print("Signature:", binascii.hexlify(signature).decode('utf-8'))
    # save_data_to_file(signature, 'signature.bin')

    # Verify the signature
    # signo = load_data_from_file('signature.bin')
    # verify_signature(message, signo, public_key)
    
    # ----------------------------------------------------------------------------------
    # -------------- part 3 ------------------------------------------------------------
    # ----------------------------------------------------------------------------------
    
    # Step 1: Generate RSA key pair
    # private_key, public_key = generate_key_pair()
    private_key = load_key_from_file('keys/private.pem')
    public_key = load_key_from_file('keys/public.pem')

    # Step 2: Get the original message
    original_message = load_data_from_file('tests/Mask7.webp')

    # Step 3: Calculate hash and encrypt with private key
    hashed_message = hash_message(original_message)
    encrypted_hash = encrypt_hash_with_private_key(private_key, hashed_message)

    # Step 4: Append the encrypted hash to the original message
    combined_message = original_message + encrypted_hash

    # Step 5: Generate a symmetric key for AES
    symmetric_key = load_key_from_file('keys/symKey.txt')  # 128 bits for AES

    # Step 6: Encrypt the combined message with the symmetric key
    encrypted_combined_message = aes_encrypt(combined_message, symmetric_key)

    # Display results
    print(f"Original Message: {original_message}")
    print(f"Encrypted Hash: {b64encode(encrypted_hash)}")
    print(f"Symmetric Key: {b64encode(symmetric_key)}")
    print(f"Encrypted Combined Message: {b64encode(encrypted_combined_message)}")

    # Example decryption
    decrypted_combined_message = aes_decrypt(encrypted_combined_message, symmetric_key)
    decrypted_message = decrypted_combined_message[:-256]  # Remove the encrypted hash
    decrypted_hash = decrypted_combined_message[-256:]    # Extract the encrypted hash

    # Verify the hash
    verify_with_public_key(public_key, decrypted_hash, hashed_message)

    save_data_to_file(decrypted_message, 'outputs/decFile.webp')

if __name__ == "__main__":
    main()



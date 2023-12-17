from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_RSA_key_pair():
    # Generate a new RSA key pair (2048 bits)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(session_key, pubKey):
    
    pubKey = RSA.import_key(pubKey)
    cipher_rsa = PKCS1_OAEP.new(pubKey)
    
    enc_session_key = cipher_rsa.encrypt(session_key)
    
    return enc_session_key

def rsa_decrypt(enc_data, priKey):
    
    priKey = RSA.import_key(priKey)
    cipher_rsa = PKCS1_OAEP.new(priKey)
    
    dec_data = cipher_rsa.decrypt(enc_data)
    
    return dec_data


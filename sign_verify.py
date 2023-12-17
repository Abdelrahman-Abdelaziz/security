from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_message(message, private_key):
    # Load the private key
    private_key = RSA.import_key(private_key)

    # Calculate the SHA-256 hash of the message
    h = SHA256.new(message)

    # Sign the hash using the private key
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(message, signature, public_key):
    # Load the public key
    public_key = RSA.import_key(public_key)

    # Calculate the SHA-256 hash of the message
    h = SHA256.new(message)

    try:
        # Verify the signature using the public key
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
    


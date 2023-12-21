from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from utils import *

def generate_self_signed_certificate(private_key_bytes, ca_pri_key, subject_info):
    
    # private key of client
    private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,                  # If the private key is password-protected, provide the password here
    backend=default_backend()
    )
    
    # private key of certificate authority for signature
    ca_priKey = serialization.load_pem_private_key(
    ca_pri_key,
    password=None,                  # If the private key is password-protected, provide the password here
    backend=default_backend()
    )
    
    pubKey = private_key.public_key()
    
    # Define the subject of the certificate (information about the entity being certified)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, subject_info[0]),                            #EG
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, subject_info[1]),               #Cairo
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, subject_info[2]),                   #Abdo Basha
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, subject_info[3]),     #Ain Shams University
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_info[4]),                            #Bob
    ])

    # Set certificate details
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject         # Self-signed, so issuer is the same as subject
    ).public_key(
        pubKey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).sign(
        ca_priKey, hashes.SHA256(), default_backend()
    )

    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize certificate to PEM format
    certificate_pem = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    return private_key_pem, certificate_pem

if __name__ == "__main__":
    
    kys = load_key_from_file('keys/private.pem')
    kkkkk = load_key_from_file('keys/public.pem')
    
    # Generate a self-signed X.509 certificate and private key
    private_key, certificate = generate_self_signed_certificate(kys)

    # Print the private key
    print("Private Key:")
    print(private_key)

    # Print the certificate
    print("\nCertificate:")
    print(certificate)
    
    save_data_to_file(certificate, 'outputs/cert.pem')
    
    cert = x509.load_pem_x509_certificate(certificate, default_backend())
    
    public_key = cert.public_key()
    public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    print('\n')
    print(public_key_pem)
    print('\n')
    print(kkkkk)
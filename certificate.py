from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_self_signed_certificate():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    pubKey = private_key.public_key()
    
    # Define the subject of the certificate (information about the entity being certified)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"EG"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"Cairo"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"Abdo Basha"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Ain Shams University"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Bob"),
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
        private_key, hashes.SHA256(), default_backend()
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

    return private_key_pem, certificate_pem, pubKey

if __name__ == "__main__":
    # Generate a self-signed X.509 certificate and private key
    private_key, certificate, pubKey = generate_self_signed_certificate()

    # Print the private key
    print("Private Key:")
    print(private_key)

    # Print the certificate
    print("\nCertificate:")
    print(certificate)
    
    cert = x509.load_pem_x509_certificate(certificate, default_backend())
    
    public_key = cert.public_key()
    public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    pub = pubKey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print('\n')
    print(public_key_pem)
    print(pub)
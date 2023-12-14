from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# # Various details about who we are. For a self-signed certificate the
# # subject and issuer are always the same.
# subject = issuer = x509.Name([
#     x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
#     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
#     x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
#     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
#     x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
# ])
# cert = x509.CertificateBuilder().subject_name(
#     subject
# ).issuer_name(
#     issuer
# ).public_key(
#     key.public_key()
# ).serial_number(
#     x509.random_serial_number()
# ).not_valid_before(
#     datetime.datetime.now(datetime.timezone.utc)
# ).not_valid_after(
#     # Our certificate will be valid for 10 days
#     datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
# ).add_extension(
#     x509.SubjectAlternativeName([x509.DNSName("localhost")]),
#     critical=False,
# # Sign our certificate with our private key
# ).sign(key, hashes.SHA256())
# # Write our certificate out to disk.
# with open("path/to/certificate.pem", "wb") as f:
#     f.write(cert.public_bytes(serialization.Encoding.PEM))
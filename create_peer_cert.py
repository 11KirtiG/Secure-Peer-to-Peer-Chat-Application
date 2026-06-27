import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

os.makedirs("peer", exist_ok=True)

with open("ca/ca_key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), None)

with open("ca/ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

print("Generating Peer Private Key...")

peer_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "SecurePeer")
])

print("Creating Peer Certificate signed by CA...")

peer_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(peer_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .sign(ca_key, hashes.SHA256())
)

with open("peer/key.pem", "wb") as f:
    f.write(peer_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

with open("peer/cert.pem", "wb") as f:
    f.write(peer_cert.public_bytes(serialization.Encoding.PEM))

print("Peer Certificate Created Successfully.")
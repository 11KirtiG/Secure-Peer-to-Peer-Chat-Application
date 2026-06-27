import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)

def verify_certificate(cert, ca_cert):
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        print("Certificate Verified Successfully.")
        return True
    except:
        print("Certificate Verification Failed.")
        return False

def rsa_encrypt(pub, data):
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(priv, data):
    return priv.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt(key, msg):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, msg.encode(), None)

def aes_decrypt(key, data):
    aes = AESGCM(key)
    nonce = data[:12]
    return aes.decrypt(nonce, data[12:], None).decode()
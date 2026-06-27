# 🔐 Secure Peer-to-Peer Chat Application

A secure peer-to-peer chat application developed in Python that establishes an encrypted communication channel using X.509 certificates without relying on TLS or any pre-built secure communication protocols.

---

## Features

- Certificate Authority (CA) based authentication
- RSA-2048 key generation
- X.509 certificate creation and verification
- TCP Socket communication
- AES-256 GCM encrypted messaging
- SHA-256 hashing
- Secure session key exchange
- Mutual authentication between peers

---

## Technologies Used

- Python
- Socket Programming
- Cryptography Library
- RSA-2048
- X.509 Certificates
- AES-256 GCM
- SHA-256

---

## Project Workflow

1. Create Certificate Authority
2. Generate peer certificates
3. Establish TCP connection
4. Exchange certificates
5. Verify certificates
6. Exchange encrypted session key
7. Create secure channel
8. Start encrypted chat communication

---

## Project Structure

```
create_ca.py
create_peer_cert.py
crypto_core.py
peer.py
ca/
peer/
```

---

## Installation

Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/Secure-Peer-to-Peer-Chat-Application.git
```

Install dependencies

```bash
pip install cryptography
```

Run

```bash
python create_ca.py
python create_peer_cert.py
python peer.py
```

---

## Cryptographic Algorithms

| Algorithm | Purpose |
|-----------|----------|
| RSA-2048 | Key generation & certificate signing |
| X.509 | Digital Certificates |
| SHA-256 | Hashing |
| AES-256 GCM | Secure encrypted communication |

---

## Future Improvements

- GUI using PyQt or Tkinter
- Multi-user chat
- File transfer
- Cross-platform support

---

## Author

Kirti Gupta

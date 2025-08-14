# CSE722-Project-1: Encrypted-Chat

A secure peer-to-peer chat application built with Python using **RSA-OAEP** and **AES-GCM** encryption for message confidentiality, integrity, authenticity, and freshness. 
---

## Features
- **CLI-based chat** 
- **RSA public key exchange** (PEM format, chunked transfer)
- **AES-256 symmetric key exchange** encrypted via RSA-OAEP
- **All post-handshake messages** sent as AES-GCM encrypted **SECMSG** (Secure Message) frames
- **Nonce exchange** for replay prevention & freshness
- **RSA-PSS signatures** for session key integrity verification

---

## ▶️ How to Run (Windows)

### 1. Install Python and Dependencies
- **Python 3.8+** required ([download here](https://www.python.org/downloads/))
- Install required modules:
```bash
py -m pip install --upgrade pip
py -m pip install pycryptodome


### 2.a. Run the application on terminal A (Server Side)
py chat_plain.py listen 5000

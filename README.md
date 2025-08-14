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


## 1. Install Python and Dependencies

- **Python 3.8+** required ([download here](https://www.python.org/downloads/))
- Install required modules:

```bash
py -m pip install --upgrade pip
py -m pip install pycryptodome
```

---

## 2. How to Run the Code (Windows - local host)

### 1.a. Run the application on terminal A (Server Side)
```bash
py chat_plain.py listen 5000
```

### 1.b. Run the application on terminal B (Client Side)
```bash
py chat_plain.py connect 127.0.0.1 5000
```

### 2. Send messages from the client and server sides. These messages will be shared as plaintext. 

### 3.a. Generate the RSA Key-pair on terminal A
```bash
/genkey 
```

### 3.b. Generate the RSA Key-pair on terminal B
```bash
/genkey 
```
### 4.a. To see the generated public key on terminal A
```bash
/showkey
```

### 4.b. o see the generated public key on terminal B
```bash
/showkey 
```

---





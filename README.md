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

## 2. How to Run the Code (Windows - Local Host)

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
### 4.a. To see the generated public key on terminal A (Optional)
```bash
/showkey
```

### 4.b. To see the generated public key on terminal B (Optional)
```bash
/showkey 
```

### 5.a. Now we will send the public Key of A to B on Terminal A
```bash
/sendkey
```

### 5.b. Now we will send the public Key of B to A on Terminal B
```bash
/sendkey
```
### 6.a. To see the public key of B received in terminal A (Optional)
```bash
/showpeerkey
```

### 6.b.  To see the public key of B received in terminal A (Optional)
```bash
/showpeerkey 
```

### 7. Now we will initiate the shared session key sharing process. You may choose terminal A or B. Here we will choose terminal A. So, in Terminal A, type the following command. Here, A will request to B to generate and share the shared session key. B will share it using the following protocol to ensure confidentiality, integrity, and authenticity. 
<img width="462" height="206" alt="image" src="https://github.com/user-attachments/assets/ebbf3306-3808-4bbd-b58a-8f7f33e84933" />

```bash
/initshare
```
### 8. Send messages from the client and server sides. These messages will be shared as encrypted texts. (Encrypted using the shared session Key)

### 9. To terminate the connection use the following command on both terminal A and B
```bash
/quit
```

---
## 1. Install Python and Dependencies

- **Python 3.8+** required ([download here](https://www.python.org/downloads/))
- Install required modules:

```bash
py -m pip install --upgrade pip
py -m pip install pycryptodome
```

---




# CSE722-Project-1: Encrypted-Chat

A secure peer-to-peer chat application built with Python using **RSA** and **AES** encryption for message confidentiality, integrity, authenticity, and freshness. 
---

## Features
- **CLI-based chat** 
- **RSA public key exchange** (PEM format, chunked transfer)
- **AES-256 symmetric key exchange** encrypted via RSA-OAEP
- **All post-handshake messages** sent as AES-GCM encrypted **SECMSG** (Secure Message) frames
- **Nonce exchange** for replay prevention & freshness
- **RSA-PSS signatures & hashing** for session key authenticity and integrity

---


## 1. Install Python and Dependencies

- **Python 3.13** required ([download here](https://www.python.org/downloads/))
- Install required modules:

```bash
py -3.13 -m pip install --upgrade pip
py -3.13 -m pip install pycryptodome
```

---

## 2. How to Run the Code (Windows - Local Host)

### 1.a. Run the application on terminal A (Server Side)
```bash
py -3.13 encrypted-chat.py listen 5000
```

### 1.b. Run the application on terminal B (Client Side)
```bash
py -3.13 encrypted-chat.py connect 127.0.0.1 5000
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

### 9. To terminate the connection, use the following command on both terminal A and B
```bash
/quit
```

---
## 3. Packet Capture

- We used **wireshark** for packet capturing.
- Screen shot - 1 showing the plaintext message captured.
![WhatsApp Image 2025-08-15 at 00 53 08_ea8d3b19](https://github.com/user-attachments/assets/d46270c2-c186-4acc-982d-f24c9d8cbf76)
- Screen shot - 2 showing the encrypted message captured.
![WhatsApp Image 2025-08-15 at 00 53 25_0915bb82](https://github.com/user-attachments/assets/79cd1fbd-a1fa-4dec-a632-dda56ad818ba)

---

## 4. Application Developed By

- Mohammad Fahim
- Partha Bhoumik

---


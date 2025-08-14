#!/usr/bin/env python3

import socket
import threading
import sys
import json
import base64
import os
from typing import Optional, Tuple

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Signature import pss

# ===== Debug toggle =====
DEBUG = True
def dbg(*args, **kwargs):
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)

# ----------------------------
# Chat status
# ----------------------------
sent_count = 0
recv_count = 0
peer_info: Optional[Tuple[str, int]] = None

# ----------------------------
# RSA key storage (6-variable model)
# ----------------------------
# Your keys (local)
my_private_key: Optional[RSA.RsaKey] = None         # 1) private key object
my_public_key_obj: Optional[RSA.RsaKey] = None      # 2) public key object
my_public_key_bytes: Optional[bytes] = None         # 3) public key PEM (bytes for send/show)

# Peer keys (remote)
peer_public_key_obj: Optional[RSA.RsaKey] = None    # 4) peer public key object
peer_public_key_bytes: Optional[bytes] = None       # 5) peer public key PEM (bytes for show)
peer_id: Optional[str] = None                       # 6) optional identifier (unused)

# ----------------------------
# Step 5 session state
# ----------------------------
my_session_key_bytes: Optional[bytes] = None        # the 32-byte shared key we will use
session_established: bool = False

# A's pending state when initiating
pending_nonce_a: Optional[bytes] = None             # A stores its own nonce_A while waiting for KEYRESP
expected_nonce_b: Optional[bytes] = None            # A stores B's nonce_B to send back in KEYCONF

# B's pending state when responding
stored_nonce_b: Optional[bytes] = None              # B stores its nonce_B to verify on KEYCONF

# ----------------------------
# UI helpers
# ----------------------------
def show_status():
    status = "[STATUS] "
    if peer_info:
        status += f"Connected to {peer_info[0]}:{peer_info[1]} | "
    else:
        status += "Not connected | "
    status += f"Sent: {sent_count} | Received: {recv_count}"
    print(status)

def show_commands():
    print("[Commands: /genkey, /sendkey, /showkey, /showpeerkey, /initshare, /showsession, /quit]")

def showsession():
    print("[Session Status]")
    print(f"  session_key_present: {'YES' if my_session_key_bytes else 'NO'}")
    print(f"  session_established: {'YES' if session_established else 'NO'}")
    if pending_nonce_a:
        print("  waiting_for_KEYRESP (A role): YES")
    if expected_nonce_b:
        print("  waiting_to_send_KEYCONF (A role): YES")
    if stored_nonce_b:
        print("  waiting_for_KEYCONF (B role): YES")

# ----------------------------
# RSA helpers
# ----------------------------
def generate_rsa_keys():
    global my_private_key, my_public_key_obj, my_public_key_bytes
    if my_private_key is not None or my_public_key_obj is not None or my_public_key_bytes is not None:
        print("[!] You already generated a key pair. Not overwriting.")
        return
    key = RSA.generate(2048)
    my_private_key = key
    my_public_key_obj = key.publickey()
    my_public_key_bytes = my_public_key_obj.export_key()  # PEM bytes
    print("[+] Generated my RSA keypair.")
    preview = my_public_key_bytes.decode("utf-8").splitlines()[1][:12]
    print(f"    My public key preview: {preview}...")
    dbg("My RSA modulus bits:", my_public_key_obj.size_in_bits())

def show_my_public_key():
    if my_public_key_bytes is None:
        print("[!] No RSA key pair generated yet. Use /genkey.")
        return
    print("[My Public Key]")
    print(my_public_key_bytes.decode("utf-8"))

def exchange_public_keys(sock: socket.socket):
    if my_public_key_bytes is None:
        print("[!] No RSA key pair generated yet. Use /genkey first.")
        return
    print("[*] Sending my RSA PUBLIC key to peer...")
    pem_text = my_public_key_bytes.decode("utf-8")
    for line in pem_text.splitlines():
        send_line(sock, line)

# ----------------------------
# Crypto primitives
# ----------------------------
def rsa_encrypt_with_peer_public(plaintext: bytes) -> bytes:
    if peer_public_key_obj is None:
        raise ValueError("No peer public key available.")
    cipher = PKCS1_OAEP.new(peer_public_key_obj, hashAlgo=SHA256)
    ct = cipher.encrypt(plaintext)
    dbg("RSA-OAEP encrypt -> plaintext len", len(plaintext), "ciphertext len", len(ct))
    return ct

def rsa_decrypt_with_my_private(ciphertext: bytes) -> bytes:
    if my_private_key is None:
        raise ValueError("No local private key available.")
    cipher = PKCS1_OAEP.new(my_private_key, hashAlgo=SHA256)
    pt = cipher.decrypt(ciphertext)
    dbg("RSA-OAEP decrypt -> ciphertext len", len(ciphertext), "plaintext len", len(pt))
    return pt

def sign_over_key_with_my_private(key_bytes: bytes) -> bytes:
    if my_private_key is None:
        raise ValueError("No local private key available for signing.")
    h = SHA256.new(key_bytes)
    signer = pss.new(my_private_key)
    sig = signer.sign(h)
    dbg("PSS sign -> key hash:", h.hexdigest(), "signature len", len(sig))
    return sig

def verify_signature_over_key_with_peer_public(key_bytes: bytes, signature: bytes) -> bool:
    if peer_public_key_obj is None:
        print("[!] Cannot verify signature: peer public key is missing.")
        return False
    h = SHA256.new(key_bytes)
    verifier = pss.new(peer_public_key_obj)
    try:
        verifier.verify(h, signature)
        dbg("PSS verify OK for key hash:", h.hexdigest())
        return True
    except (ValueError, TypeError):
        dbg("PSS verify FAILED for key hash:", h.hexdigest())
        return False

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    blob = nonce + tag + ciphertext
    dbg("AES-GCM encrypt -> key len", len(key), "nonce len", len(nonce),
        "tag len", len(tag), "ciphertext len", len(ciphertext), "blob len", len(blob))
    return blob

def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("Invalid AES-GCM blob.")
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    pt = cipher.decrypt_and_verify(ciphertext, tag)
    dbg("AES-GCM decrypt -> key len", len(key), "nonce len", len(nonce),
        "tag len", len(tag), "ciphertext len", len(ciphertext), "plaintext len", len(pt))
    return pt

# ----------------------------
# Framing helpers
# ----------------------------
def send_framed_lines(sock: socket.socket, begin: str, end: str, text: str, chunk: int = 256):
    send_line(sock, begin)
    for i in range(0, len(text), chunk):
        send_line(sock, text[i:i+chunk])
    send_line(sock, end)

def send_framed_b64(sock: socket.socket, begin: str, end: str, blob: bytes):
    send_framed_lines(sock, begin, end, base64.b64encode(blob).decode(), 64)

# ----------------------------
# Step 5 messages (handshake)
# ----------------------------
def send_keyreq(sock: socket.socket):
    global pending_nonce_a
    if peer_public_key_obj is None:
        print("[!] Need peer public key first. Ask them to /sendkey.")
        return
    pending_nonce_a = os.urandom(16)
    obj = {
        "message": "share the shared key",
        "nonce_A": base64.b64encode(pending_nonce_a).decode()
    }
    plaintext = json.dumps(obj).encode("utf-8")
    dbg("KEYREQ plaintext:", obj)
    ciphertext = rsa_encrypt_with_peer_public(plaintext)
    print("[*] Sending KEYREQ to peer...")
    send_framed_b64(sock, "-----BEGIN KEYREQ-----", "-----END KEYREQ-----", ciphertext)

def send_keyresp(sock: socket.socket, nonce_a_b64: str):
    global my_session_key_bytes, stored_nonce_b
    if my_private_key is None:
        print("[!] Need local RSA keypair to sign. Use /genkey.")
        return
    if peer_public_key_obj is None:
        print("[!] Need peer public key to encrypt response. Ask them to /sendkey.")
        return
    if my_session_key_bytes is not None:
        print("[!] Session key already set locally; not regenerating.")
        return

    my_session_key_bytes = os.urandom(32)
    stored_nonce_b = os.urandom(16)
    dbg("K_session (hex):", my_session_key_bytes.hex())
    dbg("nonce_B (hex):", stored_nonce_b.hex())

    signature = sign_over_key_with_my_private(my_session_key_bytes)
    dbg("signature (b64 first 16):", base64.b64encode(signature).decode()[:16] + "...")

    inner = {
        "nonce_A": nonce_a_b64,
        "nonce_B": base64.b64encode(stored_nonce_b).decode(),
        "sig":     base64.b64encode(signature).decode()
    }
    inner_json = json.dumps(inner).encode("utf-8")
    dbg("KEYRESP inner JSON:", inner)

    inner_blob = aes_gcm_encrypt(my_session_key_bytes, inner_json)
    dbg("KEYRESP inner_blob (b64 len):", len(base64.b64encode(inner_blob)))

    ek = rsa_encrypt_with_peer_public(my_session_key_bytes)
    dbg("KEYRESP ek (RSA ciphertext) len:", len(ek))

    outer = {
        "ek":  base64.b64encode(ek).decode(),
        "aes": base64.b64encode(inner_blob).decode()
    }
    outer_text = json.dumps(outer)
    dbg("KEYRESP outer JSON length:", len(outer_text))
    print("[*] Sending KEYRESP to peer...")
    send_framed_lines(sock, "-----BEGIN KEYRESP-----", "-----END KEYRESP-----", outer_text, 256)

def send_keyconf(sock: socket.socket):
    global expected_nonce_b
    if my_session_key_bytes is None or expected_nonce_b is None:
        print("[!] Missing session key or expected nonce_B; cannot send KEYCONF.")
        return
    dbg("KEYCONF encrypting nonce_B (hex):", expected_nonce_b.hex())
    blob = aes_gcm_encrypt(my_session_key_bytes, expected_nonce_b)
    dbg("KEYCONF blob (b64 len):", len(base64.b64encode(blob)))
    print("[*] Sending KEYCONF to peer...")
    send_framed_b64(sock, "-----BEGIN KEYCONF-----", "-----END KEYCONF-----", blob)
    expected_nonce_b = None

# ----------------------------
# Encrypted Chat (SECMSG)
# ----------------------------
def send_secure_message(sock: socket.socket, text: str):
    """Encrypt a chat message with AES-GCM and send as a framed SECMSG."""
    global my_session_key_bytes
    if my_session_key_bytes is None or not session_established:
        print("[!] Session not established yet; cannot send secure message.")
        return
    # You can wrap the message in JSON to allow future fields (ts, sender, etc.)
    payload = json.dumps({"m": text}).encode("utf-8")
    blob = aes_gcm_encrypt(my_session_key_bytes, payload)
    dbg("SECMSG out (b64 len):", len(base64.b64encode(blob)), "msg len", len(text))
    send_framed_b64(sock, "-----BEGIN SECMSG-----", "-----END SECMSG-----", blob)

# ----------------------------
# Networking (recv loop)
# ----------------------------
def recv_loop(sock: socket.socket) -> None:
    global recv_count, peer_public_key_obj, peer_public_key_bytes
    global pending_nonce_a, expected_nonce_b, my_session_key_bytes, session_established, stored_nonce_b

    buf = b""

    collecting_pem = False
    pem_lines = []

    collecting_keyreq = False
    keyreq_lines = []

    collecting_keyresp = False
    keyresp_lines = []

    collecting_keyconf = False
    keyconf_lines = []

    collecting_secmsg = False
    secmsg_lines = []

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            print("[!] Peer disconnected.")
            break
        buf += chunk

        while True:
            idx = buf.find(b"\n")
            if idx == -1:
                break

            line = buf[:idx]
            buf = buf[idx+1:]
            if line.endswith(b"\r"):
                line = line[:-1]

            text = line.decode("utf-8", errors="replace").strip()

            # ----- PEM PUBLIC KEY collect -----
            if not collecting_pem and text == "-----BEGIN PUBLIC KEY-----":
                collecting_pem = True
                pem_lines = [text]
                continue
            if collecting_pem:
                pem_lines.append(text)
                if text == "-----END PUBLIC KEY-----":
                    pem = "\n".join(pem_lines) + "\n"
                    if peer_public_key_obj is None and peer_public_key_bytes is None:
                        try:
                            peer_public_key_obj = RSA.import_key(pem.encode("utf-8"))
                            peer_public_key_bytes = pem.encode("utf-8")
                            print("[+] Stored PEER's RSA PUBLIC key.")
                            body_line = pem.splitlines()[1] if len(pem.splitlines()) > 1 else ""
                            print(f"    Peer public key preview: {body_line[:12]}...")
                            dbg("Peer RSA modulus bits:", peer_public_key_obj.size_in_bits())
                        except Exception as e:
                            print(f"[!] Failed to import peer public key: {e}")
                    else:
                        print("[!] Peer public key already set. Ignoring new one (no overwrite).")
                    collecting_pem = False
                    pem_lines = []
                    show_status()
                    show_commands()
                    sys.stdout.write("> "); sys.stdout.flush()
                continue

            # ----- KEYREQ collect -----
            if not collecting_keyreq and text == "-----BEGIN KEYREQ-----":
                collecting_keyreq = True
                keyreq_lines = []
                continue
            if collecting_keyreq:
                if text == "-----END KEYREQ-----":
                    try:
                        b64 = "".join(keyreq_lines)
                        ciphertext = base64.b64decode(b64.encode())
                        plaintext = rsa_decrypt_with_my_private(ciphertext)
                        obj = json.loads(plaintext.decode("utf-8"))
                        dbg("KEYREQ received JSON:", obj)
                        msg = obj.get("message", "")
                        nonce_a_b64 = obj.get("nonce_A", "")
                        if msg != "share the shared key" or not nonce_a_b64:
                            print("[!] KEYREQ content invalid.")
                        else:
                            print("[*] Received KEYREQ (A->B). Generating session key and responding...")
                            send_keyresp(sock, nonce_a_b64)
                    except Exception as e:
                        print(f"[!] Failed to process KEYREQ: {e}")
                    collecting_keyreq = False
                    keyreq_lines = []
                    show_status()
                    show_commands()
                    sys.stdout.write("> "); sys.stdout.flush()
                else:
                    keyreq_lines.append(text)
                continue

            # ----- KEYRESP collect -----
            if not collecting_keyresp and text == "-----BEGIN KEYRESP-----":
                collecting_keyresp = True
                keyresp_lines = []
                continue
            if collecting_keyresp:
                if text == "-----END KEYRESP-----":
                    try:
                        outer_text = "".join(keyresp_lines)
                        dbg("KEYRESP outer JSON length:", len(outer_text))
                        outer = json.loads(outer_text)
                        ek_b64  = outer.get("ek", "")
                        aes_b64 = outer.get("aes", "")
                        if not ek_b64 or not aes_b64:
                            print("[!] KEYRESP content invalid.")
                        else:
                            ek = base64.b64decode(ek_b64.encode())
                            k_session = rsa_decrypt_with_my_private(ek)
                            dbg("Recovered K_session (hex):", k_session.hex())

                            inner_blob = base64.b64decode(aes_b64.encode())
                            inner_json = aes_gcm_decrypt(k_session, inner_blob)
                            inner = json.loads(inner_json.decode("utf-8"))
                            dbg("KEYRESP inner JSON:", inner)

                            nonce_a_b64 = inner.get("nonce_A", "")
                            nonce_b_b64 = inner.get("nonce_B", "")
                            sig_b64     = inner.get("sig", "")
                            if not (nonce_a_b64 and nonce_b_b64 and sig_b64):
                                print("[!] KEYRESP inner content invalid.")
                            else:
                                if pending_nonce_a is None:
                                    print("[!] No pending nonce_A; unexpected KEYRESP.")
                                else:
                                    nonce_A_recv = base64.b64decode(nonce_a_b64.encode())
                                    if nonce_A_recv != pending_nonce_a:
                                        print("[!] nonce_A mismatch in KEYRESP.")
                                    else:
                                        signature = base64.b64decode(sig_b64.encode())
                                        if not verify_signature_over_key_with_peer_public(k_session, signature):
                                            print("[!] Signature over session key FAILED.")
                                        else:
                                            if my_session_key_bytes is not None:
                                                print("[!] Session key already set locally; ignoring new KEYRESP.")
                                            else:
                                                print("[+] KEYRESP verified (hybrid). Storing session key and sending KEYCONF...")
                                                my_session_key_bytes = k_session
                                                expected_nonce_b = base64.b64decode(nonce_b_b64.encode())
                                                dbg("Expected nonce_B (hex):", expected_nonce_b.hex())
                                                pending_nonce_a = None
                                                send_keyconf(sock)
                                                session_established = True
                                                print("[✓] Session established (A side).")
                    except Exception as e:
                        print(f"[!] Failed to process KEYRESP: {e}")
                    collecting_keyresp = False
                    keyresp_lines = []
                    show_status()
                    show_commands()
                    sys.stdout.write("> "); sys.stdout.flush()
                else:
                    keyresp_lines.append(text)
                continue

            # ----- KEYCONF collect -----
            if not collecting_keyconf and text == "-----BEGIN KEYCONF-----":
                collecting_keyconf = True
                keyconf_lines = []
                continue
            if collecting_keyconf:
                if text == "-----END KEYCONF-----":
                    try:
                        b64 = "".join(keyconf_lines)
                        blob = base64.b64decode(b64.encode())
                        if my_session_key_bytes is None or stored_nonce_b is None:
                            print("[!] Missing session key or stored nonce_B; cannot process KEYCONF.")
                        else:
                            dbg("KEYCONF blob (b64 len):", len(b64))
                            plaintext = aes_gcm_decrypt(my_session_key_bytes, blob)
                            dbg("Decrypted KEYCONF nonce_B (hex):", plaintext.hex())
                            if plaintext != stored_nonce_b:
                                print("[!] nonce_B mismatch in KEYCONF.")
                            else:
                                print("[✓] KEYCONF verified. Session established (B side).")
                                session_established = True
                                stored_nonce_b = None
                    except Exception as e:
                        print(f"[!] Failed to process KEYCONF: {e}")
                    collecting_keyconf = False
                    keyconf_lines = []
                    show_status()
                    show_commands()
                    sys.stdout.write("> "); sys.stdout.flush()
                else:
                    keyconf_lines.append(text)
                continue

            # ----- SECMSG collect (encrypted chat) -----
            if not collecting_secmsg and text == "-----BEGIN SECMSG-----":
                collecting_secmsg = True
                secmsg_lines = []
                continue
            if collecting_secmsg:
                if text == "-----END SECMSG-----":
                    try:
                        if my_session_key_bytes is None or not session_established:
                            print("[!] Received secure message but no session key established.")
                        else:
                            b64 = "".join(secmsg_lines)
                            blob = base64.b64decode(b64.encode())
                            inner = aes_gcm_decrypt(my_session_key_bytes, blob)
                            obj = json.loads(inner.decode("utf-8"))
                            msg = obj.get("m", "")
                            recv_count += 1
                            print(f"\n<peer-secure> {msg}")
                    except Exception as e:
                        print(f"[!] Failed to decrypt SECMSG: {e}")
                    collecting_secmsg = False
                    secmsg_lines = []
                    show_status()
                    show_commands()
                    sys.stdout.write("> "); sys.stdout.flush()
                else:
                    secmsg_lines.append(text)
                continue

            # ----- Normal plaintext line (pre-session coordination) -----
            recv_count += 1
            print(f"\n<peer> {text}")
            show_status()
            show_commands()
            sys.stdout.write("> "); sys.stdout.flush()

# ----------------------------
# Base chat functions
# ----------------------------
def listen_once(port: int) -> Tuple[socket.socket, Tuple[str, int]]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[*] Listening on 0.0.0.0:{port} ...")
    sock, addr = srv.accept()
    srv.close()
    print(f"[+] Incoming connection from {addr[0]}:{addr[1]}")
    return sock, addr

def connect_to(ip: str, port: int) -> Tuple[socket.socket, Tuple[str, int]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    print(f"[+] Connected to {ip}:{port}")
    return sock, (ip, port)

def send_line(sock: socket.socket, text: str) -> None:
    global sent_count
    sock.sendall((text + "\n").encode("utf-8", errors="replace"))
    sent_count += 1
    show_status()

# ----------------------------
# CLI flow
# ----------------------------
def main(argv):
    global peer_info

    sock: Optional[socket.socket] = None
    if len(argv) >= 2:
        mode = argv[1].lower()
        if mode == "listen" and len(argv) == 3:
            port = int(argv[2])
            sock, peer_info = listen_once(port)
        elif mode == "connect" and len(argv) == 4:
            ip = argv[2]; port = int(argv[3])
            sock, peer_info = connect_to(ip, port)
        else:
            print("Usage: chat_plain.py [listen <port> | connect <ip> <port>]")
            return
    else:
        print("Choose mode: [L]isten or [C]onnect?")
        mode = input("> ").strip().lower()
        if mode.startswith("l"):
            print("Enter port to listen on (e.g., 5000):")
            port = int(input("> ").strip())
            sock, peer_info = listen_once(port)
        elif mode.startswith("c"):
            print("Enter peer IP (e.g., 127.0.0.1):")
            ip = input("> ").strip()
            print("Enter peer port (e.g., 5000):")
            port = int(input("> ").strip())
            sock, peer_info = connect_to(ip, port)
        else:
            print("[!] Unknown choice. Exiting.")
            return

    # Start receiver thread
    t = threading.Thread(target=recv_loop, args=(sock,), daemon=True)
    t.start()

    print("Type messages and press Enter.")
    show_commands()
    show_status()

    while True:
        line = input("> ")
        if not line:
            continue

        cmd = line.strip().lower()

        if cmd == "/quit":
            break

        # Step 4 - RSA public key exchange
        elif cmd == "/genkey":
            generate_rsa_keys()
        elif cmd == "/sendkey":
            exchange_public_keys(sock)
        elif cmd == "/showkey":
            show_my_public_key()
        elif cmd == "/showpeerkey":
            if peer_public_key_bytes:
                print("[Peer Public Key]")
                print(peer_public_key_bytes.decode("utf-8"))
            else:
                print("[!] No peer public key received yet. Ask them to /sendkey.")

        # Step 5 - Initiate as A
        elif cmd == "/initshare":
            send_keyreq(sock)

        elif cmd == "/showsession":
            showsession()

        else:
            # After session establishment -> send SECMSG (encrypted)
            if session_established and my_session_key_bytes:
                send_secure_message(sock, line)
            else:
                # Before session establishment -> plaintext
                send_line(sock, line)

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    print("[*] Bye.")

if __name__ == "__main__":
    main(sys.argv)

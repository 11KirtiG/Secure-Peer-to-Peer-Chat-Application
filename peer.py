import socket
import threading
import os
import struct
import tkinter as tk
from tkinter import scrolledtext
from crypto_core import *
from cryptography.hazmat.primitives import serialization
from cryptography import x509

PORT = 5000

my_cert = load_cert("peer/cert.pem")
my_key = load_key("peer/key.pem")
ca_cert = load_cert("ca/ca_cert.pem")

aes_key = None
sock = None


# -------------------------
# TCP LENGTH PREFIX
# -------------------------
def send_data(data):
    global sock
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)

def recv_exact(n):
    global sock
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def receive_data():
    raw_len = recv_exact(4)
    if not raw_len:
        return None
    msg_len = struct.unpack(">I", raw_len)[0]
    return recv_exact(msg_len)


# -------------------------
# GUI FUNCTIONS
# -------------------------
def display(msg):
    chat_box.config(state=tk.NORMAL)
    chat_box.insert(tk.END, msg + "\n")
    chat_box.config(state=tk.DISABLED)
    chat_box.yview(tk.END)


def send_message():
    global aes_key
    msg = entry_box.get()
    entry_box.delete(0, tk.END)

    if msg == "":
        return

    encrypted = aes_encrypt(aes_key, msg)
    send_data(encrypted)
    display("Kirti: " + msg)


def receive_messages():
    global aes_key
    while True:
        try:
            data = receive_data()
            if not data:
                display("Connection closed.")
                break

            message = aes_decrypt(aes_key, data)
            display("Shaily: " + message)

        except:
            break


# -------------------------
# SECURE HANDSHAKE
# -------------------------
def secure_handshake(initiator):
    global aes_key

    display("Connection Established")

    # 3-way handshake
    if initiator:
        display("Step 1: Sending SYN")
        sock.send(b"SYN")
        sock.recv(1024)
        display("Step 2: Received SYN-ACK")
        sock.send(b"ACK")
        display("Step 3: Sending ACK")
    else:
        sock.recv(1024)
        display("Step 1: Received SYN")
        sock.send(b"SYN-ACK")
        display("Step 2: Sending SYN-ACK")
        sock.recv(1024)
        display("Step 3: Received ACK")

    display("3-Way Handshake Completed\n")

    # Certificate exchange
    if initiator:
        send_data(my_cert.public_bytes(serialization.Encoding.PEM))
        peer_cert_data = receive_data()
    else:
        peer_cert_data = receive_data()
        send_data(my_cert.public_bytes(serialization.Encoding.PEM))

    peer_cert = x509.load_pem_x509_certificate(peer_cert_data)
    verify_certificate(peer_cert, ca_cert)
    display("Certificate Verified Successfully")

    # Session key exchange
    if initiator:
        aes_key = os.urandom(32)
        encrypted = rsa_encrypt(peer_cert.public_key(), aes_key)
        send_data(encrypted)
    else:
        encrypted = receive_data()
        aes_key = rsa_decrypt(my_key, encrypted)

    display("Secure Channel Established\n")
    display("You can start your conversation now\n")


# -------------------------
# LISTEN MODE
# -------------------------
def listen_mode():
    global sock
    
    server = socket.socket()
    server.bind(("0.0.0.0", PORT))
    server.listen(1)

    display("Listening for connection...")
    sock, addr = server.accept()
    display(f"Incoming connection from {addr}")

    secure_handshake(False)
    threading.Thread(target=receive_messages, daemon=True).start()



# CONNECT MODE

def connect_mode():
    global sock
    ip = ip_entry.get()
    sock = socket.socket()
    sock.connect((ip, PORT))

    secure_handshake(True)
    threading.Thread(target=receive_messages, daemon=True).start()



# TKINTER UI

root = tk.Tk()
root.title("Secure P2P Chat")

chat_box = scrolledtext.ScrolledText(root, state=tk.DISABLED, width=60, height=20)
chat_box.pack(pady=10)

entry_box = tk.Entry(root, width=50)
entry_box.pack(side=tk.LEFT, padx=10, pady=10)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack(side=tk.LEFT)

ip_entry = tk.Entry(root, width=15)
ip_entry.pack(side=tk.LEFT, padx=5)

connect_button = tk.Button(root, text="Connect", command=connect_mode)
connect_button.pack(side=tk.LEFT)

listen_button = tk.Button(root, text="Listen", command=listen_mode)
listen_button.pack(side=tk.LEFT)

root.mainloop()
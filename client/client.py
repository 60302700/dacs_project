import sys, requests
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import PublicFormat, PrivateFormat, Encoding, NoEncryption
import uuid
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import io
import json
from flask import jsonify
import random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


SERVER = "http://127.0.0.1:5000"


def pin_generator():
    chars = "abcdefghijklmnopqrstuvwxzy0123456789"
    return "".join([random.choice(chars) for i in range(6)])

def register(username, device_id):
    r = requests.post(f"{SERVER}/register", json={"username": username, "device_id": device_id})
    print(r.json())

def login(username, device_id):
    r = requests.post(f"{SERVER}/login/request", json={"username": username, "device_id": device_id})
    data = r.json()
    print("Challenge from server:", data)
    response = data["challenge"]  # placeholder for Phase 1
    r2 = requests.post(f"{SERVER}/login/response",
                       json={"username": username, "session": data["session"], "response": response})
    print(r2.json())

def privateKeyAES(private_pem: bytes, user,filename: str = None) -> None:

    # Generate random PIN
    pin = pin_generator()

    # Generate random salt and nonce
    salt = os.urandom(16)  # 128-bit salt
    nonce = os.urandom(12)  # 96-bit nonce for AESGCM

    # Derive a 32-byte key (AES-256) from PIN using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = kdf.derive(pin.encode())

    # Encrypt the private key
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_pem, None)

    # Combine salt + nonce + ciphertext
    encrypted_blob = salt + nonce + ciphertext
    b64_encrypted = base64.b64encode(encrypted_blob).decode('utf-8')

    data = {"Private_Key" : b64_encrypted , "Pin" : str(pin), "user" : user}

    # Save to file if filename provided
    if not filename:
        filename = f"private_key_enc_{uuid.uuid4().hex}.json"
    with open(filename, "w") as f:
        json.dump(data,f)
    print("File Generated")



def gen_public_private_key(user):
    try:
        private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo)
        name = str(uuid.uuid4())+".json"
        privateKeyAES(private_pem,user,name)
        
        file={user: {"Pub_key":public_pem.decode("utf-8"),"user":user,"device_id":["id_123234231"]} }
        
        res = requests.post(f"{SERVER}/recive_public_key", json=file)
        if not res.ok:
            raise Exception("Request Not Successfull Executed")
        print(f"Saved Private Key as f{name}.pem")
    except Exception as e:
        print(f"Error Occured : f{str(e)}")
    


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python client.py [register|login] <username> <device_id>")
        sys.exit(1)

    action, username, device_id = sys.argv[1], sys.argv[2], sys.argv[3]
    if action == "register":
        register(username, device_id)
    elif action == "login":
        login(username, device_id)
    elif action == "get_keys":
        gen_public_private_key(username)

import os, json, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_secret(plaintext: bytes, pin: str, out_file: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    key = kdf.derive(pin.encode())
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    blob = {
        "kdf": "pbkdf2",
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    with open(out_file, "w") as f:
        json.dump(blob, f, indent=2)
    print(f"Encrypted secret stored at {out_file}")

def decrypt_secret(pin: str, in_file: str) -> bytes:
    with open(in_file) as f:
        blob = json.load(f)
    salt = base64.b64decode(blob["salt"])
    iv = base64.b64decode(blob["iv"])
    ciphertext = base64.b64decode(blob["ciphertext"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    key = kdf.derive(pin.encode())
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext

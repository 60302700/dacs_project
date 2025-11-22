import os
import sys
import json
import base64
import requests
from pick import pick
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.asymmetric import padding

BASE_URL = "http://127.0.0.1:5000"
SESSION = requests.Session()


# ----------------------
# Helper Functions
# ----------------------
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def load_encrypted_private_key(file_path: str):
    """Load encrypted private key and PIN from local JSON file."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        username = data["username"]
        pin = data["Pin"]
        blob = base64.b64decode(data["Private_Key"])
        return username, pin, blob
    except FileNotFoundError:
        title = "Login File Not Found , Would Like To Register ?"
        option = pick(["Yes","No"], title)
        if option[0] == "Yes":
            register()
        else:
            return
    except Exception as e:
        print(f"[Error] Failed to read encrypted private key: {e}")
        


def decrypt_private_key(blob: bytes, pin: str) -> bytes:
    """Decrypt AESGCM-encrypted private key."""
    try:
        salt = blob[:16]
        nonce = blob[16:28]
        ciphertext = blob[28:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
        )
        key = kdf.derive(pin.encode())
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted
    except Exception as e:
        print(f"[Error] Failed to decrypt private key: {e}")
        sys.exit(1)


def load_private_key_from_bytes(private_key_bytes: bytes):
    """Load DER-encoded private key bytes."""
    try:
        # Remove PEM framing if present
        pem_data = private_key_bytes.replace(
            b"-----BEGIN PRIVATE KEY-----\n", b""
        ).replace(
            b"\n-----END PRIVATE KEY-----\n", b""
        ).replace(b"\n", b"")
        der_bytes = base64.b64decode(pem_data)
        return load_der_private_key(der_bytes, password=None)
    except Exception as e:
        print(f"[Error] Failed to load private key: {e}")
        sys.exit(1)


def request_challenge(username: str):
    """Request a challenge from the server."""
    try:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        resp = SESSION.post(
            f"{BASE_URL}/challenge",
            json={"username": username},
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json().get("challenge")
    except Exception as e:
        print(f"[Error] Challenge request failed: {e}")
        sys.exit(1)


def decrypt_challenge(private_key, challenge_b64: str) -> str:
    """Decrypt server challenge using RSA OAEP private key."""
    try:
        challenge_bytes = base64.b64decode(challenge_b64)
        plaintext = private_key.decrypt(
            challenge_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode()
    except Exception as e:
        print(f"[Error] Failed to decrypt challenge: {e}")
        sys.exit(1)

def verify_challenge(answer,username):
    device_id = "4425a739254f0f72daec1ed96abcd78d5e6aba5d03b6865b83a3fb86f9853ab3"
    x = SESSION.post(f"{BASE_URL}/challenge/verify",data={"username":username,"answer":answer,"deviceid":device_id},allow_redirects=False)
    #print(SESSION.cookies.get_dict())

# ----------------------
# Actions
# ----------------------
def login():
    try:
        clear_screen()
        print("[Login] Starting challenge-response login...")

        username, pin, encrypted_blob = load_encrypted_private_key("johnde.json")
        private_key_bytes = decrypt_private_key(encrypted_blob, pin)
        private_key = load_private_key_from_bytes(private_key_bytes)

        challenge_b64 = request_challenge(username)
        response = decrypt_challenge(private_key, challenge_b64)

        verify_challenge(response,username)
        print(f"[Success] Logged In")
        input("Press Enter to continue...")
    except Exception as e:
        print(f"[Error] {str(e)}")


def register():
    clear_screen()
    print("[Register] Functionality not implemented yet.")
    input("Press Enter to continue...")


def quit_program():
    clear_screen()
    print("Exiting...")
    sys.exit(0)


# ----------------------
# Menu Loop
# ----------------------
def main():
    options = {
        "Login": login,
        "Register": register,
        "Exit": quit_program,
    }
    title = "CryptoLogin"

    while True:
        option = pick(list(options.keys()), title)
        action = options.get(option[0])
        if action:
            action()


if __name__ == "__main__":
    main()

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
from device_fingerprinting.production_fingerprint import ProductionFingerprintGenerator
from tinydb import TinyDB , Query
import pyperclip
BASE_URL = "http://127.0.0.1:5000"
SESSION = requests.Session()

ClientDB = TinyDB("clientsidedb.json")
Creds = ClientDB.table("credentials")

CredQ = Query()

# ----------------------
# Helper Functions
# ----------------------
from pick import pick

def loginCredentails():
    clear_screen()
    print("accessing db")
    all_docs = Creds.all()
    print(all_docs)
    count = len(all_docs)

    # If exactly one credential document, return it
    if count == 1:
        only_doc = all_docs[0]
        return Creds.get(doc_id=only_doc.doc_id)

    # If more than one, show a pick menu
    options = []
    for doc in all_docs:
        # Make a label for each option. Adjust what you show (filename, username, etc.)
        label = f"{doc.get('filename')}"
        options.append(label)

    title = "Select Credentials To Use"
    selected, index = pick(options, title)
    # Get the corresponding document (based on index)
    chosen_doc = all_docs[index]
    return Creds.get(doc_id=chosen_doc.doc_id)
        
# "LogOut": logout,

def registerDevice(username):
    clear_screen()
    try:
        did = ""
        while len(did) != 128:
            did = input("[Input] Enter Device id To Register its 128 chars long: ")

        data = SESSION.post(f"{BASE_URL}/register/device",json={"username":username,"deviceid":did})
        if data.ok:
            print(data.json().get("msg"))
            input("[Enter]")
    except Exception as e:
        print(f"[Err] {str(e)}")
        input("[Enter]")

def removeRegisteredDevice(username):
        clear_screen()
        try:
            index = None
            while True:
                data = SESSION.post(f"{BASE_URL}/register/device/all",json={"username":username})
                # print(data.json())
                devs = data.json()["msg"]
                if data.ok:
                    for k in devs:
                        print(f"{devs.index(k)} : {k}")
                    index = input("[Input] Enter Device id To Register its 128 chars long: ")
                    if index.strip().lower() == "exit":
                        break
                    elif int(index) in range(len(devs)):
                        data = SESSION.post(f"{BASE_URL}/register/device/delete",json={"username":username,"deviceid":devs[index]})
                        msg = data.json()["msg"]
                        if data.ok:
                            print(msg)
                            input("[Enter]")
        except Exception as e:
            print(f"{str(e)}")
            input("[Enter]")

def logout(username):
    clear_screen()
    SESSION.post(f"{BASE_URL}/logout",json={"username":username})

def WebuiToken(username):
    clear_screen()
    try:
        requestData = SESSION.post(f"{BASE_URL}/tokengen",json={"username":username})
        data = requestData.json() 
        print("[Info] Generating WebToken")       
        if requestData.ok:
            print(f"New Web Token: {data["msg"]}")
            input("[Enter] Press Enter To Continue")
        else:
            raise Exception(f"Request Err On Server Side Code: {requestData.status_code}")
    except Exception as e:
        print(f"[Error] {str(e)}")
        input("Error")

def getAllToken(username):
    try:
        clear_screen()
        while True:
            clear_screen()
            data = SESSION.post(f"{BASE_URL}/tokengen/all",json={"username":username})
            data = data.json().get("msg")
            if len(data) == 0:
                print("[INFO] No Web Sessions")
                input("[Enter]")
                return
            for k in data:
                print(f"Session {data.index(k)}:{k}")
            index = input("[Select] Select Session:")
            if str(index).strip().lower() == "exit":
                break
            if int(index) not in range(len(data)):
                continue
            else:
                stat = SESSION.post(f"{BASE_URL}/tokengen/delete",json={"username":username,"session":data[int(index)]})
                if stat.ok:
                    msg = stat.json().get('msg')
                    print(f"Session Deleted {msg}")
    except Exception as e:
        print(f"{str(e)}")
        input("[Enter] Continue")

def saveFile(data):
    username = data.get("username")
    if not Creds.search(CredQ.username == username):
        Creds.insert(data)


def genDeviceFingerprint():
    clear_screen()
    # Generate device fingerprint
    generator = ProductionFingerprintGenerator()
    fingerprint_data = generator.generate_fingerprint()
    return fingerprint_data['fingerprint_hash']

def displaygenDeviceFingerprint():
    copy = None
    generator = ProductionFingerprintGenerator()
    DevID = generator.generate_fingerprint()['fingerprint_hash']
    while copy not in ['y','n']:
        clear_screen()
        print(f"Device Fingerprint: {DevID}")
        copy = input("Would You Like To Copy The ID? (y/n)").lower()
        if copy == 'y':pyperclip.copy(DevID)    
        else: return

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def load_encrypted_private_key():
    """Load encrypted private key and PIN from local JSON file."""
    try:
        data = loginCredentails()
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
    device_id = genDeviceFingerprint()
    x = SESSION.post(f"{BASE_URL}/challenge/verify",data={"username":username,"answer":answer,"deviceid":device_id},allow_redirects=False)
    print(x.cookies)
    input("Enter")

# ----------------------
# Actions
# ----------------------
def login():
    try:
        clear_screen()
        print("[Login] Starting challenge-response login...")
        username, pin, encrypted_blob = load_encrypted_private_key()
        private_key_bytes = decrypt_private_key(encrypted_blob, pin)
        private_key = load_private_key_from_bytes(private_key_bytes)
        challenge_b64 = request_challenge(username)
        response = decrypt_challenge(private_key, challenge_b64)
        verify_challenge(response,username)
        print(f"[Success] Logged In")
        cookies = SESSION.cookies.get_dict()
        options = {
        "LogOut": logout,
        "Register A Device": registerDevice,
        "Remove A Device":removeRegisteredDevice,
        "WebUI Access Token":WebuiToken,
        "See All Tokens":getAllToken,
        "See Device ID":displaygenDeviceFingerprint,
    }
        title = "CryptoLogin"

        while cookies == SESSION.cookies.get_dict():
            option = pick(list(options.keys()), title)            
            action = options.get(option[0])
            if action == displaygenDeviceFingerprint:
                action()
            elif action == logout:
                action(username)
                return
            elif action:
                action(username)
    except Exception as e:
        print(f"[Error] {str(e)}")
        input("[Enter To Continue]")


def register():
    clear_screen()
    try:
        print("[System] Generating DeviceID")
        device_id = genDeviceFingerprint()
        username = input("Enter Username: ")
        loginFile = SESSION.post(f"{BASE_URL}/register",json={"username":username,"device_id":device_id})
        print(loginFile)
        data = loginFile.json()
        data = data.get('file')
        data['filename'] = f"{data['username']}.clog"
        saveFile(data)
    except Exception as e:
        print(f"[Err] {str(e)}")
        input("Press Enter To Continue")


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
        "Show Device ID":displaygenDeviceFingerprint,
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

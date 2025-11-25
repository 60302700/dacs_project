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
from getmac import get_mac_address as gma
from hashlib import sha256
from requests.exceptions import JSONDecodeError
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives.serialization import (
    PublicFormat,
    PrivateFormat,
    Encoding,
    NoEncryption,
    load_pem_public_key
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import uuid

BASE_URL = "http://127.0.0.1:5000"
SESSION = requests.Session()

ClientDB = TinyDB("clientsidedb.json")
Creds = ClientDB.table("credentials")
Sessions = ClientDB.table('sessions')

CredQ = Query()

# ----------------------
# Helper Functions
# ----------------------
from pick import pick

def validatesession():
    clear_screen()
    session = Sessions.all()
    if len(session) == 0:
        return False
    print("Session Previous Session Dectected Using")
    session = session[0]
    s = SESSION.post(f"{BASE_URL}/dashboard",cookies=session)
    if s.url.split("/")[-1] != "dashboard":
        print("Session Invalid")
        return False
    print("Session Valid")
    input("[Enter]")
    return True

import time

def chat_loop(username="User"):
    clear_screen()
    """The main persistent chat interaction loop."""
    print(f"\n--- 👋 Welcome to Dummy Chat, {username}! ---")
    print("Type 'exit' or 'quit' to end the session.")
    
    while True:
        # Get user input
        user_input = input(f"{username} > ").strip()
        
        # Check for exit commands
        if user_input.lower() in ['exit', 'quit']:
            print("\n🚪 Logging out. Goodbye!")
            break
        
        # Check for specific interaction triggers
        if user_input.lower() == 'hi':
            response = "Hello there! How can I help you today?"
        elif user_input.lower() == 'hello':
            response = "Greetings! What's on your mind?"
        elif user_input.lower() == 'how are you':
            response = "I'm just a dummy chat bot, but thanks for asking!"
        else:
            # Default response for anything else
            response = f"You said: '{user_input}'. I don't understand that command."

        # Display the bot's response
        print(f"🤖 Bot > **{response}**")

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
    except JSONDecodeError:
        print("[Error] No Json Dectected  !!SESSION MIGHT BE INVALID!!")
        input("[Enter]")
        return "logout"
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
        except JSONDecodeError:
            print("[Error] No Json Dectected  !!SESSION MIGHT BE INVALID!!")
        except Exception as e:
            print(f"{str(e)}")
            input("[Enter]")

def logout(username):
    clear_screen()
    Sessions.truncate()
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
    except JSONDecodeError:
        print("[Error] No Json Dectected  !!SESSION MIGHT BE INVALID!!")
        input("[Enter]")
        return "logout"
    except Exception as e:
        print(f"[Error] {str(e)}")
        input("[Error]")

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
    except JSONDecodeError:
        print("[Error] No Json Dectected  !!SESSION MIGHT BE INVALID!!")
        input("[Enter]")
        return "logout"
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
    cipher = sha256()
    cipher.update(gma().encode())
    return cipher.digest().hex()

def displaygenDeviceFingerprint():
    copy = None
    DevID = genDeviceFingerprint()
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
    if SESSION.cookies.get_dict().get("session_token"):
        input("[Enter] Login Succesfull")
        return
    input("[Error] Login Invalid")
    return

# ----------------------
# Actions
# ----------------------
def login(sessionExsist=False):
    try:
        clear_screen()
        username, pin, encrypted_blob = load_encrypted_private_key()
        if not sessionExsist:
            print("[Login] Starting challenge-response login...")
            private_key_bytes = decrypt_private_key(encrypted_blob, pin)
            private_key = load_private_key_from_bytes(private_key_bytes)
            challenge_b64 = request_challenge(username)
            response = decrypt_challenge(private_key, challenge_b64)
            verify_challenge(response,username)
            print(f"[Success] Logged In")
            cookies = SESSION.cookies.get_dict()
            Sessions.truncate()
            Sessions.insert(cookies)
        options = {
        "LogOut": logout,
        "Register A Device -  Adds Devices To Trust List": registerDevice,
        "Remove A Device - Removes Devices From Trust List":removeRegisteredDevice,
        "WebUI Access Token - Generates A Token For Web Session":WebuiToken,
        "WebUI Token Session Controll":getAllToken,
        "Chat - dummy chat system":chat_loop,
        "See Device ID":displaygenDeviceFingerprint,
    }
        title = f"CryptoLogin   \n Session:{SESSION.cookies.get_dict().get('session_token')}\n\n"
        invalidsess = None
        while invalidsess != "logout":
            option = pick(list(options.keys()), title)            
            action = options.get(option[0])
            if action == displaygenDeviceFingerprint:
                action()
            elif action == logout:
                invalidsess = action(username)
                return
            elif action:
                invalidsess = action(username)
    except Exception as e:
        print(f"[Error] {str(e)}")
        input("[Enter To Continue]")

def pin_generator():
    return hex(int.from_bytes(os.urandom(32)))[2:]

def privateKeyAES(private_pem: bytes, user,filename: str = None) -> dict:
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
    if not filename:
        filename = f"private_key_enc_{uuid.uuid4().hex}.clog"
    data = {"Private_Key" : b64_encrypted , "Pin" : str(pin), "username" : user , "filename":filename}

    return data


def gen_public_private_key(user:str,Device_id) -> tuple:
    try:
        private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
        print("b")
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
        data = privateKeyAES(private_pem,user,name)
        print("a")
        SESSION.post(f"{BASE_URL}/PublicKey",json={"user":user,"publicKey":public_pem.decode("utf-8"),"Device_id":Device_id})
        print("c")
        return data

    except Exception as e:
        return {"status": "Err", "msg":f"{str(e)}"}

def register():
    clear_screen()
    try:
        print("[System] Generating DeviceID")
        device_id = genDeviceFingerprint()
        username = input("Enter Username: ")
        loginFile = SESSION.post(f"{BASE_URL}/register",json={"username":username,"device_id":device_id})
        data = gen_public_private_key(username,device_id)
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
    validsess = validatesession()
    if validsess:
        login(validsess)
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

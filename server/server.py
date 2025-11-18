from flask import Flask, request, jsonify, make_response
from tinydb import TinyDB, Query
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    PublicFormat, PrivateFormat, Encoding, NoEncryption
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import uuid
import os
import json
import base64
import random
import requests
import datetime
import sys


app = Flask(__name__)

DB = TinyDB("Users.json")
challenge_db = TinyDB("challenges.json")

users = DB.table("users")
login_sessions = DB.table("Sessions")
public_key_db = DB.table("Public_Keys")


Challenge = Query()
UserQ = Query()
SessionQ = Query()
PubKeyQ = Query()


SERVER = "http://127.0.0.1:5000"
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    device_id = data['device_id']

    User = Query()
    existing_user = users.get(User.username == username)

    if existing_user is None:
        new_doc = {
            "username": username,
            "devices": [device_id]
        }
        users.insert(new_doc)

    else:
        devices = existing_user.get("devices", [])
        if device_id not in devices:
            devices.append(device_id)
            users.update({"devices": devices}, User.username == username)

    return jsonify({"status": "ok", "Message":"Successfull Registrered"}), 201


@app.route('/login/request', methods=['POST'])
def login_request():
    data = request.json
    username = data['username']
    device_id = data['device_id']
    if username not in users or device_id not in users[username]["devices"]:
        return jsonify({"error": "User or device not registered"}), 400
    session_id = str(uuid.uuid4())
    challenge = str(uuid.uuid4())
    login_sessions[session_id] = {"username": username, "challenge": challenge}
    return jsonify({"session": session_id, "challenge": challenge}), 200

@app.route('/login/response', methods=['POST'])
def login_response():
    data = request.jsonss
    session_id = data['session']
    response = data['response']
    if session_id not in login_sessions:
        return jsonify({"error": "invalid session"}), 400
    challenge = login_sessions[session_id]["challenge"]
    if response == challenge:
        return jsonify({"status": "login success"}), 200
    return jsonify({"status": "login failed"}), 403

def rec_public_key():
    try:
        json = request.get_json()
        print(json)
        id = list(json.keys())[0]
        print(id)
        data = json.get(id)
        print(data)
        document = {
            'record_id':id,
            'public_key':data.get("Pub_key"),
            "device":data.get("device_id")
        }
        public_key_db.upsert(document,PubKeyQ.record_id == document.get("record_id"))
        return jsonify({"status":"OK","msg" :"successfully add to db"}) , 200
    except Exception as e:
        return jsonify({"status":"Err","msg":str(e)}), 500


##### PHASE 4 BY ERLAND #####

# For testing the server, run the file and open http://127.0.0.1:5000/test in the browser
@app.route("/test", methods=["GET"])
def test_route():
    return jsonify({"message": "Server is running!"})


def pin_generator():
    chars = "abcdefghijklmnopqrstuvwxzy0123456789"
    return "".join([random.choice(chars) for i in range(6)])


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
        data = privateKeyAES(private_pem,user,name)
        
        file={user: {"Pub_key":public_pem.decode("utf-8"),"user":user,"device_id":["id_123234231"]} }
        
        res = requests.post(f"{SERVER}/recive_public_key", json=file)
        if not res.ok:
            raise Exception("Request Not Successfull Executed")
        print(f"Saved Private Key as f{name}.pem")
    except Exception as e:
        print(f"Error Occured : f{str(e)}")


def privateKeyAES(private_pem: bytes, user,filename: str = None) -> None:
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
    
    return {filename:data}



if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, jsonify, make_response,Response
from tinydb import TinyDB, Query
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
import os
import base64


app = Flask(__name__)

DB = TinyDB("Database.json")

users = DB.table("users")
login_sessions = DB.table("Sessions")
public_key_db = DB.table("Public_Keys")
challengedb = DB.table("Challenge")

UserQ = Query()
SessionQ = Query()
PubKeyQ = Query()
ChallengeQ = Query()


LoginPage = open("static/login.html").read()
registerPage = open("static/register.html").read()
# stylecss = open("static/style.css").read()
# jsScript = open("static/script.js").read()

SERVER = "http://127.0.0.1:5000"

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data['username']
        device_id = data['device_id']
        User = Query()
        existing_user = users.get(User.username == username)
        if existing_user is not None:
            return jsonify({"status": "Err", "msg":"User Already Exsists/Registered"}), 201
    
        if existing_user is None:
            new_doc = {
                "username": username,
                "devices": [device_id]
            }
            users.insert(new_doc)
        
        """else:
            devices = existing_user.get("devices", [])
            if device_id not in devices:
                devices.append(device_id)
                users.update({"devices": devices}, User.username == username)"""
        
        data =  gen_public_private_key(username)
        return jsonify({"status": "ok", "msg":"Successfull Registrered","file":data}), 201
    except Exception as e:
        print(f"{str(e)}")

@app.route('/login/request', methods=['POST'])
def login_request():
    data = request.json
    username = data['username']
    device_id = data['device_id']
    print(data)
    if username not in users or device_id not in users[username]["devices"]:
        return jsonify({"status" : "Err","msg": "User or device not registered"}), 400
    session_id = str(uuid.uuid4())
    challenge = str(uuid.uuid4())
    login_sessions[session_id] = {"username": username, "challenge": challenge}
    return jsonify({"session": session_id, "challenge": challenge}), 200

@app.route('/login/response', methods=['POST'])
def login_response():
    data = request.jsons
    session_id = data['session']
    response = data['response']
    if session_id not in login_sessions:
        return jsonify({"error": "invalid session"}), 400
    challenge = login_sessions[session_id]["challenge"]
    if response == challenge:
        return jsonify({"status": "login success"}), 200
    return jsonify({"status": "login failed"}), 403

def rec_public_key(publicKey,user,Device_id):
    #rec_public_key(public_pem.decode("utf-8"),user,"id_123234231")
    try:
        document = {
            'record_id':user,
            'public_key':publicKey,
            "device":Device_id,
        }
        public_key_db.upsert(document,PubKeyQ.record_id == document.get("record_id"))
        return True
    except Exception as e:
        return jsonify({"status":"Err","msg":str(e)}), 400

##### PHASE 4 BY ERLAND #####

###changes made by Abdullah###
@app.route("/challenge", methods=["POST"])
def challenge():
    try:
        print(request.json)
        username = request.json["username"]
        doesUserExsist = checkUser(username)
        print("username")
        print(doesUserExsist)
        if not doesUserExsist:
            return {"status":"Err","msg":f"{str(e)}"} , 400
        PublicKey = getPublicKey(username)
        print(PublicKey)
        plaintext = os.urandom(80).hex()
        public_key = load_pem_public_key(PublicKey.encode())

        encrypted = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("ecrypted succesfull")
        encrypted = base64.b64encode(encrypted).decode()
        challengedb.insert({"plaintext" : plaintext, "encrypted" : encrypted})
        return {"status":"ok","msg":"Server Challenge","challenge":encrypted}, 201
    except Exception as e:
        return {"status":"Err","msg":f"{str(e)} hmm "} , 400


@app.route("/challenge/verify",methods=["POST"])
def verify():
    try:
        answer = request.json["answer"]
        username = request.json["username"]
        result = checkChallenge(answer)
        if result is None:
            return False
        else:
            return genSession(username)
    except Exception as e:
        return str(e)
    
# For testing the server, run the file and open http://127.0.0.1:5000/test in the browser

@app.route("/test", methods=["GET"])
def test_route():
    return jsonify({"message": "Server is running!"})

def pin_generator():
    return hex(int.from_bytes(os.urandom(32)))[2:]


def gen_public_private_key(user:str) -> tuple:
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
        
        rec_public_key(public_pem.decode("utf-8"),user,"id_123234231")

        return data

    except Exception as e:
        return {"status": "Err", "msg":f"{str(e)}"}
        
def getPublicKey(username):
    try:
        data = public_key_db.get(PubKeyQ.record_id ==  username)
        return data.get("public_key")
    except Exception as e:
        return f"{str(e)}"

def checkUser(username):
    try:
        return users.get(UserQ.username == username)
    except Exception as e:
        return str(e)


def checkChallenge(text):
    information = challengedb.get(ChallengeQ.plaintext == text)
    if information is None:
        return False
    return True

def genSession(username):
    sessionid = uuid.uuid4().__str__()
    data = {"username":username,"session_id":sessionid}
    login_sessions.insert(data)
    return sessionid

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
        filename = f"private_key_enc_{uuid.uuid4().hex}.json"
    data = {"Private_Key" : b64_encrypted , "Pin" : str(pin), "username" : user , "filename":filename}

    return data

@app.route("/",methods=['GET'])
def login():
    return Response(LoginPage , mimetype='text/html')

@app.route("/register",methods=['GET'])
def registerhtml():
    return Response(registerPage , mimetype='text/html')

if __name__ == '__main__':
    app.run(debug=True)
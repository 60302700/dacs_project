from flask import Flask, request, jsonify, make_response , Response, url_for , redirect, render_template
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
import time
import base64
import threading
import logging
from datetime import datetime

# File name = current date, e.g., 2025-11-21.log
log_filename = datetime.now().strftime("%Y-%m-%d") + ".log"

logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,             # or DEBUG if you want more details
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = Flask(__name__)

db_lock = threading.Lock()
DB = TinyDB("Database.json")


users = DB.table("users")
login_sessions = DB.table("Sessions")
public_key_db = DB.table("Public_Keys")
challengedb = DB.table("Challenge")
RegisterToken = DB.table("Token")

UserQ = Query()
SessionQ = Query()
PubKeyQ = Query()
ChallengeQ = Query()
TokenQ = Query()

LoginPage = open("static/login.html").read()
registerPage = open("static/register.html").read()
# stylecss = open("static/style.css").read()
# jsScript = open("static/script.js").read()

SERVER = "http://127.0.0.1:5000"

EXEMPT_ROUTES = ['login', 'register', 'challenge', 'verify','registerhtml','genWebSession','PublicKey','rec_public_key','/register/device','registedevice']

@app.before_request
def checkSession():
    endpoint = request.endpoint
    #print(endpoint)
    if endpoint in EXEMPT_ROUTES or endpoint is None or request.path.startswith("/static/"):return
    session_token = request.cookies.get("session_token")
    session = GetSession(session_token)
    if not session:
        return redirect(url_for('login'))

@app.route('/register/device/all',methods=["POST"])
def showAllDevices():
    try:
        username = request.json["username"]
        if checkUser(username):
            return jsonify({"status":"ok","msg": showAllDevicesFromUser(username)}), 200
    except Exception as e:
        return jsonify({"status":"Err","msg":f"{str(e)}"}),400
    

@app.route('/register/device',methods=['POST'])
def registedevice():
    try:
        username = request.json["username"]
        deviceid = request.json["deviceid"]
        print(username,deviceid)
        addDeviceTouser(username,deviceid)
        return jsonify({"status":"ok","msg":"Device Added"}), 200
    except Exception as e:
        return jsonify({"status":"Err","Msg":f"{str(e)}"}), 400

@app.route("/register/device/delete",methods=["POST"])
def removeDevice():
    try:
        username = request.json["username"]
        deviceid = request.json["deviceid"]
        DoesUserExsist = checkUser(username)
        if DoesUserExsist:
            status = removeDeviceFromuser(username,deviceid)
            if status ==  None:
                return jsonify({"status":"ok","msg":"One Device Remaining Can't Delete"})
            if status:
                return jsonify({"status":"ok","msg":"Device Removed"}), 200
            return jsonify({"status":"ok","msg":"Device Not Found"}), 400
    except Exception as e:
        return jsonify({"status":"Err","msg":f"{str(e)}"}), 400
    

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data['username']
        device_id = data['device_id']
        with db_lock:
            existing_user = users.get(UserQ.username == username)
        if len(username) == 0:
            return jsonify({"status": "Err", "msg":"No User Exsist"}), 400
        if existing_user is not None:
            logging.info(f"""{{"status": "Err", "msg":"User Already Exsists/Registered"}} 201""")
            return jsonify({"status": "Err", "msg":"User Already Exsists/Registered"}), 300
    
        if existing_user is None:
            new_doc = {
                "username": username,
                "devices": [device_id]
            }
            with db_lock:
                users.insert(new_doc)
    
        logging.info(f"""{{"status": "ok", "msg":"Successfull Registrered"}} , 201""")
        return jsonify({"status": "ok", "msg":"Successfull Registrered","user":username,"device_id":device_id}), 201
    except Exception as e:
        logging.info(f"{str(e)}")
        return jsonify({"status": "Err", "msg": "Internal Server Error"}), 500


@app.route("/PublicKey",methods=["POST"])
def rec_public_key():
    try:
        publicKey = request.json["publicKey"]
        user = request.json["user"]
        Device_id = request.json["Device_id"]
        userexsist = public_key_db.get(PubKeyQ.record_id == user)
        if userexsist is not None:
            return jsonify({"status": "Err", "msg":"User Already Exsists/Registered"}), 300
        if checkUser(user):
            document = {
            'record_id':user,
            'public_key':publicKey,
            "device":[Device_id],
        }
            with db_lock:
                public_key_db.upsert(document,PubKeyQ.record_id == document.get("record_id"))
            logging.info(f"Added PublicKey for user {user}")
            return jsonify({"status":"ok","msg":"Public Key Generated"}), 200
    except Exception as e:
        logging.info(f"""{"status":"Err","msg":str(e)}, 400""")
        return jsonify({"status":"Err","msg":str(e)}), 400

##### PHASE 4 BY ERLAND #####

###changes made by Abdullah###
@app.route("/challenge", methods=["POST"])
def challenge():
    try:
        username = request.json["username"]
        doesUserExsist = checkUser(username)
        if not doesUserExsist:
            return {"status":"Err","msg":"User Not Found"} , 400
        PublicKey = getPublicKey(username)
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
        encrypted = base64.b64encode(encrypted).decode()
        with db_lock:
            challengedb.insert({"plaintext" : plaintext, "encrypted" : encrypted})
        logging.info(f"Server Provided A Challenge for User {username}")
        return {"status":"ok","msg":"Server Challenge","challenge":encrypted}, 201
    except Exception as e:
        logging.error(f"Err Occured , Err:{str(e)}")
        return {"status":"Err","msg":f"{str(e)}"} , 400


@app.route("/challenge/verify",methods=["POST"])
def verify():
    try:
        username = None
        answer = None
        device_id = None
        if not request.is_json:
            answer = request.form.get("answer")
            username = request.form.get("username")
            device_id = request.form.get("deviceid")
        elif request.is_json:
            answer = request.json["answer"]
            username = request.json["username"]
            device_id = request.json["deviceid"]
        result = checkChallenge(answer)
        devid = checkDevID(username,device_id)
        # #print(result)
        # #print(devid)
        # #print(username)
        #print(result,devid)
        if result and devid:
            sessionid,expiretime = genSession(username)
            #print(sessionid,expiretime)
            # #print(sessionid)
            resp = make_response("", 204)
            resp.set_cookie("session_token",sessionid,samesite="Lax",expires=expiretime)
            logging.info(f"Successfull Completed The Challenge for the user {username}")
            return resp
        else:
            logging.error(f"Invalid Credentials For {username}")
            return jsonify({"status":"Err","msg":"Invalid Credentials"}), 404
    except Exception as e:
        logging.error(f"Error Occured For {username} , Err: {str(e)}")
        return jsonify({"status":"Err","msg":str(e)}), 400


@app.route("/genWebSession",methods=["POST"])
def genWebSession():
    token = request.form.get('token')
    username = checkToken(token)
    if username:
        sessionid,expirytime = genSession(username,token)
        resp = make_response(redirect(url_for("chats")))
        resp.set_cookie("session_token",sessionid,samesite="Lax",expires=expirytime)
        logging.info(f"Successfull Completed The Challenge for the user {username}")
        return resp
    return jsonify({"status":"Err","msg":"Invalid Token"}),400
# For testing the server, run the file and open http://127.0.0.1:5000/test in the browser

"""@app.route("/test", methods=["GET"])
def test_route():
    return jsonify({"message": "Server is running!"})"""

@app.route("/logout",methods=['POST'])
def logout():
    username = request.json["username"]
    session_id = request.cookies.get("session_token")
    doesUserExsist = checkUser(username)
    SessionExsist = GetSession(session_id)
    #print(username,session_id)
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie('session_token')
    if doesUserExsist and SessionExsist:
        RemoveSession(session_id)
        logging.info(f"User {username} Logged Out SucessFully")
        return resp
    else:
        logging.info(f"User Already logged out")
        return resp

@app.route("/tokengen/all",methods=["POST"])
def showToken():
    try:
        username = request.json["username"]
        if checkUser(username):
            data = getAllTokens(username)
            return jsonify({"status":"ok","msg":data}),200
    except Exception as e:
        return jsonify({"status":"Err","msg":f"{str(e)}"}),400

@app.route("/tokengen/delete",methods=["POST"])
def delToken():
        try:
            username = request.json["username"]
            sessionid = request.json["session"]
            if checkUser(username):
                boolean = delTokenFromUsername(username,sessionid)
                if boolean:
                    return jsonify({"status":"ok","msg":f"{sessionid} has been Deleted"}),200
                return jsonify({"status":"ok","msg":f"{sessionid} Does Not Exsist"}),400
        except Exception as e:
            return jsonify({"status":"Err","msg":f"{str(e)}"})



@app.route("/tokengen",methods=["POST"])
def getToken():
    try:
        username = request.json["username"]
        session = request.cookies.get("session_token")
        DoesUserExsist = checkUser(username)
        DoesSessionExsist = GetSession(session)
        if not DoesUserExsist and not DoesSessionExsist:
            return jsonify({"status":"Err","msg":"User Not Found"}),400
        token = genRegisterToken(username)
        return jsonify({"status":"ok","msg":token}),200
    except Exception as e:
        return jsonify({"status":"Err","Msg":f"{str(e)}"})

def delTokenFromUsername(username,sessions):
    status = RegisterToken.get(TokenQ.username == username)
    if status:
        data = status["token"]
        if sessions in data:
            data.remove(sessions)
            with db_lock:
                RegisterToken.update({"token":data},TokenQ.username == username)
            with db_lock:
                login_sessions.remove(SessionQ.token == sessions)
            return True
    return False


def getAllTokens(username):
    return RegisterToken.get(TokenQ.username == username).get("token")

def pin_generator():
    return hex(int.from_bytes(os.urandom(32)))[2:]


def gen_public_private_key(user:str,Device_id) -> tuple:
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
        
        rec_public_key(public_pem.decode("utf-8"),user,Device_id)
        logging.info(f"Sucessfull Generated Private And Public Key")
        return data

    except Exception as e:
        logging.error(f"Failed In Generated Of Private And Public Key , Err:{str(e)}")
        return {"status": "Err", "msg":f"{str(e)}"}
        
def getPublicKey(username):
    try:
        with db_lock:
            data = public_key_db.get(PubKeyQ.record_id ==  username)
        return data.get("public_key")
    except Exception as e:
        return f"{str(e)}"

def checkUser(username):
    try:
        with db_lock:
            return users.get(UserQ.username == username)
    except Exception as e:
        return str(e)


def checkChallenge(text):
    with db_lock:
        information = challengedb.get(ChallengeQ.plaintext == text)
        challengedb.remove(ChallengeQ.plaintext == text)
    if information is None:
        return False
    return True

def genSession(username:str,token=None) -> tuple:
    sessionid = uuid.uuid4().__str__()
    expirytime = time.time() + 3600
    with db_lock:
        login_sessions.insert({"username": username,"session_id": sessionid,"expirytime": expirytime,"token":token})
    return sessionid,expirytime

def cleanup_expired():
    now = time.time()
    login_sessions.remove(SessionQ.expirytime <= now)

def expiry_monitor():
    while True:
        with db_lock:
            all_sessions = login_sessions.all()
            if all_sessions:
                nextExpiryTime = min([i.get("expirytime") for i in all_sessions])
                cleanup_expired()
                timesleep = max(0,nextExpiryTime-time.time())
            else:
                timesleep = 5
        time.sleep(timesleep)

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


def GetSession(session):
    try:
        with db_lock:
            sess = login_sessions.get(SessionQ.session_id == session)
        if sess is None:
            return False
        return True
    except Exception as e:
        #print(str(e))
        return False

def RemoveSession(session):
    with db_lock:
        login_sessions.remove(SessionQ.session_id == session)

def checkDevID(username,devid):
    with db_lock:
        userdata = users.get(UserQ.username == username)
    devices = userdata.get('devices')
    if devid in devices:
        return True
    return False

def getUserFromSession(session):
    try:
        with db_lock:
            sess = login_sessions.get(SessionQ.session_id == session)
        if sess is None:
            return False
        return sess.get('username')
    except Exception as e:
        return False

def removeDeviceFromuser(username,deviceid):
    status = users.get(UserQ.username == username)
    if status:
        data = status["devices"]
        if deviceid in data:
            data.remove(deviceid)
            with db_lock:
                userdata = users.get(UserQ.username == username)
                if len(userdata.get("devices")) > 1:
                    users.update({"devices":data},UserQ.username == username)
                    return True
                else:return None
    return False

def addDeviceTouser(username,deviceid):
    with db_lock:
        data = users.get(UserQ.username == username)
    if data is None:
        with db_lock:
            users.insert({
            "username": username,
            "devices": [deviceid]
        })
        return
    devices = data.get("devices",[])
    if deviceid not in devices:
        devices.append(deviceid)
        with db_lock:
            users.update({"devices":devices}, UserQ.username == data.get('username'))
    

def genRegisterToken(username):
    token = str(uuid.uuid4())
    data = RegisterToken.get(UserQ.username == username)
    if data:
        data["token"].append(token)
        RegisterToken.update({"token":data["token"]},UserQ.username == username)
    else:
        RegisterToken.insert({"username":username,"token":[token]})
    return token

def checkToken(token):
    alltoken = RegisterToken.get(TokenQ.token.any([token]))
    #print(alltoken)
    if alltoken:
        return alltoken['username']
    return False



def showAllDevicesFromUser(username):
    return users.get(UserQ.username == username).get("devices")

@app.route("/",methods=['GET'])
def login():
    return Response(LoginPage , mimetype='text/html')

@app.route("/register",methods=['GET'])
def registerhtml():
    return Response(registerPage , mimetype='text/html')

@app.route("/chat",methods=['GET'])
def chats():
    token = request.cookies.get("session_token")
    user = getUserFromSession(token)
    logging.info(f"User {user} Logged In SucessFully")
    return render_template('chat.html', Username=user)

if __name__ == '__main__':
    threading.Thread(target=expiry_monitor, daemon=True).start()
    app.run(host='0.0.0.0', port=5000,debug=True,use_reloader=False)

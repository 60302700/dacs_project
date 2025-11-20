import json
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def check_device_hash(username, device_id, public_key, device_hash):
    computed_hash = hashlib.sha256((str(username) + ":" + str(device_id) + ":" + str(public_key)).encode()).hexdigest()
    return computed_hash == device_hash

def verify_private_key_matches(public_key_pem, private_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    challenge = b"test-challenge"
    signature = private_key.sign(
        challenge,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    try:
        public_key.verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def main():
    # Load database
    with open("../server/Database.json", "r") as f:
        db = json.load(f)
    # Example: check for user 'ahmed'
    pk_entry = None
    for k, v in db.get("Public_Keys", {}).items():
        if v.get("record_id") == "ahmed":
            pk_entry = v
            break
    if not pk_entry:
        print("No public key entry found for user 'ahmed'.")
        return
    username = pk_entry["record_id"]
    device_id = pk_entry["device"]
    public_key = pk_entry["public_key"]
    device_hash = pk_entry["device_hash"]
    print("Checking device hash...")
    if check_device_hash(username, device_id, public_key, device_hash):
        print("Device hash matches!")
    else:
        print("Device hash does NOT match!")
    # To verify private key, ask user to upload private key PEM file
    priv_path = input("Enter path to private key PEM file: ")
    with open(priv_path, "r") as f:
        private_key_pem = f.read()
    print("Verifying private key matches public key...")
    if verify_private_key_matches(public_key, private_key_pem):
        print("Private key matches public key!")
    else:
        print("Private key does NOT match public key!")

if __name__ == "__main__":
    main()

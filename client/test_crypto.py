from crypto_store import encrypt_secret, decrypt_secret

if __name__ == "__main__":
    secret = b"this_is_my_private_key"
    pin = "123456"
    path = "secret.json"

    encrypt_secret(secret, pin, path)
    recovered = decrypt_secret(pin, path)
    print("Decrypted secret:", recovered)

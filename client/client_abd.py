import sys, requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from prompt_toolkit import PromptSession

session = PromptSession()

while True:
    try:
        text = session.prompt("auth> ")
        if text.strip() == "exit":
            break
        print(f"You typed: {text}")
    except KeyboardInterrupt:
        continue
    except EOFError:
        break
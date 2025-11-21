import sys, requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from pick import pick
import os

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def login():
    clear()
    username = input("Username: ")
    password = input("Password: ")
def register():pass
def getcredentials():pass
def quit():
    clear()
    exit()
options = {"Login":login,"Register":register,"Get Credentials":getcredentials,"Exit":quit}
title = "CryptoLogin"

while True:
    option = pick(list(options.keys()),title)
    options.get(option[0])()
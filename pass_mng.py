from cryptography.fernet import Fernet
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import getpass

def load_salt():
    if not os.path.exists("salt.salt"):
        salt = os.urandom(16)
        with open("salt.salt", "wb") as f:
            f.write(salt)
    else:
        with open("salt.salt", "rb") as f:
            salt = f.read()
    return salt

def derive_key_from_password(password: str):
    salt = load_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
master_pwd = getpass.getpass("Enter master password to read passwords:")
key = derive_key_from_password(master_pwd)
fernet = Fernet(key)
def addpwd():
    kwd = input("Add keyword: ")
    user = input("Add user: ")
    pwd = getpass.getpass("Add password: ")

    encrypted_pwd = fernet.encrypt(pwd.encode())

    with open("passwords.txt", "a") as f:
        f.write(f"{kwd}|{user}|{encrypted_pwd.decode()}\n")
def find_pwd_by_kwd():
    user_inp_kwd = input("Find by keyword: ").strip().lower()
    found = False

    with open("passwords.txt", "r") as f:
        for line in f:
            kwd, user, enc_pwd = line.strip().split('|')
            if user_inp_kwd == kwd.lower():
                try:
                    decrypted_pwd = fernet.decrypt(enc_pwd.encode()).decode()
                    print(f"Keyword: {kwd} | User: {user} | Password: {decrypted_pwd}")
                    found = True
                except Exception:
                    print("Wrong master password or corrupted data.")
                    return
    if not found:
        print("No password found for the given keyword.")
def show_all_pwds():
    with open('passwords.txt', 'r') as f:
        for line in f:
            kwd, user, enc_pwd = line.strip().split('|')
            try:
                decrypted_pwd = fernet.decrypt(enc_pwd.encode()).decode()
                print(f"Keyword: {kwd} | User: {user} | Password: {decrypted_pwd}")
            except Exception:
                print(f"Cannot decrypt password for keyword: {kwd} (wrong master password?)")
while True:
    user_inp_avq = input("Do you want to add a password, view an existing one or quit the program? (a, v, q)")
    if user_inp_avq == 'q':
        break
    if user_inp_avq == 'a':
        addpwd()
    elif user_inp_avq == 'v':
        user_inp_viewm = input("Do you want to view all passwords or find one by keywords? (a, f)")
        if user_inp_viewm == 'a':
            show_all_pwds()
        elif user_inp_viewm == 'f':
            find_pwd_by_kwd()
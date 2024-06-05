import requests
import json
from cryptography.hazmat.primitives import padding
from colorama import Fore
import secrets
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib
import time
import threading
import rsa

SERVER_ADDRESS = "http://127.0.0.1:9999"
fudness = 0

def encrypt_data_withkey(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    base64_encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    return base64_encoded_ciphertext

def decrypt_data_withkey(base64_encoded_ciphertext, key):
    try:
        base64_decoded_ciphertext = base64.b64decode(base64_encoded_ciphertext)
        cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_ciphertext = decryptor.update(base64_decoded_ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_ciphertext) + unpadder.finalize()
        return plaintext
    except:
        print("ERROR DECODING: ", base64_encoded_ciphertext)
        quit()

client_bytes = secrets.token_bytes(32)

keydata = b'''
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAuKxmbcHaXTmyXfWf1JxNvJD2Fn/KQ5RdtfHVrFCmTkAJufaCOtlZ
8tw0Q2a1sowfyBcvLuXr6pYO0CRsn6S9pi3GxRbvPoyNZvtIotKIVFBEMttmt6Uw
xIaH1TRitX/KbpYsXIsvhj5szQnXRl9Yj/mZIpPvZb2+lHJF3BXW8HZO21aaBlbi
p6QPF++bX+tMn+8rRPJAGGgNiUvScgf8R8SkBncMW9IU0tDLzpnD7jNOOKB+ldJK
LFbSu+VPkMCaalHCfOyD1tZSGsqYGk4iWbc/qf38cHixbaMz7CLYfN3ExEQ/yN6z
hdGL7XB6H2KSsjCmbFzCZTslgt9fCo10twIDAQAB
-----END RSA PUBLIC KEY-----
'''

def clientelle():
    global fudness

    #time.sleep(random.randint(0, 300))
    client_data = {}  # Dictionary to store client ID and encryption key
    for _ in range(5):  # Register 5 times
        encrypted_message = encrypt_data_withkey(
            json.dumps({
                "version": 10,
                "uac": True if random.randint(0, 1) == 1 else False,
                "username": "nigger" + secrets.token_hex(8),
                "guid": 'windows-guid',
                "cpu": "Intel i5-100k",
                "gpu": "RTX 3050",
                "ram": 16,
                "antivirus": "Windows Defender",
                "path": "C:\\Windows\\System32\\malware.exe",
                "pid": 5102,
                "client_bytes": base64.encodebytes(client_bytes).decode("utf-8"),
            }),
            client_bytes
        ) + "|" + base64.b64encode(rsa.encrypt(client_bytes, rsa.PublicKey.load_pkcs1(keydata))).decode("utf-8")

        register_client = requests.post(
            SERVER_ADDRESS + "/gateway",
            encrypted_message,
        )
        decrypted_response = json.loads(
            decrypt_data_withkey(register_client.text, client_bytes).decode("utf-8")
        )
        server_bytes = base64.decodebytes(decrypted_response["server_bytes"].encode())
        new_encryption_key = hashlib.sha256(client_bytes + server_bytes).hexdigest()[:32].encode()
        client_id = decrypted_response["client_id"]
        client_data[client_id] = new_encryption_key  # Store client ID and encryption key

    while True:
        #time.sleep(300)
        time.sleep(1)
        for client_id, encryption_key in client_data.items():

            heartbeat_response = requests.post(
                SERVER_ADDRESS + "/gateway",
                client_id + encrypt_data_withkey(json.dumps({
                    "action": "heartbeat",
                }), encryption_key),
            )
            
            

            if heartbeat_response.status_code != 200:
                print(f"Heartbeat for client {client_id} failed with status code {heartbeat_response.status_code}")
            
            decrypted_response = decrypt_data_withkey(heartbeat_response.text, encryption_key).decode("utf-8")
            if decrypted_response != "Ok":
                try:
                    submit_output = requests.post(
                        SERVER_ADDRESS + "/gateway",
                        client_id + encrypt_data_withkey(json.dumps({
                            "action": "submit_output",
                            "client_id": client_id,
                            "command_id": json.loads(decrypted_response)["command_id"],
                            "output": "Example Output"
                        }), encryption_key),
                    )
                    print(f"Submit Output response for client {client_id}: {submit_output.text}")
                except Exception as e:
                    print(f"Submit Output for client {client_id} errored:", e)


def create_threads(num_threads):
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=clientelle)
        thread.start()
        threads.append(thread)
    return threads

threads = create_threads(200)
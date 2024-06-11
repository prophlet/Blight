import asyncio
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
import rsa
from concurrent.futures import ThreadPoolExecutor

SERVER_ADDRESS = "http://127.0.0.1:9999"
CONNECTION_INTERVAL = 300

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
MIIBCgKCAQEAx+zN1dr6iV1Upyd9ixoG2gxvupYqIeuFMV0GgWcCK91pcPZCkeQG
SDy/LhGjCjOMvX/2Eg0wsed99hntvZ2b6RKdsdfrSVUFxvp6H0lEVPGPjDCMssjY
RLi3JbKIopLtgdDHdnf4nCpnSrMNFV5ZuqdIoQIMaw/imyWATNSB18WOebAA8lI9
oR0XG89Ob3/IyxIAK1rUqlx1a1oJ+uBsLscsxwOGWyXir6by31uVfrdzxORFviCr
8bZfuX5wF06WQ9TH1WFAw/G4CTTWP5qooLug04Qt7cAemTLfJjkyaDeLq20ia2ix
xs9LxVype+cEoOSfpawaAH71Kw+d40Dp7wIDAQAB
-----END RSA PUBLIC KEY-----
'''

def clientelle(session=None):
    if session is None:
        session = requests.Session()
    session.headers.update({'Content-Type': 'application/json'})
    client_data = {}
    for _ in range(5):
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

        response = session.post(SERVER_ADDRESS + "/gateway", data=encrypted_message)
        if response.status_code!= 200:
            print(f"Request failed with status code {response.status_code}")
            quit()

        decrypted_response = json.loads(
            decrypt_data_withkey(response.text, client_bytes).decode("utf-8")
        )
        server_bytes = base64.decodebytes(decrypted_response["server_bytes"].encode())
        new_encryption_key = hashlib.sha256(client_bytes + server_bytes).hexdigest()[:32].encode()
        client_id = decrypted_response["client_id"]
        client_data[client_id] = new_encryption_key

    while True:
        #time.sleep(CONNECTION_INTERVAL - (CONNECTION_INTERVAL / 10))
        for client_id, encryption_key in client_data.items():
            response = session.post(SERVER_ADDRESS + "/gateway", data=client_id + encrypt_data_withkey(json.dumps({
                "action": "heartbeat",
            }), encryption_key))
            if response.status_code!= 200:
                print(f"Heartbeat for client {client_id} failed with status code {response.status_code}")
                quit()

            decrypted_response = decrypt_data_withkey(response.text, encryption_key).decode("utf-8")
            if decrypted_response!= "Ok":
                try:
                    submit_output = session.post(
                        SERVER_ADDRESS + "/gateway",
                        data=client_id + encrypt_data_withkey(json.dumps({
                            "action": "submit_output",
                            "client_id": client_id,
                            "command_id": json.loads(decrypted_response)["command_id"],
                            "output": base64.b64encode(secrets.token_bytes(2048)).decode("utf-8")
                        }), encryption_key),
                    )
                    print(f"Submit Output response for client {client_id}: {submit_output.text}")  # Use.text() method for async response
                except Exception as e:
                    print(f"Submit Output for client {client_id} errored:", e)

def main_instance(instance_number):
    clientelle()

def main():
    NUM_INSTANCES = 100
    with ThreadPoolExecutor(max_workers=NUM_INSTANCES) as executor:
        futures = [executor.submit(main_instance, i) for i in range(NUM_INSTANCES)]
        for future in futures:
            future.result()  # Wait for all futures to complete

if __name__ == "__main__":
    main()

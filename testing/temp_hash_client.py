import secrets
import argon2
import time
from colorama import Fore
import random
import binascii
from itertools import permutations


def charsex_bytes(bytearray_input):
    if isinstance(bytearray_input, bytes):
        bytearray_input = list(bytearray_input)
    
    permutations_list = [''.join(p) for p in permutations(bytearray_input)]
    return permutations_list

all_bytes = charsex_bytes()
times_found = []

print(all_bytes)

print(f"Keys Generated: {Fore.YELLOW}{len(all_bytes)}{Fore.RESET}")

while True:
    random.shuffle(all_bytes)

    server_hash_time = time.time()
    server_bytes = random.choice(all_bytes)
    server_hasher = argon2.PasswordHasher(time_cost=16, memory_cost=2**4, parallelism=2, hash_len=32, type=argon2.low_level.Type.ID)
    server_hash = server_hasher.hash((server_bytes).encode())
    print(f"Server Hash: {Fore.YELLOW}{server_hash}{Fore.RESET}. Took {Fore.YELLOW}{int((time.time() - server_hash_time) * 1000)}ms {Fore.RESET}")

    start_time = time.time()

    for chosen_hex in all_bytes:
        client_hasher = argon2.PasswordHasher(time_cost=16, memory_cost=2**4, parallelism=2, hash_len=32, type=argon2.low_level.Type.ID)
        client_hash = client_hasher.hash((server_bytes).encode())
        try:
            client_hasher.verify(client_hash, chosen_hex.encode())

            time_found = int(time.time() - start_time)
            times_found.append(time_found)
            print(f"Hash found in {time_found}s!")

            total_time = sum(times_found)
            average = total_time / len(times_found) if times_found else 0

            print(f"Current Average: {Fore.YELLOW}{int(average)}s{Fore.RESET}\n")
            break
        except:
            continue

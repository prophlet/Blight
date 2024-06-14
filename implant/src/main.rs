extern crate colored; 

// TODO: Ureq library for http requests to gateway

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
        EncodeRsaPublicKey,
        DecodeRsaPublicKey
    }, 
    Pkcs1v15Encrypt, 
    RsaPrivateKey, 
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

fn main() {

    let client_bytes = random_bytes(32);
    let mut rng = rand::thread_rng();
    let server_pub_rsa = RsaPublicKey::from_pkcs1_pem(&SERVER_RSA_PUB).unwrap();
    let rsa_client_bytes = BASE64_STANDARD.encode(server_pub_rsa.encrypt(&mut rng, Pkcs1v15Encrypt, &client_bytes).unwrap());
    
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
use crate::libraries::*;

pub async fn obtain_connection() -> Conn {
    return (*CONNECTION_POOL.read().unwrap()).get_conn().await.unwrap()
} 

pub async fn discord_webhook_push(title: &str, description: &str, color: u32, ping: bool) {
    let webhook_url = &*DISCORD_WEBHOOK_URL.read().unwrap();
    if webhook_url == &String::new() {return};
    
    match reqwest::Client::new().post(webhook_url).json(&json!({
        "content": if ping {"@here"} else {""},
        "embeds": [
          {
            "title": title,
            "description":description,
            "color": color
          }
        ],
        "username": "Blight Loader"
      })).send().await {
        Ok(result) => result,
        Err(_) => {
            fprint("failure", "Discord webhook failed to send. Check if the webhook URL is valid.");
            panic!();
        }
    };

}

pub fn get_timestamp() -> u64 {
    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards lmao");
    return since_the_epoch.as_secs()
}

// TODO :BUFFER TOO SMALL

pub fn aes_256cbc_encrypt(data: &str, key: &[u8]) -> core::result::Result<String, symmetriccipher::SymmetricCipherError> {

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

pub fn aes_256cbc_decrypt(encrypted_data: &str, key: &[u8]) -> core::result::Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

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

pub fn fprint(stype: &str, sformatted: &str) -> () {
    
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


pub fn value_to_str(row: &mysql_async::Row, index: usize) -> String {
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

pub fn value_to_u64(row: &mysql_async::Row, index: usize) -> u64 {return value_to_str(row, index).parse::<u64>().unwrap();}
pub fn value_to_bool(row: &mysql_async::Row, index: usize) -> bool { match value_to_u64(row, index) {1 => true, 0 => false, _ => panic!("Not a bool")} }

pub fn key_to_string(json: &serde_json::Value, json_key: &str) -> String {String::from(json[json_key].as_str().unwrap())}
pub fn key_to_u64(json: &serde_json::Value, json_key: &str) -> u64 {json[json_key].as_u64().unwrap()}
pub fn key_to_bool(json: &serde_json::Value, json_key: &str) -> bool {json[json_key].as_bool().unwrap()}

pub fn all_keys_valid(json: &serde_json::Value, keys: Vec<&str>, types: Vec<&str>) -> bool {
    let mut counter: usize = 0;
    for key in keys {
        if let Some(_) = json.get(key) {
            match types[counter] {
                "String" => {
                    match json[key].as_str() {
                        Some(_) => (),
                        None => return false,
                    };
                }
                "u64" => {
                    match json[key].as_u64() {
                        Some(_) => (),
                        None => return false,
                    };
                },
                "bool" => {
                    match json[key].as_bool() {
                        Some(_) => (),
                        None => return false,
                    };
                }
                &_ => {
                    return false
                }
            }
        } else {
            return false;
        }
        counter += 1;
    }
    return true
}

pub async fn ip_to_country(ip: &str) -> String {
    let ip_db = &*IP_DATABASE.read().unwrap();
    let reader = maxminddb::Reader::from_source(ip_db).unwrap();
    let ip: IpAddr = ip.parse().unwrap();
    let country: std::prelude::v1::Result<geoip2::Country, maxminddb::MaxMindDBError> = reader.lookup(ip);
    match country {
        Ok(_) => String::from(country.unwrap().country.unwrap().iso_code.unwrap()),
        Err(_) => String::from("NL")
    }
}

pub fn argon2_hash(input: &[u8]) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let params = 
        ParamsBuilder::new()
        .m_cost(2_u32.pow(8))
        .t_cost(16)
        .p_cost(2)
        .build()
        .unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    return argon2.hash_password(input, &salt).unwrap().to_string();    
}

pub async fn is_suspicious_ip(ip: &str) -> bool {
    if !&*SUSPICIOUS_IP_CHECK.read().unwrap() {return false}
    let resp = match reqwest::get(format!("https://scamalytics.com/ip/{}", ip)).await {
        Ok(r) => r,
        Err(e) => {
            fprint("error", &format!("(is_suspicious_ip): {}", e));
            return true;
        }
    }.text().await.unwrap();
    
    return resp.contains("Yes");
}

/* 
pub fn verify_argon2(hash: &str, input: &[u8]) -> bool {

    return Argon2::default().verify_password(
        input, &PasswordHash::parse(&hash, argon2::password_hash::Encoding::B64
    ).unwrap()).is_ok();
}
*/
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    rand::thread_rng().fill_bytes(&mut buffer);
    buffer[..].to_vec()
}

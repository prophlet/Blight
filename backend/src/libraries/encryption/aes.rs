use crate::libraries::*;

pub async fn get_encryption_key(connection: &mut Conn, client_id: &str) -> std::result::Result<String, GenericError> {

    if client_id == "N/A" { return Err(GenericError::NoRows) }

    let clientdb_encryption_query: std::result::Result<Option<(String, u64)>, Error>  = connection.exec_first(
        r"SELECT encryption_key, key_expiration FROM clients WHERE client_id = :client_id",
        params! {
            "client_id" => &client_id,
        }
    ).await;

    match clientdb_encryption_query {
        Ok(None) =>  { Err(GenericError::NoRows) },
        Ok(_) =>  { 
            let clientdb_encryption_query = clientdb_encryption_query.unwrap().unwrap();
            let encryption_key = clientdb_encryption_query.0;
            let expiration_time = clientdb_encryption_query.1;

            if expiration_time + 10 < get_timestamp() {
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


pub async fn get_encryption_key_from_ip(connection: &mut Conn, ip: &str) -> std::result::Result<String, GenericError> {

    let purgatory_db_query: std::result::Result<Option<(String, u64)>, Error>  = connection.exec_first(
        r"SELECT encryption_key, expiration_time FROM purgatory WHERE request_ip = :request_ip ORDER BY expiration_time DESC",
        params! {
            "request_ip" => &ip,
        }
    ).await;

    match purgatory_db_query {
        Ok(None) =>  {             
            let clientdb_encryption_query: std::result::Result<Option<(String, u64)>, Error>  = connection.exec_first(
                r"SELECT encryption_key, key_expiration FROM clients WHERE ip = :ip ORDER BY key_expiration DESC",
                params! {
                    "ip" => &ip,
                }
            ).await;

            match clientdb_encryption_query {
                Ok(None) =>  { 
                    fprint("debug", &format!("get_encryption_key_from_ip: No key found for {}", ip));
                    Err(GenericError::NoRows)
                },
                Ok(_) =>  { 
                    let clientdb_encryption_query = clientdb_encryption_query.unwrap().unwrap();
                    let encryption_key = clientdb_encryption_query.0;
                    let expiration_time = clientdb_encryption_query.1;

                    if expiration_time + 10 < get_timestamp() {
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
         },
        Ok(_) =>  { 
            let purgatory_db_query = purgatory_db_query.unwrap().unwrap();
            let encryption_key = purgatory_db_query.0;
            let expiration_time = purgatory_db_query.1;

            if expiration_time + 10 < get_timestamp() {
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


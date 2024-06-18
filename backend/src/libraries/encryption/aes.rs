use crate::libraries::*;

pub async fn get_encryption_key(connection: &mut Conn, client_id: &str) -> std::result::Result<String, GenericError> {

    if client_id == "N/A" { return Err(GenericError::NoRows) }

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


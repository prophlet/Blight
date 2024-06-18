use crate::libraries::*;

pub async fn get_last_seen(connection: &mut Conn, client_id: &str) -> u64 {

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

pub async fn update_last_seen(connection: &mut Conn, client_id: &str) -> () {
    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();

    let _: std::result::Result<Option<u64>, Error>  = connection.exec_first(
        r"UPDATE clients SET last_seen = :last_seen, key_expiration = :key_expiration WHERE client_id = :client_id",
        params! {
            "last_seen" => get_timestamp(),
            "key_expiration" => get_timestamp() + connection_interval + 10,
            "client_id" => client_id
        }
    ).await;
}

pub async fn is_client_online(connection: &mut Conn, client_id: &str) -> bool {
    let connection_interval = *CONNECTION_INTERVAL.read().unwrap();

    match connection.exec_first::<u64, &str, Params>(r"SELECT last_seen FROM clients WHERE client_id = :client_id",
        params! {"client_id" => client_id }
    ).await {
        Ok(None) => false,
        Ok(last_seen) => {
            return last_seen.unwrap() + connection_interval + 10 > get_timestamp()
        },
        Err(error) => {
            fprint("error", &format!("(is_client_online): {}", error));
            return false
        },
    }
}

pub async fn is_client(connection: &mut Conn, client_id: &str) -> bool {

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
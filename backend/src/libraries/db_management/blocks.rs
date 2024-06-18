use crate::libraries::*;

pub async fn is_block(connection: &mut Conn, block_id: &str) -> bool { 

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

pub async fn block_client(connection: &mut Conn, client_id: &str, reason: &str, ip: &str, duration: u64) -> bool {
    let enable_firewall = *ENABLE_FIREWALL.read().unwrap();
    if !enable_firewall {
        fprint("info", &format!("({}) {} would be blocked for {} seconds for: \"{}\", but firewall is disabled.", 
            client_id.yellow(), ip.yellow(), duration.to_string().yellow(), reason.yellow())
        );
        return false
    };  

    match connection.exec_drop(
    r"INSERT INTO blocks (block_id, client_id, reason, ip, banned_until) VALUES (:block_id, :client_id, :reason, :ip, :banned_until)",
        params! {
            "block_id" => generate(8, CHARSET),
            "client_id" => &client_id,
            "reason" => &reason,
            "ip" => &ip,
            "banned_until" => match duration {
                0 => 0,
                _ => {
                    get_timestamp() + duration
                }
            }
        }
    ).await {
        Ok(_) => {
            let mut duration: String = duration.to_string();
            if duration == 0.to_string() {duration = String::from("forever")};

            fprint("restricted", &format!("({}) {} was blocked until {} for: \"{}\" seconds.", 
                client_id.yellow(), ip.yellow(), duration.yellow(), reason.yellow())
            );
            return true
        },
        Err(e) => {
            fprint("error", &format!("(block_client): {}", e));
            return false
        }
    };
}

pub async fn is_client_blocked(connection: &mut Conn, client_id: &str, ip: &str) -> bool {
    
    let enable_firewall = *ENABLE_FIREWALL.read().unwrap();
    let blocked_client_query: std::result::Result<Option<i64>, Error>;
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

            let time_expire = blocked_client_query.unwrap().unwrap();
            if time_expire == 0 {return true}
            if time_expire < get_timestamp().try_into().unwrap() {

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
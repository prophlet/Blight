use crate::web_paths::*;


/*
    Obsolete, will need to retire soon. Successed by get_storage
*/

#[post("/api/parse_storage")]
pub async fn api_parse_storage(req_body: String) -> impl Responder {
    let json = match serde_json::from_str(&req_body) {
        Ok(r) => r,
        Err(_) => return resp_badrequest()
    };

    let api_secret: String = String::from(str::from_utf8(&*API_SECRET.read().unwrap().as_bytes()).unwrap());

    if key_to_string(&json, "api_secret") == api_secret {
        let read_storage = parse_storage_read(&format!("storage:{}", key_to_string(&json, "storage_id")));
        return actix_web::HttpResponse::build(actix_web::http::StatusCode::OK).body(read_storage);
    } else {
        fprint("failure", &format!("Request was sent to /api/get_output without authentication."));
        return resp_unauthorised();
    }
}

#[get("/api/storage_post/{authtoken}")]
pub async fn api_storage_post(path: web::Path<String>, req_body: web::Bytes) -> impl Responder {

    let authtoken = path.to_string();
    fprint("debug", &format!("{} {}", authtoken, *STORAGE_POST_PATH.read().unwrap()));
    if authtoken != *STORAGE_POST_PATH.read().unwrap() {return resp_unauthorised()}

    let storage_id = parse_storage_write(&req_body);
    return actix_web::HttpResponse::build(actix_web::http::StatusCode::OK).body(storage_id.replace("storage:", ""));
}

#[get("/api/storage_get/{storage_id}")]
pub async fn storage_get(path: web::Path<String>, req: HttpRequest) -> impl Responder {

    let storage_id = path.to_string();
    let mut connection: Conn = obtain_connection().await;
    let ip = req.peer_addr().unwrap().ip().to_string();

    if is_client_blocked(&mut connection, "N/A", &ip).await {
        fprint("restricted", &format!("{} blocked client attempted to download storage from id {}", ip.yellow(), storage_id));
        return resp_unauthorised();
    };

    let read_storage = parse_storage_read(&format!("storage:{}", storage_id));
    return actix_web::HttpResponse::build(actix_web::http::StatusCode::OK).body(read_storage);
}
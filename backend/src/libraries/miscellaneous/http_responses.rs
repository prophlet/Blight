use crate::libraries::*;

pub fn resp_unauthorised() -> HttpResponse {
    return HttpResponse::build(StatusCode::UNAUTHORIZED).body("You do not have the required authorization to complete this request.");
}

pub fn resp_badrequest() -> HttpResponse {
    return HttpResponse::build(StatusCode::BAD_REQUEST).body("Your request was malformed. Check the information you provided alongside this request.");
}

pub fn resp_unsupported() -> HttpResponse {
    return HttpResponse::build(StatusCode::UNPROCESSABLE_ENTITY).body("The information you submitted or the feature you requested isn't yet supported.");
}

pub fn resp_servererror() -> HttpResponse {
    return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).body("The server is overwhelmed or under maintinence. Retry your request at a later date.");
}

pub fn resp_ok(message: String) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(message);
}

pub async fn resp_ok_encrypted(message: &str, key: &[u8]) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(aes_256cbc_encrypt(message, key).unwrap());
}
use crate::libraries::*;

pub fn resp_unauthorised() -> HttpResponse {
    return HttpResponse::build(StatusCode::UNAUTHORIZED).finish();
}

pub fn resp_badrequest() -> HttpResponse {
    return HttpResponse::build(StatusCode::BAD_REQUEST).finish();
}

pub fn resp_unsupported() -> HttpResponse {
    return HttpResponse::build(StatusCode::UNPROCESSABLE_ENTITY).finish();
}

pub fn resp_servererror() -> HttpResponse {
    return HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).finish();
}

pub fn resp_ok(message: String) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(message);
}

pub async fn resp_ok_encrypted(message: &str, key: &[u8]) -> HttpResponse {
    return HttpResponse::build(StatusCode::OK).body(aes_256cbc_encrypt(message, key).unwrap());
}
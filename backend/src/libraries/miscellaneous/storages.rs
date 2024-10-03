use crate::libraries::*;

pub fn parse_storage_write(storage: &[u8]) -> String {
    let storage_id = generate(32, CHARSET);

    // Try decoding. If decoding fails, do nothing. If decoding succeeds, use that for the rest of the fn.
    let parsed_storage = match BASE64_STANDARD.decode(str::from_utf8(storage).unwrap()) {
        Ok(decoded_blob) => decoded_blob,
        Err(_) => storage.to_owned()
    };

    if (&parsed_storage).len() >= 512 {
        let mut file = File::create(format!("artifacts/storages/{}", &storage_id)).unwrap();
        file.write_all(&compress_bytes(&parsed_storage)).unwrap();
        return format!("storage:{}", storage_id)
    } else {
        match String::from_utf8(parsed_storage.to_owned()) {
            Ok(stringaling) => return stringaling,
            Err(error) => {
                fprint("error", &format!("(parse_storage_write, writing): storage ID {}: {}", &storage_id, error));
                return String::from("Invalid storage")
            }
        }
    }

}

pub fn parse_storage_read(storage_id: &str) -> Vec<u8> {
    if (&storage_id).starts_with("storage:") {
        let storage_id = storage_id.split(":").collect::<Vec<&str>>()[1];
        match fs::read(format!("artifacts/storages/{}", storage_id)) {
            Ok(result) => {
                return decompress_bytes(&result);
            },
            Err(error) => {
                fprint("error", &format!("(parse_storage_read): storage ID {}: {}", &storage_id, error));
                return "Invalid storage".as_bytes().to_vec();
            }
        };
    } else {
        return storage_id.as_bytes().to_vec()
    }
} 


pub fn compress_bytes(input: &[u8]) -> Vec<u8>{
    let mut compressor = GzEncoder::new(Vec::new(), Compression::best());
    compressor.write_all(&input).unwrap();
    return compressor.finish().unwrap()
}

pub fn decompress_bytes(input: &[u8]) -> Vec<u8>{
    let mut decompressor: GzDecoder<&[u8]> = GzDecoder::new(input);
    let mut decompressed_bytes: Vec<u8> = Vec::new();
    decompressor.read_to_end(&mut decompressed_bytes).unwrap();
    return decompressed_bytes;
}

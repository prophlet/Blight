pub mod db_management;
pub mod encryption;
pub mod miscellaneous;


#[derive(Debug)]
pub enum GenericError {
    Mysql(Error),
    NoRows,
    _WrongData,
    _ProgramErrored,
    _Expired
}

extern crate colored; 

use actix_web::{HttpResponse, http::StatusCode};


use std::{
    time::SystemTime, 
    time::UNIX_EPOCH, 
    fs, str, fs::File,
    io::Write,
    net::IpAddr,
};

use base64::prelude::*;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use mysql_async::{*, prelude::*};

use colored::Colorize;
use random_string::generate;
use crate::serde_json::json;
use maxminddb::geoip2;
use serde_json;
use rand;

use std::io::prelude::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;

use argon2::{
    ParamsBuilder,
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2
};

use reqwest;
use rand::RngCore;

use crate::CONNECTION_POOL;
use crate::CHARSET;
use crate::CONNECTION_INTERVAL;
use crate::DISCORD_WEBHOOK_URL;
use crate::IP_DATABASE;
use crate::ENABLE_FIREWALL;

use miscellaneous::general::*;
use db_management::clients::*;
pub mod api;
pub mod gateway;
use crate::*;

extern crate colored; 
use actix_web::{
    post, get, HttpRequest, Responder
};
use actix_http::header::{self, HeaderMap, HeaderValue};

use crate::libraries::{
    miscellaneous::{
        general::*,
        http_responses::*,
        storages::*
    },
    db_management::{
        blocks::*,
        clients::*,
        loads::*,
        commands::*
    },
    encryption::aes::*,
    GenericError
};

use base64::prelude::*;

use mysql_async::{*, prelude::*};

use colored::Colorize;
use random_string::generate;
use crate::serde_json::json;
use serde_json;
use sha256;
use rand;

use itertools::Itertools;
use rand::seq::SliceRandom;

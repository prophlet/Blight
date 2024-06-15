use std::error::Error;  
use std::boxed::Box;  
use std::process::Command;

// If error or 0, it's a VM.

#[cfg(target_os = "windows")]
pub fn get_bios_serial_number() -> Result<String, Box<dyn Error>> {  
    use serde::Deserialize;  
    use wmi::{COMLibrary, WMIConnection};  

  
    #[derive(Deserialize, Debug)]  
    pub struct Win32BIOS {  
        pub serialnumber: String,  
    }  

    let com_con = COMLibrary::new()?;  
    let wmi_con = WMIConnection::new(com_con.into())?;  
    let results: Vec<Win32BIOS> = wmi_con.raw_query("SELECT SerialNumber FROM Win32_BIOS")?;  
    if !results.is_empty() {  
        return Ok(results[0].serialnumber.clone());  
    } else {  
        return Err("No BIOS Serial Number found.".into());  
    }  
}  

fn main() {

    #[cfg(target_os = "windows")]
    println!("{}", get_bios_serial_number().unwrap());

    let _ = Command::new("cmd.exe").arg("/c").arg("pause").status();
}
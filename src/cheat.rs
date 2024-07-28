use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};

pub fn process_id(process_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    unsafe{
        let snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 )?;
        if snapshot.is_invalid() {
            return Err(anyhow!("Failed to create snapshot").into());
        } 
        let mut pe32 = std::mem::zeroed::<PROCESSENTRY32W>();
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        Process32FirstW(snapshot, &mut pe32)?;

            loop {
                if Process32NextW(snapshot, &mut pe32).is_err() {
                    break;
                }
                let string = OsString::from_wide(&pe32.szExeFile[..pe32.szExeFile.iter().position(|c| *c==0u16).unwrap()]);            
                if process_name == string {
                    let _ = CloseHandle(snapshot);
                    return Ok(pe32.th32ProcessID);
                }
            }
    

       let _ = CloseHandle(snapshot);
        
    }
    Ok(0)
}

pub fn Base_Address(){
    
}


fn infinite_arrows() -> Result<(), Box<dyn std::error::Error>>{
    let pid = process_id("GhostOfTsushima.exe")?;

    let process = unsafe {OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid)}?;    


    Ok(())
}
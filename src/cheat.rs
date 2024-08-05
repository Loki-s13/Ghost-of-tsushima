use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;


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

pub fn base_address(process_handle: HANDLE, module_name: &'static str) -> GamecheatResult<u64>{
    let mut needed_bytes = 0;
    unsafe {
        EnumProcessModules(process_handle, std::ptr::null_mut(), 0, &mut needed_bytes);
    }
    let total_modules = needed_bytes / std::mem::size_of::<HMODULE>() as u32; 
    let module_handles = vec![0 as HMODULE; total_modules as usize];
    unsafe {
        map_win_bool!(EnumProcessModules(
            process_handle,
            module_handles.as_mut_ptr(),
            needed_bytes,
            &mut needed_bytes
        ))?

    };

    for module_handle in module_handles {
        let mut module_name_buffer = [0u16; MAX_PATH];
        let name_length = unsafe {
            map_win_init!(GetModuleBaseNameW(
                process_handle,
                module_handle,
                module_name_buffer.as_mut_ptr() as *mut _,
                (module_name_buffer.len() / std::mem::size_of::<u16>()) as u32 
            ))
        }?;
        let retrieved_module_name = OsString::from_wide(&module_name_buffer[..name_length as usize]);
        if retrieved_module_name.eq_ignore_ascii_case(module_name) {
            return OK(module_handle as u64);
        }
    }
    Err(anyhow::anyhow!("Module not found").into())

}


fn infinite_arrows() -> Result<(), Box<dyn std::error::Error>>{
    let pid = process_id("GhostOfTsushima.exe")?;

    let process_handle = unsafe {OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid)}?;  

    let base_adress = base_address(process_handle, "GhostOfTsushima.exe")?;

    let arrow_offset: u64 = 1CDC3C8;
    let arrow_address = base_address + arrow_offset;

    let arrows: i32 = 999_999;

    unsafe {
        WriteProcessMemory(process_handle, arrow_address as *mut _, &arrows as *const _ as *const _, std::mem::size_of_val(&arrows), std::ptr::null_mut())?;
    }

    let _ = unsafe { CloseHandle(process_handle) };

    Ok(())
}
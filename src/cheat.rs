use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32};

fn process_id(process_name: &str) -> Option<u32> {
    unsafe{
        let snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if snapshot.is_invalid() {
            println!("Invalid!");
            return None;
        } 
        let mut pe32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
        pe32.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut pe32).as_bool() {
            loop {
                if process_name == pe32.szExeFile.to_string_lossy() {
                    CloseHandle(snapshot);
                    return Some(pe32.th32ProcessID);
                }

                if !Process32Next(snapshot, &mut pe32).as_bool() {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        None
    }
}

fn infinite_arrows(){
    //let process = unsafe {OpenProcess(PROCESS_VM_WRITE, false, )};

}
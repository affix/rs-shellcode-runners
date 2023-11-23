Rust Windows Shellcode Runner
------------------------------

## Overview
This repository contains a collection of Rust modules designed to execute shellcode using various methods of the native Windows API. Each module demonstrates a unique approach to loading and running shellcode, offering flexibility and adaptability for different use cases.

## Features
- Multiple Execution Methods: Includes various techniques for executing shellcode using Windows API calls.
- Rust Implementation: Leveraging Rust's safety features and performance.
  - Makes use of native Windows API by calling kernel32.dll functions.
- Detailed Documentation: Each method is thoroughly documented for ease of understanding and use.

## Getting Started
### Prerequisites
- Rust (latest stable version): See Rust Installation.
- Git: To clone the repository.
- Windows environment for compatibility with Windows API.

## Installation
Clone the repository:

```bash
git clone https://github.com/affix/rs-shellcode-runners.git
cd rust-windows-shellcode-runner
```

## Usage
Each method in the repository can be used as follows:

[CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread): The CreateThread function is a part of the Windows API, primarily used for creating a thread to execute within the virtual address space of the calling process. When applied to running shellcode in memory, it offers a method to dynamically execute arbitrary code, often used in legitimate software as well as in various security research and exploitation scenarios.

Navigate to `create-thread ` directory.

```powershell
cd create-thread
cargo build
.\target\debug\create-thread.exe
```


Process Injection with [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread): 
CreateRemoteThread is a function in the Windows API used to create a thread in the virtual address space of another process. Unlike CreateThread, which creates a thread in the same process, CreateRemoteThread allows for cross-process thread creation. This makes it particularly significant in various programming scenarios, including system monitoring, debugging, and certain types of malware activity.

```powershell
cd create-remote-thread
cargo build
.\target\debug\create-remote-thread.exe
```

## License
This project is licensed under the MIT License.

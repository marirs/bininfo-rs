# Binary File Information
[![macOS](https://github.com/marirs/fileinfo-rs/actions/workflows/macos.yml/badge.svg)](https://github.com/marirs/fileinfo-rs/actions/workflows/macos.yml)
[![Linux x86_64](https://github.com/marirs/fileinfo-rs/actions/workflows/linux_x86-64.yml/badge.svg)](https://github.com/marirs/fileinfo-rs/actions/workflows/linux_x86-64.yml)
[![Linux Arm7](https://github.com/marirs/fileinfo-rs/actions/workflows/linux_arm7.yml/badge.svg)](https://github.com/marirs/fileinfo-rs/actions/workflows/linux_arm7.yml)
[![Windows](https://github.com/marirs/fileinfo-rs/actions/workflows/windows.yml/badge.svg?branch=master)](https://github.com/marirs/fileinfo-rs/actions/workflows/windows.yml)

Provides some information on PE and ELF files.

### Requirements
- Rust 1.60+

### Add the lib to your project
```toml
[dependencies]
bininfo = "0.4.1"
```

### Example
```text
$ ./bininfo ~/Downloads/test.exe 

+-----------------+----------------------------------------------+
|                          Entry point                           |
+=================+==============================================+
| Address         | 0x19eb0                                      |
+-----------------+----------------------------------------------+
| Section Name    | .text                                        |
+-----------------+----------------------------------------------+
| Virtual Address | 0x1000                                       |
+-----------------+----------------------------------------------+
| Virtual Size    | 0x1a64a                                      |
+-----------------+----------------------------------------------+
| Raw Address     | 0x400                                        |
+-----------------+----------------------------------------------+
| Raw Size        | 0x1a800                                      |
+-----------------+----------------------------------------------+
| Entropy         | 6.3360176                                    |
+-----------------+----------------------------------------------+
| Characteristics | 60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ) |
+-----------------+----------------------------------------------+
+--------+-----------------+----------------------+-------------+------------------+-----------+--------------------------------------------------------------+
|                                                                          Sections                                                                           |
+========+=================+======================+=============+==================+===========+==============================================================+
| Name   | Virtual Address | Virtual Address Size | Raw Address | Raw Address Size | Entropy   | Characteristics                                              |
+--------+-----------------+----------------------+-------------+------------------+-----------+--------------------------------------------------------------+
| .text  | 0x1000          | 0x1a64a              | 0x400       | 0x1a800          | 6.3360176 | 60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ)                 |
+--------+-----------------+----------------------+-------------+------------------+-----------+--------------------------------------------------------------+
| .rdata | 0x1c000         | 0x7e44               | 0x1ac00     | 0x8000           | 5.1286488 | 40000040 (CNT_INITIALIZED_DATA | MEM_READ)                   |
+--------+-----------------+----------------------+-------------+------------------+-----------+--------------------------------------------------------------+
| .data  | 0x24000         | 0x318                | 0x22c00     | 0x200            | 1.5757816 | C0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)       |
+--------+-----------------+----------------------+-------------+------------------+-----------+--------------------------------------------------------------+
| .pdata | 0x25000         | 0x11e8               | 0x22e00     | 0x1200           | 5.1656566 | 40000040 (CNT_INITIALIZED_DATA | MEM_READ)                   |
+--------+-----------------+----------------------+-------------+------------------+-----------+--------------------------------------------------------------+
| .reloc | 0x27000         | 0x344                | 0x24000     | 0x400            | 4.90169   | 42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ) |
+--------+-----------------+----------------------+-------------+------------------+-----------+--------------------------------------------------------------+
+--------------+-------+------------+-------+-------------------------------+
|                               Rich Headers                                |
+==============+=======+============+=======+===============================+
| Product Name | Build | Product ID | Count | Guessed Visual Studio Version |
+--------------+-------+------------+-------+-------------------------------+
| Implib900    | 30729 | 147        | 12    | VS2008 SP1 build 30729        |
+--------------+-------+------------+-------+-------------------------------+
| Implib1400   | 29913 | 257        | 2     | VS2019 v16.9.2 build 29913    |
+--------------+-------+------------+-------+-------------------------------+
| Utc1900_CPP  | 29913 | 261        | 22    | VS2019 v16.9.2 build 29913    |
+--------------+-------+------------+-------+-------------------------------+
| Utc1900_C    | 29913 | 260        | 9     | VS2019 v16.9.2 build 29913    |
+--------------+-------+------------+-------+-------------------------------+
| Masm1400     | 29913 | 259        | 3     | VS2019 v16.9.2 build 29913    |
+--------------+-------+------------+-------+-------------------------------+
| Implib1400   | 26715 | 257        | 9     | UNKNOWN PRODUCT               |
+--------------+-------+------------+-------+-------------------------------+
| Import0      | 0     | 1          | 164   | Unmarked objects              |
+--------------+-------+------------+-------+-------------------------------+
| Unknown      | 0     | 0          | 17    | Unmarked objects (old)        |
+--------------+-------+------------+-------+-------------------------------+
| Linker1400   | 29914 | 258        | 1     | VS2019 v16.9.4 build 29914    |
+--------------+-------+------------+-------+-------------------------------+
+---------------------------+---------------------------------------------------------------------------------------------------------------+
|                                                                Signatures                                                                 |
+===========================+===============================================================================================================+
| Signature #1                                                                                                                              |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Signature Digest: 8fb889c04c8e8b755c1b6355aa804f8a                                                                                        |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Signer                                                                                                                                    |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Issuer                    | CN=StartCom Class 2 Primary Intermediate Object CA,OU=Secure Digital Certificate Signing,O=StartCom Ltd.,C=IL |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Serial Number             | 0D:C2                                                                                                         |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate #0                                                                                                                            |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Issuer        | CN=Thawte Timestamping CA,OU=Thawte Certification,O=Thawte,L=Durbanville,ST=Western Cape,C=ZA                 |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Subject       | CN=Symantec Time Stamping Services CA - G2,O=Symantec Corporation,C=US                                        |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Serial Number | 7E:93:EB:FB:7C:C6:4E:59:EA:4B:9A:77:D4:06:FC:3B                                                               |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate #1                                                                                                                            |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Issuer        | CN=Symantec Time Stamping Services CA - G2,O=Symantec Corporation,C=US                                        |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Subject       | CN=Symantec Time Stamping Services Signer - G4,O=Symantec Corporation,C=US                                    |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Serial Number | 0E:CF:F4:38:C8:FE:BF:35:6E:04:D8:6A:98:1B:1A:50                                                               |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate #2                                                                                                                            |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Issuer        | CN=StartCom Class 2 Primary Intermediate Object CA,OU=Secure Digital Certificate Signing,O=StartCom Ltd.,C=IL |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Subject       | EMAIL=falc0ware@gmail.com,CN=VAlera Sok0lov,L=T0msk,ST=T0msk Oblast,C=RU,DESCRIPTION=2ylE67ffj51UCbym         |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
| Certificate Serial Number | 0D:C2                                                                                                         |
+---------------------------+---------------------------------------------------------------------------------------------------------------+
+-----------------------------------+--------------------------------------------+
|                                    Imports                                     |
+===================================+============================================+
| Module Name                       | Imports                                    |
+-----------------------------------+--------------------------------------------+
| kernel32.dll                      | IsProcessorFeaturePresent                  |
|                                   | SetUnhandledExceptionFilter                |
|                                   | UnhandledExceptionFilter                   |
|                                   | IsDebuggerPresent                          |
|                                   | RtlVirtualUnwind                           |
|                                   | InitializeSListHead                        |
|                                   | GetCurrentThreadId                         |
|                                   | WriteConsoleW                              |
|                                   | GetConsoleMode                             |
|                                   | GetModuleHandleA                           |
|                                   | FormatMessageW                             |
|                                   | GetModuleHandleW                           |
|                                   | TryEnterCriticalSection                    |
|                                   | LeaveCriticalSection                       |
|                                   | AcquireSRWLockExclusive                    |
|                                   | ReleaseSRWLockExclusive                    |
|                                   | InitializeCriticalSection                  |
|                                   | CloseHandle                                |
|                                   | ReleaseMutex                               |
|                                   | GetLastError                               |
|                                   | GetCurrentProcess                          |
|                                   | GetCurrentThread                           |
|                                   | RtlCaptureContext                          |
|                                   | GetProcAddress                             |
|                                   | RtlLookupFunctionEntry                     |
|                                   | SetLastError                               |
|                                   | GetCurrentDirectoryW                       |
|                                   | GetEnvironmentVariableW                    |
|                                   | WriteFile                                  |
|                                   | EnterCriticalSection                       |
|                                   | GetCurrentProcessId                        |
|                                   | QueryPerformanceCounter                    |
|                                   | GetSystemTimeAsFileTime                    |
|                                   | GetProcessHeap                             |
|                                   | HeapAlloc                                  |
|                                   | HeapFree                                   |
|                                   | TlsGetValue                                |
|                                   | TlsSetValue                                |
|                                   | TlsAlloc                                   |
|                                   | HeapReAlloc                                |
|                                   | AcquireSRWLockShared                       |
|                                   | ReleaseSRWLockShared                       |
|                                   | AddVectoredExceptionHandler                |
|                                   | SetThreadStackGuarantee                    |
|                                   | WaitForSingleObjectEx                      |
|                                   | LoadLibraryA                               |
|                                   | CreateMutexA                               |
|                                   | GetStdHandle                               |
+-----------------------------------+--------------------------------------------+
| vcruntime140.dll                  | __current_exception                        |
|                                   | __C_specific_handler                       |
|                                   | __current_exception_context                |
|                                   | memcmp                                     |
|                                   | memcpy                                     |
|                                   | memmove                                    |
|                                   | memset                                     |
|                                   | __CxxFrameHandler3                         |
|                                   | _CxxThrowException                         |
+-----------------------------------+--------------------------------------------+
| api-ms-win-crt-runtime-l1-1-0.dll | _initterm                                  |
|                                   | _initterm_e                                |
|                                   | exit                                       |
|                                   | _exit                                      |
|                                   | _initialize_narrow_environment             |
|                                   | __p___argc                                 |
|                                   | __p___argv                                 |
|                                   | _cexit                                     |
|                                   | _c_exit                                    |
|                                   | _register_thread_local_exe_atexit_callback |
|                                   | _configure_narrow_argv                     |
|                                   | _seh_filter_exe                            |
|                                   | _get_initial_narrow_environment            |
|                                   | _initialize_onexit_table                   |
|                                   | _register_onexit_function                  |
|                                   | _crt_atexit                                |
|                                   | terminate                                  |
|                                   | _set_app_type                              |
+-----------------------------------+--------------------------------------------+
| api-ms-win-crt-math-l1-1-0.dll    | __setusermatherr                           |
+-----------------------------------+--------------------------------------------+
| api-ms-win-crt-stdio-l1-1-0.dll   | __p__commode                               |
|                                   | _set_fmode                                 |
+-----------------------------------+--------------------------------------------+
| api-ms-win-crt-locale-l1-1-0.dll  | _configthreadlocale                        |
+-----------------------------------+--------------------------------------------+
| api-ms-win-crt-heap-l1-1-0.dll    | _set_new_mode                              |
|                                   | free                                       |
+-----------------------------------+--------------------------------------------+
+----------------+--------+------------------+-------------+------------+----------+
|                                    Resources                                     |
+================+========+==================+=============+============+==========+
| Resources Type | Offset | Resource Id      | Language ID | Data Start | Data End |
+----------------+--------+------------------+-------------+------------+----------+
| Icon           | 3      | ID(1)            | ID(1033)    | 0xb4c4     | 0xc16c   |
+----------------+--------+------------------+-------------+------------+----------+
| String         | 6      | ID(4089)         | ID(0)       | 0xc16c     | 0xc45e   |
+----------------+--------+------------------+-------------+------------+----------+
| String         | 6      | ID(4090)         | ID(0)       | 0xc460     | 0xc76c   |
+----------------+--------+------------------+-------------+------------+----------+
| String         | 6      | ID(4091)         | ID(0)       | 0xc76c     | 0xca3a   |
+----------------+--------+------------------+-------------+------------+----------+
| String         | 6      | ID(4093)         | ID(0)       | 0xca3c     | 0xcaa4   |
+----------------+--------+------------------+-------------+------------+----------+
| String         | 6      | ID(4094)         | ID(0)       | 0xcaa4     | 0xcb58   |
+----------------+--------+------------------+-------------+------------+----------+
| String         | 6      | ID(4095)         | ID(0)       | 0xcb58     | 0xcc06   |
+----------------+--------+------------------+-------------+------------+----------+
| RCData         | 10     | ID(11111)        | ID(0)       | 0xcc08     | 0xcc34   |
+----------------+--------+------------------+-------------+------------+----------+
| GroupIcon      | 14     | Name("MAINICON") | ID(1033)    | 0xcc34     | 0xcc48   |
+----------------+--------+------------------+-------------+------------+----------+
| Version        | 16     | ID(1)            | ID(1033)    | 0xcc48     | 0xd13c   |
+----------------+--------+------------------+-------------+------------+----------+
| Manifest       | 24     | ID(1)            | ID(1033)    | 0xd13c     | 0xd724   |
+----------------+--------+------------------+-------------+------------+----------+
+-------------------+-------------------+
| Thread Local Storage (TLS) Callbacks  |
+===================+===================+
| Address           | 0x14000cf00       |
+-------------------+-------------------+

```

---
License: Apache License

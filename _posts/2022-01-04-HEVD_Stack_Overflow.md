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

Driver will execute the <code>BufferOverflowStackIoctlHandler</code> function, in case of *HEVD_IOCTL_BUFFER_OVERFLOW_STACK* value in the switch statement. *HEVD_IOCTL_BUFFER_OVERFLOW_STACK* is a macro that corresponds to the IOCTL with 0x800 function code in it. So in order to trigger the vulnerability, we need to use 0x800 in the IOCTL creation.

![IOCTL definitions](/assets/img/code_IOCTL_definitions.png)
*IOCTL definitions*

This is how the disassembled <code>IrpDeviceIoCtlHandler</code> function code looks in IDA:

![IrpDeviceIoCtlHandler](/assets/img/ida_stackbo_flow.png)
*switch statement and IOCTL handler*

<code>0x222003</code> is deducted from the IOCTL value held in ECX and the result is loaded into EAX register (1). If the difference is larger than <code>0x6C</code>, program jumps to a different part of code to return *"[-] Invalid IOCTL Code: "* message. It means there are 109 possible IOCTL codes that will be accepted by the program, in the range <code>0x222003 - 0x22206f</code>.
<br>
If the difference is smaller than or equal <code>0x6C</code>, the IOCTL is used in the *jmp* instruction to jump to the correct offset from the jump table (2). In the bottom of the picture, we see code at one of the offsets that calls <code>BufferOverflowStackIoctlHandler</code>(3).

### <span class="myheader">Exploitation</span>

With all the relevant information needed to trigger the vulnerability, we can build exploit. To communicate, we need first to open a handle from userland to the target device using <code>CreateFile</code> API, putting instead of file name name of the HEVD device, which we can get e.g. from WinObj tool:

![Name of HEVD device](/assets/img/winobj_nameOfHevdDevice.png)
*device name in WinObj tool*

Then we use <code>ctypes</code> library in Python to start building exploit: 

```python
import ctypes, sys, struct
from ctypes import *
from subprocess import *

kernel32 = windll.kernel32

hevd = kernel32.CreateFileW("\\\\.\\HackSysExtremeVulnerableDriver",
                            0xC0000000,
                            0,
                            None,
                            0x3,
                            0,
                            None
                            )
    
if (not hevd) or (hevd == -1):
    print("[!] Failed to retrieve handle to device-driver with error-code: " + str(GetLastError()))
    sys.exit(1)
else:
    print("[*] Successfully retrieved handle to device-driver: " + str(hevd))
```

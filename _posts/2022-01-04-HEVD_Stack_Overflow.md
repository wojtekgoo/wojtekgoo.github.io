---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2022-01-04 09:00:00 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, drivers, x86, shellcoding, kernel exploitation]
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

Vulnerability exists in the [BufferOverflowStack.c](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/BufferOverflowStack.c) file:

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

Inspecting <code>else</code> condition, we notice that the <code>RtlCopyMemory</code> function copies full length of the supplied UserBuffer to the KernelBuffer leading to the stack buffer overflow vulnerability, as we are able to overwrite information on the stack and diverge the code execution from a current path to e.g. a shellcode. <code>Size</code> of the user supplied data is not validated in any way:

```c
Size = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
```

In the <code>SECURE</code> version, this is taken care of as max length of the copied data is not larger than the KernelBuffer itself as specified by the <code>sizeof</code> operator. 

## <span class="myheader">Exploitation</span>

To exploit this vulnerability we need to make the driver code follow the correct execution flow and reach the vulnerable code. Below we can observe in IDA Pro what is the path we need to take:

![IDA Stack BO path](/assets/img/ida_stackbo_path.png)
_Stack Buffer Overflow path in IDA Pro_

<code>DriverEntry</code> is the first piece of code called after a driver is loaded. In the code there is also <code>IrpDeviceIoCtlHandler</code> function defined that handles incoming IOCTL control codes inside IRP packets.
Based on the information in the packet, function will redirect execution to the appropriate IOCTL handler - <code>BufferOverflowStackIoCtlHandler</code> in this case - which is a wrapper for <code>TriggerBufferOverflowStack</code> that contains the vulnerable code as described in the 'Vulnerability' section above.

Our next task is to determine what IOCTL needs to be send to trigger the vulnerability.

### <span class="myheader">IOCTL</span>

Let's have a look at the source code first.
<br>
<code>IrpDeviceIoCtlHandler</code> function uses *switch* statement to transfer control to a correct handler, depending on the IOCTL received:

![IrpDeviceIoCtlHandler source code](/assets/img/code_IrpDeviceIoCtlHandler.png)
_source code of the IrpDeviceIoCtlHandler_

![IOCTL definitions](/assets/img/code_IOCTL_definitions.png)
_IOCTL definitions_

This is how the disassembled function code looks in IDA:

![IrpDeviceIoCtlHandler](/assets/img/ida_stackbo_flow.png)
_switch statement and IOCTL handler_

<code>0x222003</code> is deducted from the IOCTL value held in ECX and the result is loaded into EAX register (1). If the difference is larger than <code>0x6C</code>, program jumps to a different part of code to return "[-] Invalid IOCTL Code: " message. It means, there are 109 possible IOCTL codes that will be accepted by the program, in the range <code>0x222003 - 0x22206f</code>.
<br>
If the difference is smaller than <code>0x6C</code>, the IOCTL is used in the *jmp* instruction to jump to the correct offset from the jump table (2). In the bottom of the picture, we see code at this offset that calls <code>BufferOverflowStackIoctlHandler</code> and <code>TriggerBufferOverflowStack</code> in the end (3).

![WrongIOCTL](/assets/img/ida_invalidioctl.png)
_Incorrect IOCTL code_


### <span class="myheader">Exploitation</span>
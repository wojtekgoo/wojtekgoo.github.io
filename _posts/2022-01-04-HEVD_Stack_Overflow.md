---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2022-01-04 09:00:00 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, drivers, x86, shellcoding, kernel exploitation]
---


## <span class="myheader">Loading HEVD driver</span>

In this post we will be exploiting the Stack Overflow vulnerability in the [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) driver. Before that, I recommend to read the previous blogpost where I explain some basic concepts.

To load the driver, download first the pre-built executable from [here](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/releases) (or build it from source if you have too much time). Then, download and run the [OSR Driver Loader](https://www.osronline.com/article.cfm%5earticle=157.htm) to load the driver in the debugee:

![OSR tool](/assets/img/osr_tool.png)
_OSR Driver Loader_

If all went well, you should see a new driver in the list of loaded modules:

![HEVD loaded](/assets/img/windbg_loaded_hevd.png)
_HEVD loaded in the debugee_


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
<br>
Our next task is to determine what IOCTL needs to be send to trigger the vulnerability.
<br>
Let's have a look at the source code first. <code>IrpDeviceIoCtlHandler</code> function uses *switch* statement to transfer control to a correct handler, depending on the IOCTL received:

<table>
<tr>
<th><pre> HackSysExtremeVulnerableDriver.c </pre></th>
<th><pre> HackSysExtremeVulnerableDriver.h </pre></th>
</tr>
<tr>
<td>
<pre>
```c
/// <summary>
/// IRP Device IoCtl Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <param name="Irp">The pointer to IRP</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
IrpDeviceIoCtlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    ULONG IoControlCode = 0;
    PIO_STACK_LOCATION IrpSp = NULL;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp)
    {
        IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

        switch (IoControlCode)
        {
        case HEVD_IOCTL_BUFFER_OVERFLOW_STACK:
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
            Status = BufferOverflowStackIoctlHandler(Irp, IrpSp);
            DbgPrint("****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n");
            break;
```
</pre>
</td>
<td>
<pre>
```c
//
// IOCTL Definitions
//

#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                         IOCTL(0x800)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS                      IOCTL(0x801)
#define HEVD_IOCTL_ARBITRARY_WRITE                               IOCTL(0x802)
```
</pre>
</td>
</tr>
</table>

This is how it looks in the disassembled code:

![](/assets/img/ida_IrpDeviceIoCtlHandler.png)  
_switch statement_

0x222003 is deducted from the IOCTL value held in ECX and result is loaded into EAX register. Then, it is used in the **jmp** instruction to jump to the correct offset from the jump table:

![](/assets/img/ida_jumptable_IrpDeviceIoCtlHandler.png)
_switch jumptable_
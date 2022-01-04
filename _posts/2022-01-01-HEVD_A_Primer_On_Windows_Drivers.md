---
layout: post
title: "HEVD: A primer on Windows drivers"
date: 2022-01-01 09:00:00 +0100
categories: [HEVD, Intro to Windows drivers]
tags: [drivers, x86]
---


## <span class="myheader">HEVD</span>

Over the next few posts in this series I am going to be looking at Windows kernel exploitation via the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). This is a wonderful piece of software with intentional bugs in it, created for those like me who are just starting out in low-level exploitation.  
There are multiple good articles out there explaining various HEVD vulnerabilities, so almost nothing I create in this blog will be new. However, I noticed that for every exploit I had to combine many different resources to really understand what the vulnerability is about and how to use it, as I could never find a single page that would do the job. Hence, I decided to describe it once again for my own reference.

**I will not explain:**
+ how to install HEVD
+ how to set up a lab environment
+ basic subjects like buffer overflows theory, function calls, APIs etc.

To set up your lab, read e.g. [this](https://fluidattacks.com/blog/windows-kernel-debugging/) or [this](https://www.exploit-db.com/docs/44094). 

## <span class="myheader">Windows internals</span>

Before we deep-dive into the driver exploitation, I made a small refresher of some concepts I think are most relevant to the topic. Understanding in general what role a driver has and how it receives requests from the user is crucial to learn how to find vulnerabilities in the real-world code. This is by no means exhaustive list of topics but will make sure we are on the same page before we continue.

#### <span class="myheader">Modes</span>

A processor in computer with Windows operates in two modes: *user mode* and *kernel mode*. It switches between them depending on what type of code is running. Applications run in user mode and core operating system components run in kernel mode.
+ **User Mode**: here, the executing code has limited power - it cannot for example access hardware directly or reference every memory address. To do this, code running in UM must use special APIs that will handle it.
+ **Kernel Mode**: here, the executing code has unrestricted access to the hardware, can use any CPU instruction or reference any memory address[^1]

System drivers, like HEVD, operate in Kernel Mode. It means that if we are able to discover and exploit a vulnerability in the driver, we can force it to execute a piece of malicious code that we placed in UM (like shellcode) with high privileges stemming from the KM.

#### <span class="myheader">Process</span>

When an application starts, Windows creates a *process* for it. Think of a process as a container that holds all the necessary information for application to run. If the application runs in user-mode, process provides the app with a private virtual address space. 

#### <span class="myheader">Thread</span>

TODO

#### <span class="myheader">Virtual address space</span>

TODO: virtual addr space definition

Because a user-mode application's virtual address space is private, one application cannot alter data that belongs to another application. Each application runs in isolation, and if an application crashes, the crash is limited to that one application. Other applications and the operating system are not affected by the crash.

In addition to being private, the virtual address space of a user-mode application is limited. A processor running in user mode cannot access virtual addresses that are reserved for the operating system. Limiting the virtual address space of a user-mode application prevents the application from altering, and possibly damaging, critical operating system data. 

All code that runs in kernel mode shares a single virtual address space. This means that a kernel-mode driver is not isolated from other drivers and the operating system itself. If a kernel-mode driver accidentally writes to the wrong virtual address, data that belongs to the operating system or another driver could be compromised. If a kernel-mode driver crashes, the entire operating system crashes.

#### <span class="myheader">Memory regions</span>

In User Mode there are two main memory regions used for functions implementation: *stack* and *heap*.

Stack is a region of memory where data is added and removed in such way that data added last will be removed first and data added first will be removed in the end (Last-In-First-Out queue). Imagine building a tower from wooden bricks. If you want to move a piece at the bottom without collapsing whole tower, first you need to remove all bricks that you added later that reside on the top.
<br>
In most Operating Systems each thread has its own stack region in memory. Functions executed by the thread may store some of their local data on the stack and have to remove all the data placed on the stack when they finish execution.

TODO: define heap

In Kernel Mode, up to Windows 10 19H1 (1903), there were kernel stack and kernel pool which played similar role to the userland heap.[^2]

#### <span class="myheader">Windows Drivers</span>

Driver is a software interacts with the kernel and/or controls hardware resources. Drivers mainly let OS and hardware communicate with each other. It sits and waits for the system to call it when it needs something, like starting/using/controlling a hardware device. Then, the driver interprets incoming OS request and translates it into instructions understood by the device and vice versa.
<br>
You can think of a driver as a DLL that is loaded into the kernel address space and executes with the same privilege as the kernel. A driver does not have a main execution thread; it contains code that can be called by the kernel when certain events occur. Such events may be interrupts or processes requiring the operating system to do stuff; the kernel handles those interrupts and may execute appropriate drivers to fulfill the requests.[^3]

##### <span class="myheader">DriverEntry</span>

After a driver is loaded, first piece of code that is called is a <code>DriverEntry</code> function:

```c++
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath
);
```
The <code>DriverObject</code> argument is a pointer to the <code>DRIVER_OBJECT</code> structure filled out by the I/O manager during the driver loading process that holds information about the driver itself. I/O manager creates a <code>DRIVER_OBJECT</code> for every driver loaded in the system.

![DRIVER_OBJECT](/assets/img/windbg_driver_object.png)
*DRIVER_OBJECT structure*

One of the most important fields in the <code>DriverObject</code> structure is <code>MajorFunctions</code> which is an array of function pointers.
<br>
Whenever driver receives request, it invokes relevant routine pointed by index from the array - more on that later. 

##### <span class="myheader">Devices</span>

The operating system represents devices by *device objects*. They serve as the target of all operations on the device. A driver creates device object for every device the driver handles. So if a device is served by multiple drivers, each one will create its own device object.

If a device wants to be accessible for user processes, a driver needs to define the device by creating a <code>DEVICE_OBJECT</code> structure and a symbolic link (symlink). One example is <code>C:\</code> symlink that represents storage device. We can check it with <code>WinObj</code> tool from SysInternals suite:

![Symlink in WinObj](/assets/img/WinObj_symlink.png)
_WinObj showing symlink for a storage device_

##### <span class="myheader">IOCTL and IRP</span>

Drivers receive requests from userland in form of standard APIs (like ReadFile or WriteFile) or I/O Control Codes (IOCTL), if the request does not fit into standard API. IOCTLs are 32 bit integers that encodes information what action hardware needs to take.
IOCTL is generated with <code>DeviceIoControl</code> API located in kernel32.dll in user-mode and is passed to the kernel-mode I/O Manager.

Windows I/O Manager takes the standard API request or IOCTL and builds **I/O Request Packet (IRP)** to describe the I/O request to kernel-mode components and determine which device should process the request. IRP is a kernel structure used to represent I/O request as it moves around the kernel system. It has all the information that the driver needs to perform a given action on an I/O request.
<br>
So when a program issues a request to a device, an IRP is created in kernel space to reflect that request.

![IRP structure](/assets/img/windbg_irp_structure.png)
_IRP structure_

In summary, an IOCTL is a particular user-mode type of "miscellaneous" request to a device driver. An IRP is a kernel-mode data structure for managing all kinds of requests inside the Windows driver kernel architecture.[^4]

##### <span class="myheader">User-Kernel communication</span>

Now when we understand most important data objects, we can try to grasp how requests are passed from the user-mode apps to the kernel-mode drivers.

When user-mode code calls some kernel32.dll API like <code>ReadFile</code> or <code>DeviceIoControl</code>, the request is transferred to ntdll.dll
<br>
Ntdll prepares registers, sets the stack and calls SYSENTER (in x86) or SYSCALL (x64) instruction that switches to kernel mode. The request is handled then by the I/O Manager, that creates IRP packet and sends it to the appropriate driver.
<br>
The IRP packet contains a major function code that tells the driver how to act and which specific function from the <code>MajorFunctions</code> array to call.
There are many major function codes and each of them corresponds with a user-mode function, but the most important ones are:
* <code>IRP_MJ_CREATE</code>, relates to user-mode <code>CreateFile</code>
* <code>IRP_MJ_READ</code>, relates to <code>ReadFile</code>
* <code>IRP_MJ_DEVICE_CONTROL</code>, relevant to <code>DeviceIoControl</code>

![IOCTL flow](/assets/img/IOCTL_flow.png)
_IOCTL flow around the system_

Equipped with this basic knowledge, let's move on in the next article to the analysis of the first vulnerability in HEVD - [the Stack Overflow](https://wojtekgoo.github.io/posts/HEVD_Stack_Overflow/).

## <span class="myheader">References<span>

[^1]: https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/concepts-and-knowledge-for-all-driver-developers
[^2]: In March 2019 Microsoft brought Segment Heap used in user land to the kernel
[^3]: https://voidsec.com/exploiting-system-mechanic-driver/
[^4]: https://stackoverflow.com/questions/18901467/what-is-the-difference-between-an-ioctl-and-an-irp
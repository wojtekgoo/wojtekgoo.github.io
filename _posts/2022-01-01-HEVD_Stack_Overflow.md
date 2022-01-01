---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2022-01-01 09:00:00 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, drivers, x86, shellcoding, kernel exploitation]
---


## HEVD

Over the next few posts in this series I am going to be looking at Windows kernel exploitation via the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). This is a wonderful piece of software with intentional bugs in it, created for those like me who are just starting out in low-level exploitation.  
There are multiple good articles out there explaining various HEVD vulnerabilities, so almost nothing I create in this blog will be new. However, I noticed that for every exploit I had to combine many different resources to really understand what the vulnerability is about and how to use it, as I could never find a single page that would do the job. Hence, I decided to describe it once again for my own reference.

**I will not explain:**
+ how to install HEVD
+ how to set up a lab environment
+ basic subjects like buffer overflows theory, function calls, APIs etc.

To set up your lab, read e.g. [this](https://fluidattacks.com/blog/windows-kernel-debugging/) or [this](https://www.exploit-db.com/docs/44094). 

## Windows internals

Before I deep-dive into the exploitation, below is small refresher of some related concepts. 

#### Modes

A processor in computer with Windows operates in two modes: *user mode* and *kernel mode*. It switches between them depending on what type of code is running. Applications run in user mode and core operating system components run in kernel mode.
+ **User Mode**: here, the executing code has limited power - it cannot for example access hardware directly or reference every memory address. To do this, code running in UM must use special APIs that will handle it.
+ **Kernel Mode**: here, the executing code has unrestricted access to the hardware, can use any CPU instruction or reference any memory address<sup>1)</sup>

System drivers, like HEVD, operate in Kernel Mode. It means that if we are able to discover and exploit a vulnerability in the driver, we can force it to execute a piece of malicious code that we placed in UM (like shellcode) with high privileges stemming from the KM.

#### Process

When an application starts, Windows creates a *process* for it. Think of a process as a container that holds all the necessary information for application to run. If the application runs in user-mode, process provides the app with a private virtual address space. 

#### Virtual address space

Because a user-mode application's virtual address space is private, one application cannot alter data that belongs to another application. Each application runs in isolation, and if an application crashes, the crash is limited to that one application. Other applications and the operating system are not affected by the crash.

In addition to being private, the virtual address space of a user-mode application is limited. A processor running in user mode cannot access virtual addresses that are reserved for the operating system. Limiting the virtual address space of a user-mode application prevents the application from altering, and possibly damaging, critical operating system data. 

All code that runs in kernel mode shares a single virtual address space. This means that a kernel-mode driver is not isolated from other drivers and the operating system itself. If a kernel-mode driver accidentally writes to the wrong virtual address, data that belongs to the operating system or another driver could be compromised. If a kernel-mode driver crashes, the entire operating system crashes.

#### Memory regions

In User Mode there are two main memory regions used for functions implementation: stack and heap.<br>
In Kernel Mode, up to Windows 10 19H1 (1903), there were kernel stack and kernel pool, which played similar role to the userland heap.<sup>2)</sup>

#### Drivers

Driver is a software interacts with the kernel and/or controls hardware resources. Drivers mainly let OS and hardware communicate with each other. It sits and waits for the system to call it when it needs something, like starting/using/controlling a hardware device. Then, the driver interprets incoming OS request and translates it into instructions understood by the device and vice versa. You can think of a driver as a DLL that is loaded into the kernel address space and executes with the same privilege as the kernel. A driver does not have a main execution thread; it contains code that can be called by the kernel when certain events occur. Such events may be interrupts or processes requiring the operating system to do stuff; the kernel handles those interrupts and may execute appropriate drivers to fulfill the requests.<sup>3)</sup><br>

After a driver is loaded, first piece of code that is called is a <code>DriverEntry</code> function:
```c++
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath
);
```
<span style="color:#00bfff">DriverObject</span> is a structure filled out by the I/O manager during the driver loading process. It holds information about the driver itself

<br><br>
Drivers receive requests from userland in form of standard APIs (like ReadFile or WriteFile) or I/O Control Codes (IOCTL), if the request does not fit into API. IOCTLs are data structures with several fields, containing information what action hardware needs to take.  
IOCTL is generated with DeviceIoControl API in user-mode and is passed to the kernel-mode I/O Manager. I/O Manager creates I/O Request Packet (IRP), which is a kernel structure used to represent I/O request as it moves around the kernel system. IRP has all the information that the driver needs to perform a given action on an IO request, including the IOCTL.
So when a program issues an IOCTL to a device, an IRP is created in kernel space to reflect that request.  
<br>
In summary, an IOCTL is a particular type of "miscellaneous" request to a device driver. An IRP is a data structure for managing all kinds of requests inside the Windows driver kernel architecture.<sup>4)</sup><br><br> 

![IOCTL flow](/assets/img/IOCTL_flow.png)
_IOCTL flow around the system_

## Vulnerability

The source code for the vulnerable method is located in [StackOverflow.c](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Exploit/StackOverflow.c)



<sup>1)</sup> https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/concepts-and-knowledge-for-all-driver-developers
<sup>2)</sup> In March 2019 Microsoft brought Segment Heap used in user land to the kernel<br>
<sup>3)</sup> https://voidsec.com/exploiting-system-mechanic-driver/<br>
<sup>4)</sup> https://stackoverflow.com/questions/18901467/what-is-the-difference-between-an-ioctl-and-an-irp



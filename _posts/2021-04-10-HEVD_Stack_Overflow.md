---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2021-04-13 09:00:00 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, drivers, windows, x86, shellcoding, kernel exploitation]
---


## HEVD

Over the next few posts in this series I am going to be looking at Windows kernel exploitation via the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). This is a wonderful piece of software with intentional bugs in it, created for those like me who are just starting out in Ring 0 exploitation.<br>There are multiple good articles out there explaining various HEVD vulnerabilities, so almost nothing I create in this blog will be new. However, I noticed that for every exploit I had to combine many different resources to really understand what the vulnerability is about and how to use it, as I could never find a single page that would do the job. Hence I decided to describe it once again for my own reference.

**I will not explain:**
+ how to install HEVD
+ how to set up a lab environment
+ basic subjects like buffer overflows theory, function calls, APIs etc.

To set up your lab, read e.g. [this](https://fluidattacks.com/blog/windows-kernel-debugging/) or [this](https://www.exploit-db.com/docs/44094). 

## Windows internals

Before we deep-dive into the exploitation, below is small refresher of most important concepts in Windows architecture. 

#### Modes

Windows operates in two modes:
+ **User Mode**: here, the executing code has limited power - it cannot for example access hardware directly or reference every memory address. To do this, code running in UM must use special APIs that will handle it.
+ **Kernel Mode**: here, the executing code has unrestricted access to the hardware, can use any CPU instruction or reference any memory address  

System drivers, like HEVD, operate in Kernel Mode. It means that if we are able to discover and exploit a vulnerability in the driver, we can force it to execute a piece of malicious code that we placed in UM (like shellcode) with high privileges stemming from the KM. 

#### Memory regions

In User Mode there are two main memory regions used for functions implementation: stack and heap.  
In Kernel Mode, up to Windows 10 19H1 (1903), there were kernel stack and kernel pool, which played similar role to the userland heap.<sup>1)</sup>

#### Drivers

Driver is a software that mainly lets OS and hardware communicate with each other. It sits and waits for the system to call it when it needs something, like starting/using/controlling a hardware device. Then, the driver interprets incoming OS request and translates it into instructions understood by the device and vice versa. You can think of drivers as loadable modules (like DLLs) containing code that will be executed when certain events occur. Such events may be interrupts or processes requiring the operating system to do stuff; the kernel handles those interrupts and may execute appropriate drivers to fulfill the requests.<sup>2)</sup>
<br><br>
Drivers receive requests from userland in form of standard APIs (like ReadFile or WriteFile) or I/O Control Codes (IOCTL), if the request does not fit into API. IOCTLs are data structures with several fields, containing information what action hardware needs to take.  
IOCTL is generated with DeviceIoControl API in user-mode and is passed to the kernel-mode I/O Manager. I/O Manager creates I/O Request Packet (IRP), which is a kernel structure used to represent I/O request as it moves around the kernel system. IRP has all the information that the driver needs to perform a given action on an IO request, including the IOCTL.
So when a program issues an IOCTL to a device, an IRP is created in kernel space to reflect that request.  
<br>
In summary, an IOCTL is a particular type of "miscellaneous" request to a device driver. An IRP is a data structure for managing all kinds of requests inside the Windows driver kernel architecture.<sup>3)</sup><br><br> 

![IOCTL flow](/assets/img/IOCTL_flow.png)
_IOCTL flow around the system_

## Vulnerability

The source code for the vulnerable method is located in [StackOverflow.c](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Exploit/StackOverflow.c)



<sup>1)</sup> In March 2019 Microsoft brought Segment Heap used in user land to the kernel<br>
<sup>2)</sup> https://voidsec.com/exploiting-system-mechanic-driver/<br>
<sup>3)</sup> https://stackoverflow.com/questions/18901467/what-is-the-difference-between-an-ioctl-and-an-irp



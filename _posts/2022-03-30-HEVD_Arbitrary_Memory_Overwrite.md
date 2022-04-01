---
layout: post
title: "HEVD: Arbitrary Memory Overwrite"
date: 2022-03-30 09:00:00 +0100
categories: [HEVD]
tags: [exploit, driver, x86, shellcode, kernel exploitation]
---


## <span class="myheader">Overview</span>

In the [previous post](/_posts/2022-01-04-HEVD_Stack_Overflow.md) we loaded HEVD driver and analyzed the Stack Buffer Overflow vulnerability. In this article we will try to understand another type of vulnerability, Arbitrary Memory Overwrite, also known as Write What Where. Write What Where is any condition where an attacker is able to write an arbitrary value (like shellcode address - the 'What') to an arbitrary location (like a pointer in a Kernel Dispatch Table - the 'Where').

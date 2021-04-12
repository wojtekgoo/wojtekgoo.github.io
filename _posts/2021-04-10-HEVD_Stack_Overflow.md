---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2021-04-10 16:33:46 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, drivers, windows, x86, shellcoding, kernel exploitation]
---

## Introduction
Hi, this is the first post on my blog so to humanize myself let me write few words why I created it.\
Having spent few years in cybersecurity, I decided I want to do some research on the Windows exploitation which has always fascinated me, but I never felt ready yet to do it seriously.
Finally, as I am fond of Offensive Security trainings, I booked a ticket for the [Advanced Windows Exploitation](https://www.offensive-security.com/awe-osee/) course. Although it did not happen due to the COVID-19 outbreak, I began extensive research in kernel exploitation. Here, I am blogging my progress as a way for me to reinforce concepts and keep notes I can reference later on.

## HEVD

This series will be about exploitation of the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). This is a wonderful piece of software with intentional bugs in it, created for those like me who are just starting out in Ring 0 exploitation. There are a ton of good blog posts out there walking through various HEVD exploits. Almost nothing I do or say in this blog will be new or my own thoughts/ideas/techniques. There were instances where I diverged from any strategies I saw employed in the blogposts out of necessity or me trying to do my own thing to learn more.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits.

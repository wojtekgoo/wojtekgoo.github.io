---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2021-04-13 09:00:00 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, drivers, windows, x86, shellcoding, kernel exploitation]
---

## Introduction
Hi, this is the first post on my blog so to humanize myself let me write few words why I created it.
<br>
Having spent few years in cybersecurity, I decided I want to do some research on the Windows exploitation which has always fascinated me, but I never felt ready yet to do it seriously.
Finally, as I am fond of Offensive Security trainings, I booked a ticket for the [Advanced Windows Exploitation](https://www.offensive-security.com/awe-osee/) course. Although it did not happen due to the COVID-19 outbreak, I began extensive research in kernel exploitation.<br> At some point I felt I have to organize my thoughts in more structured manner, so here I am blogging my progress as a way for me to reinforce concepts and keep notes I can reference later on. I hope blogging will force me to teach myself what I do not know and to articulate what I do know.

## HEVD

This series will be about exploitation of the [Hacksys Extreme Vulnerable Driver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver). This is a wonderful piece of software with intentional bugs in it, created for those like me who are just starting out in Ring 0 exploitation. <br>There are multiple good articles out there explaining various HEVD vulnerabilities, so almost nothing I create in this blog will be new. However, I noticed that for every exploit I had to combine many different resources to really understand what the vulnerability is about and how to use it, as I could never find a single page that would do the job. Hence I decided to describe it once again for my own reference.

**I will not explain:**
+ how to install HEVD
+ how to set up a lab environment

It is not interesting for me and 

---
layout: post
title: "Hello World"
date: 2021-04-09 16:33:46 +0100
categories: [Other]
tags: []
---

## Introduction
Welcome to my realm.
I decided to create this blog when I was preparing for the [Advanced Windows Exploitation](https://www.offensive-security.com/awe-osee/) course (which ultimately did not happen because of COVID). As I delved more and more into Windows Kernel programming and low-level stuff, I felt I need to reinforce concepts I was learning in a more organized manner.

**This series will be light on tangential information such as:**
+ how drivers work, the different types, communication between userland, the kernel, and drivers, etc
+ how to install HEVD,
+ how to set up a lab environment
+ shellcode analysis

The reason for this is simple, the other blog posts do a much better job detailing this information than I could ever hope to. It feels silly writing this blog series in the first place knowing that there are far superior posts out there; I will not make it even more silly by shoddily explaining these things at a high-level in poorer fashion than those aforementioned posts. Those authors have way more experience than I do and far superior knowledge, I will let them do the explaining. :)

This post/series will instead focus on my experience trying to craft the actual exploits.

## HEVD Series Change
I will no longer be using Python ctypes to write exploits. We will be using C++ from now on. I realize this is a big change for people following along so I've commented the code heavily. 
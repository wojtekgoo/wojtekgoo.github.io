---
layout: post
title: "HEVD: Stack Overflow exploitation"
date: 2022-01-04 09:00:00 +0100
categories: [HEVD, Stack Overflow]
tags: [exploit, drivers, x86, shellcoding, kernel exploitation]
---


## <span class="myheader">Loading HEVD driver</span>

In this post we will be exploiting the Stack Overflow vulnerability in the [HEVD](!https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) driver. Before that, I recommend to read the previous blogpost where I explain some basic concepts.

To load the driver, download first the pre-built executable from [here](!https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/releases) (or build it from source if you have too much time). Then, download and run the [OSR Driver Loader](https://www.osronline.com/article.cfm%5earticle=157.htm) to load the driver in the debugee:

![OSR tool](/assets/img/osr_tool.png)
_OSR Driver Loader_

If all went well, you should see a new driver in the list of loaded modules:

![HEVD loaded](/assets/img/windbg_loaded_hevd.png)
_HEVD loaded in the debugee_


## <span class="myheader">Vulnerability</span>

SOME TEXT

## <span class="myheader">Exploitation</span>

SOME TEXT
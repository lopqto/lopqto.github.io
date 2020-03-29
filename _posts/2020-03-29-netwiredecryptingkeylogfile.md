---
layout: post
title:  "Decrypting NetWire's keylog files"
date:   2020-03-29 00:00:00
categories: reverse-engineering malware-analysis
permalink: /posts/netwire-decrypting-keylog-file
---
NetWire is recently back to the malware trends again. This new variant of NetWire uses Guloader to distribute itself. After some observation, it seems that NetWire creators changed the encryption routine. In this analysis, I am going to present you how to reverse the new encryption routine and get a clean version of the keylog file.

### Background

According to the malpedia:
> Netwire is a RAT, its functionality seems focused on password stealing and keylogging, but includes remote control capabilities as well.
Keylog files are stored on the infected machine in an obfuscated form. [link!](https://malpedia.caad.fkie.fraunhofer.de/details/win.netwire)

Netwire has lots of functionalities such as taking remote control of infected PCs, keylogging, taking screenshots and extracting system information. NetWire creators added multiple data encryption layers to make a hard time for researchers. there are some sources out there about the decryption of implemented custom C&C binary protocol but there are limited sources (almost nothing) about decrypting keylog files.

### NetWire encryption routine

Let's follow the white rabbit down to the rabbit hole. After execution, NetWire makes a folder at `%APPDATA%/Logs` and saves keylog files there. I won't analyze the whole malware in this blog post, only the encryption routine since with some search, you can find public researchers about analyzing NetWire.

![keylog file in windows explore](/img/netwire-decrypting-keylog-file1.png)

We need to open NetWire in a disassembler (ida free will be enough) and find the correct function that writes to the log file. To achieve this goal we can look at the import section and search for `WriteFile` Windows API call. xrefing shows there are 2 locations that `WriteFile` got used.

![ida xref WriteFile](/img/netwire-decrypting-keylog-file2.png)

Let's look at the first one.

![ida disassembly window](/img/netwire-decrypting-keylog-file3.png)

Dissecting more shows us an interesting string. Probably in this block, NetWire tries to generate keylog file names like what we saw earlier.

![interesting string ](/img/netwire-decrypting-keylog-file4.png)

So Let's assume this is the right one and dig in more. To cheat we can fire up Ghidra with default config and try to analyze decompiled version of this function.

![ghidra decompile window](/img/netwire-decrypting-keylog-file5.png)

We can clean up the code to make it more human-readable. Investigating more shows us an interesting piece of code at the middle of the function. to make it more complicated NetWire tries to load every buffer in 4-bit chunks and do encryption stuff at every bit separately.

![encryption routine](/img/netwire-decrypting-keylog-file6.png)

And to make things clear we can estimate the algorithm is something like this:

``` python

for index in range(0, number_of_bytes_to_write):
    buffer[index] = ( buffer[index] ^ 0x9D ) + 0x24

```

Reversing this opration is easy. we need to do an operation like this:

``` python
(buffer[index] - 0x24) ^ 0x9D
```

### NetWire decryptor

I wrote a small python script that you can find [here](https://github.com/lopqto/YaraRules/blob/master/malwares/netwire/decrypt_netwire.py). Just pass the filename as argv and you can get the decrypted version of the keylog file in output.

![decryption example](/img/netwire-decrypting-keylog-file7.png)

### Read more

+ [Netwire at any.run](https://any.run/malware-trends/netwire)
+ [Netwire RC at malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.netwire)
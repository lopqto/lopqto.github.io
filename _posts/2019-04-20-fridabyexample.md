---
layout: post
title:  "Frida by example: bypassing IsDebuggerPresent() check"
date:   2019-04-20 15:30:00
categories: reverse-engineering malware-analysis
permalink: /posts/frida-by-example
---
Almost every malware exists out there has a functionally to make the post-detection analysis more difficult. Threat actors use various anti-debugging techniques, one of the more common ones used to check whether a debugger is on via IsDebuggerPresent() Windows API call. In this blog post, we will discuss how to bypass this technique by Frida.

### why Frida?
Frida is a dynamic instrumentation toolkit. It gives a simple interface where you can develop complex hooking logic rapidly and make changes to it as your requirements. Frida supports Windows, macOS, GNU/Linux, iOS, Android, and QNX.

### Prepare a sample PE
To allow us to dynamically test our function hooks I wrote a small Windows test application harness in C++. You can see the main functionality below, it's short and easy to understand.
``` c++
// target.cpp

#include <Windows.h>
#include <iostream>

int main()
{
        bool check = IsDebuggerPresent();
        if(check == 0)
        {
            std::cout << "cool!" << std::endl;
        }
        else
        {
            std::cout << "common .." << std::endl;
        }

        return 0;
}

```

Lets try to look at [IsDebuggerPresent()](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680345(v=vs.85).aspx) C++ function prototype.
``` c++
BOOL WINAPI IsDebuggerPresent(void);
```
According to Microsoft docs, if the current process is not running in the context of a debugger, the return value will be zero.

### Bypassing IsDebuggerPresent()
First of all, you need to install Frida, start from here: [documentation](https://www.frida.re/docs/installation/). You can test your installation by running `frida-ps.exe` in Powershell or CMD.

How The Frida works? Frida will inject Google's V8 engine to a specific process. After that it will run JavaScript code and generate a dynamic hook. Lets make our hand dirty and write some JavaScript codes. :)

For hooking purpose we will use `Interceptor` API. 
> `Interceptor.attach(target, callbacks)`: intercept calls to `target` function. it's a `NativePointer` specifying the address of the function you would like to intercept calls to.

To begin, we need to find the address of `IsDebuggerPresent()` function by using `DebugSymbol` API.

``` javascript
// poc.js

isDebuggerPresentAddr = DebugSymbol.getFunctionByName("IsDebuggerPresent")
console.log("function address : " + isDebuggerPresentAddr)
```

Using the `Interceptor`, we can quickly hook the application and write some basic JS to make `IsDebuggerPresnt` to always return 0. Notice the use of `isDebuggerPresentAddr` in the code.

``` javascript
// poc.js

Interceptor.attach(isDebuggerPresentAddr, {
        onEnter: function (args) {
			console.log("IsDebuggerPresent() get called ...");
        },
        onLeave: function (retval) {
			retval.replace(0);
        },
});
```

`retval` is a `NativePointer`-derived object containing the raw return value. We can use `replace()` to change the return value.

Now it's time to test the bypass method. First we spawn process without injecting our code:

``` powershell
frida.exe .\target.exe
```
Frida will stop on Entrypoint.Now try to attach your debugger to the `target.exe` process and then type `%resume` command to continue execution. debugger will be detected by the process.
![debugger got detect](/img/frida-by-example1.png)
Run the following command to inject our code and bypass the check:
``` powershell
frida.exe .\target.exe -l .\poc.js
```
You can see the result below.
![debugger not detect](/img/frida-by-example2.png)

The `IsDebuggerPresent()` has been bypassed successfully. :)

### References
+ [frida.re docs](https://www.frida.re/docs/javascript-api)
+ [Microsoft MSDN](https://docs.microsoft.com/en-us/windows/desktop/apiindex/api-index-portal)

### Read more
+ [Getting started with Dynamic Binary Analysis by Ali Mosajjal](https://blog.n0p.me/2018/03/2018-03-27-dynamic-binary-analysis/)
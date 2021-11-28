# Overview

`wausyscall` is a tool for extracting Windows syscall numbers from ntdll.dll
file on system. Should work fine on win32k.sys but haven't tested.

It supports only x86 Windows but can be easily ported to other architectures,
due to PE file portability, if provided with length of instructions prior to
syscall number move instruction.

# Usage & Installation

`cargo install --path .`

`cargo install --git <url to git repo>`

```
Usage: wausyscall <path to ntdll.dll> (function name)
```

Invoking `wausyscall` on Windows with no arguments should work fine, and 
default to system provided ntdll.dll file. If running on other system, 
a path to the file should be provided.

`Function name` argument is not required. When provided, it looks up syscall
number for the specified function name, but then on Windows, providing
a path to the dll is required.

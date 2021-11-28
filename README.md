# Overview

`wausyscall` is a tool for extracting Windows syscall numbers from usermode
syscall wrapper dlls such as ntdll.dll or win32u.dll

It supports only x86 Windows but can be easily ported to other architectures,
due to PE file portability, if provided with length of instructions prior to
syscall number move instruction, given that syscall wrapper function format is
the same.

# Usage & Installation

`cargo install --path .`

`cargo install --git <url to git repo>`

```
Usage: wausyscall <path> (function name) [--only-erroneus] [--help]
```

Invoking `wausyscall` on Windows with no arguments should work fine, and 
default to system provided ntdll.dll file. If running on other system, 
a path to the file should be provided.

`--only-erroneus` prints opcodes that are most likely improperly parsed.

`Function name` argument is not required. When provided, it looks up syscall
number for the specified function name, but then on Windows, providing
a path to the dll is required.

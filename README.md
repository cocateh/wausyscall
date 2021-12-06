# Overview

`wausyscall` is a tool for extracting Windows syscall numbers from usermode
syscall wrapper dlls such as ntdll.dll or win32u.dll.

It should support every platform Windows has ever run on natively so far!!
(i386, amd64, arm, arm64, alpha, mips, ppc, itanium).

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

# Limitations

Some of the functions which match to syscall regex, but are not syscalls,
will return incorrect output.

`--only-erroneus` flag tries to print out
problematic functions, yet it is not 100% accurate.


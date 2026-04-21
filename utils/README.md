# utils

This directory contains utility scripts used during the development and build process of KloudKnox.

## Contents

### syscallMap/genSyscallMap.py

A Python script that generates a Go source file mapping Linux syscall numbers to their names. The output is used by the KloudKnox monitor to translate raw syscall identifiers captured by eBPF into human-readable event names.

The script reads syscall definitions from the kernel header file `unistd_64.h`. It searches the following default paths:

- `/usr/include/asm/unistd_64.h`
- `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`

A custom path can be provided as a command-line argument if the header is located elsewhere.

#### Usage

Generate the syscall map using the default header path:

```bash
python3 syscallMap/genSyscallMap.py > ../KloudKnox/monitor/syscalls.go
```

Specify a custom header path:

```bash
python3 syscallMap/genSyscallMap.py /usr/include/asm/unistd_64.h > ../KloudKnox/monitor/syscalls.go
```

#### Output

The script emits a Go source file in the `monitor` package containing a map literal of the form:

```go
package monitor

var syscallNames = map[int32]string{
    0:   "read",
    1:   "write",
    2:   "open",
    // ...
}
```

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](../LICENSE) file for details.

---

Copyright 2026 [BoanLab](https://boanlab.com) @ Dankook University

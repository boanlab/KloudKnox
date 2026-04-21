// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

import (
	"fmt"
	"strings"
)

// getSyscallRetMessage Function
func getSyscallRetMessage(retval int32) string {
	if retval >= 0 {
		return "Success"
	}

	errno := -retval
	switch errno {
	case 1:
		return "Operation not permitted (EPERM)"
	case 2:
		return "No such file or directory (ENOENT)"
	case 3:
		return "No such process (ESRCH)"
	case 4:
		return "Interrupted system call (EINTR)"
	case 5:
		return "Input/output error (EIO)"
	case 6:
		return "No such device or address (ENXIO)"
	case 7:
		return "Argument list too long (E2BIG)"
	case 8:
		return "Exec format error (ENOEXEC)"
	case 9:
		return "Bad file descriptor (EBADF)"
	case 10:
		return "No child processes (ECHILD)"
	case 11:
		return "Resource temporarily unavailable (EAGAIN)"
	case 12:
		return "Out of memory (ENOMEM)"
	case 13:
		return "Permission denied (EACCES)"
	case 14:
		return "Bad address (EFAULT)"
	case 17:
		return "File exists (EEXIST)"
	case 19:
		return "No such device (ENODEV)"
	case 20:
		return "Not a directory (ENOTDIR)"
	case 21:
		return "Is a directory (EISDIR)"
	case 22:
		return "Invalid argument (EINVAL)"
	case 23:
		return "File table overflow (ENFILE)"
	case 24:
		return "Too many open files (EMFILE)"
	case 30:
		return "Read-only file system (EROFS)"
	case 32:
		return "Broken pipe (EPIPE)"
	case 95:
		return "Operation not supported (EOPNOTSUPP)"
	case 98:
		return "Address already in use (EADDRINUSE)"
	case 99:
		return "Cannot assign requested address (EADDRNOTAVAIL)"
	case 100:
		return "Network is down (ENETDOWN)"
	case 101:
		return "Network is unreachable (ENETUNREACH)"
	case 110:
		return "Connection timed out (ETIMEDOUT)"
	case 111:
		return "Connection refused (ECONNREFUSED)"
	case 113:
		return "No route to host (EHOSTUNREACH)"
	case 115:
		return "Operation now in progress (EINPROGRESS)"
	default:
		return fmt.Sprintf("Error (%d)", errno)
	}
}

// getCloneFlags Function
func getCloneFlags(flags uint64) string {
	var f []string

	if flags&0x00000100 != 0 {
		f = append(f, "CLONE_VM")
	}
	if flags&0x00000200 != 0 {
		f = append(f, "CLONE_FS")
	}
	if flags&0x00000400 != 0 {
		f = append(f, "CLONE_FILES")
	}
	if flags&0x00000800 != 0 {
		f = append(f, "CLONE_SIGHAND")
	}
	if flags&0x00002000 != 0 {
		f = append(f, "CLONE_PTRACE")
	}
	if flags&0x00004000 != 0 {
		f = append(f, "CLONE_VFORK")
	}
	if flags&0x00008000 != 0 {
		f = append(f, "CLONE_PARENT")
	}
	if flags&0x00010000 != 0 {
		f = append(f, "CLONE_THREAD")
	}
	if flags&0x00020000 != 0 {
		f = append(f, "CLONE_NEWNS")
	}
	if flags&0x00040000 != 0 {
		f = append(f, "CLONE_SYSVSEM")
	}
	if flags&0x00080000 != 0 {
		f = append(f, "CLONE_SETTLS")
	}
	if flags&0x00100000 != 0 {
		f = append(f, "CLONE_PARENT_SETTID")
	}
	if flags&0x00200000 != 0 {
		f = append(f, "CLONE_CHILD_CLEARTID")
	}
	if flags&0x00800000 != 0 {
		f = append(f, "CLONE_UNTRACED")
	}
	if flags&0x01000000 != 0 {
		f = append(f, "CLONE_CHILD_SETTID")
	}
	if flags&0x02000000 != 0 {
		f = append(f, "CLONE_NEWCGROUP")
	}
	if flags&0x04000000 != 0 {
		f = append(f, "CLONE_NEWUTS")
	}
	if flags&0x08000000 != 0 {
		f = append(f, "CLONE_NEWIPC")
	}
	if flags&0x10000000 != 0 {
		f = append(f, "CLONE_NEWUSER")
	}
	if flags&0x20000000 != 0 {
		f = append(f, "CLONE_NEWPID")
	}
	if flags&0x40000000 != 0 {
		f = append(f, "CLONE_NEWNET")
	}
	if flags&0x80000000 != 0 {
		f = append(f, "CLONE_IO")
	}

	// clone3-specific
	if flags&0x00001000_0000 != 0 {
		f = append(f, "CLONE_INTO_CGROUP")
	}
	if flags&0x00010000_0000 != 0 {
		f = append(f, "CLONE_NEWTIME")
	}
	if flags&0x00100000_0000 != 0 {
		f = append(f, "CLONE_PIDFD")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x", flags)
	}
	return strings.Join(f, "|")
}

// getExecveAtFlags Function
func getExecveAtFlags(flags int32) string {
	var f []string

	if flags&0x01 != 0 {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}
	if flags&0x1000 != 0 {
		f = append(f, "AT_EMPTY_PATH")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x", flags)
	}

	return strings.Join(f, "|")
}

// getSignal Function
func getSignal(sig int32) string {
	switch sig {
	case 0:
		return "NULL (check only)"
	case 1:
		return "SIGHUP"
	case 2:
		return "SIGINT"
	case 3:
		return "SIGQUIT"
	case 4:
		return "SIGILL"
	case 5:
		return "SIGTRAP"
	case 6:
		return "SIGABRT"
	case 7:
		return "SIGBUS"
	case 8:
		return "SIGFPE"
	case 9:
		return "SIGKILL"
	case 10:
		return "SIGUSR1"
	case 11:
		return "SIGSEGV"
	case 12:
		return "SIGUSR2"
	case 13:
		return "SIGPIPE"
	case 14:
		return "SIGALRM"
	case 15:
		return "SIGTERM"
	case 16:
		return "SIGSTKFLT"
	case 17:
		return "SIGCHLD"
	case 18:
		return "SIGCONT"
	case 19:
		return "SIGSTOP"
	case 20:
		return "SIGTSTP"
	case 21:
		return "SIGTTIN"
	case 22:
		return "SIGTTOU"
	case 23:
		return "SIGURG"
	case 24:
		return "SIGXCPU"
	case 25:
		return "SIGXFSZ"
	case 26:
		return "SIGVTALRM"
	case 27:
		return "SIGPROF"
	case 28:
		return "SIGWINCH"
	case 29:
		return "SIGIO"
	case 30:
		return "SIGPWR"
	case 31:
		return "SIGSYS"
	default:
		return fmt.Sprintf("SIG(%d)", sig)
	}
}

// getUnshareFlags Function
func getUnshareFlags(flags int32) string {
	var f []string

	if flags&0x00000200 != 0 {
		f = append(f, "CLONE_FS")
	}
	if flags&0x00000400 != 0 {
		f = append(f, "CLONE_FILES")
	}
	if flags&0x00020000 != 0 {
		f = append(f, "CLONE_NEWNS")
	}
	if flags&0x00040000 != 0 {
		f = append(f, "CLONE_SYSVSEM")
	}
	if flags&0x02000000 != 0 {
		f = append(f, "CLONE_NEWCGROUP")
	}
	if flags&0x04000000 != 0 {
		f = append(f, "CLONE_NEWUTS")
	}
	if flags&0x08000000 != 0 {
		f = append(f, "CLONE_NEWIPC")
	}
	if flags&0x10000000 != 0 {
		f = append(f, "CLONE_NEWUSER")
	}
	if flags&0x20000000 != 0 {
		f = append(f, "CLONE_NEWPID")
	}
	if flags&0x40000000 != 0 {
		f = append(f, "CLONE_NEWNET")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x", flags)
	}
	return strings.Join(f, "|")
}

// getSetNSType Function
func getSetNSType(flags int32) string {
	var f []string

	if flags&0x00020000 != 0 {
		f = append(f, "CLONE_NEWNS")
	}
	if flags&0x02000000 != 0 {
		f = append(f, "CLONE_NEWCGROUP")
	}
	if flags&0x04000000 != 0 {
		f = append(f, "CLONE_NEWUTS")
	}
	if flags&0x08000000 != 0 {
		f = append(f, "CLONE_NEWIPC")
	}
	if flags&0x10000000 != 0 {
		f = append(f, "CLONE_NEWUSER")
	}
	if flags&0x20000000 != 0 {
		f = append(f, "CLONE_NEWPID")
	}
	if flags&0x40000000 != 0 {
		f = append(f, "CLONE_NEWNET")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x", flags)
	}
	return strings.Join(f, "|")
}

// getRlimitResource Function
func getRlimitResource(resource uint32) string {
	switch resource {
	case 0:
		return "RLIMIT_CPU"
	case 1:
		return "RLIMIT_FSIZE"
	case 2:
		return "RLIMIT_DATA"
	case 3:
		return "RLIMIT_STACK"
	case 4:
		return "RLIMIT_CORE"
	case 5:
		return "RLIMIT_RSS"
	case 6:
		return "RLIMIT_NPROC"
	case 7:
		return "RLIMIT_NOFILE"
	case 8:
		return "RLIMIT_MEMLOCK"
	case 9:
		return "RLIMIT_AS"
	case 10:
		return "RLIMIT_LOCKS"
	case 11:
		return "RLIMIT_SIGPENDING"
	case 12:
		return "RLIMIT_MSGQUEUE"
	case 13:
		return "RLIMIT_NICE"
	case 14:
		return "RLIMIT_RTPRIO"
	case 15:
		return "RLIMIT_RTTIME"
	case 16:
		return "RLIMIT_NLIMITS" // optional, not commonly used
	default:
		return fmt.Sprintf("%d", resource)
	}
}

// getCapabilities Function
func getCapabilities(caps uint32) string {
	capNames := []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_DAC_READ_SEARCH",
		"CAP_FOWNER",
		"CAP_FSETID",
		"CAP_KILL",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETPCAP",
		"CAP_LINUX_IMMUTABLE",
		"CAP_NET_BIND_SERVICE",
		"CAP_NET_BROADCAST",
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_IPC_LOCK",
		"CAP_IPC_OWNER",
		"CAP_SYS_MODULE",
		"CAP_SYS_RAWIO",
		"CAP_SYS_CHROOT",
		"CAP_SYS_PTRACE",
		"CAP_SYS_PACCT",
		"CAP_SYS_ADMIN",
		"CAP_SYS_BOOT",
		"CAP_SYS_NICE",
		"CAP_SYS_RESOURCE",
		"CAP_SYS_TIME",
		"CAP_SYS_TTY_CONFIG",
		"CAP_MKNOD",
		"CAP_LEASE",
		"CAP_AUDIT_WRITE",
		"CAP_AUDIT_CONTROL",
		"CAP_SETFCAP",
	}

	var out []string
	for i := uint(0); i < uint(len(capNames)); i++ {
		if caps&(1<<i) != 0 {
			out = append(out, capNames[i])
		}
	}

	if len(out) == 0 {
		return fmt.Sprintf("%#x (none)", caps)
	}
	return strings.Join(out, "|")
}

// getPtraceRequest Function
func getPtraceRequest(req int32) string {
	switch req {
	case 0:
		return "PTRACE_TRACEME"
	case 1:
		return "PTRACE_PEEKTEXT"
	case 2:
		return "PTRACE_PEEKDATA"
	case 3:
		return "PTRACE_PEEKUSER"
	case 4:
		return "PTRACE_POKETEXT"
	case 5:
		return "PTRACE_POKEDATA"
	case 6:
		return "PTRACE_POKEUSER"
	case 7:
		return "PTRACE_CONT"
	case 8:
		return "PTRACE_KILL"
	case 9:
		return "PTRACE_SINGLESTEP"
	case 12:
		return "PTRACE_GETREGS"
	case 13:
		return "PTRACE_SETREGS"
	case 14:
		return "PTRACE_GETFPREGS"
	case 15:
		return "PTRACE_SETFPREGS"
	case 16:
		return "PTRACE_ATTACH"
	case 17:
		return "PTRACE_DETACH"
	case 18:
		return "PTRACE_GETFPXREGS"
	case 19:
		return "PTRACE_SETFPXREGS"
	case 24:
		return "PTRACE_SYSCALL"
	case 25:
		return "PTRACE_SETOPTIONS"
	case 26:
		return "PTRACE_GETEVENTMSG"
	case 27:
		return "PTRACE_GETSIGINFO"
	case 28:
		return "PTRACE_SETSIGINFO"
	case 29:
		return "PTRACE_GETREGSET"
	case 30:
		return "PTRACE_SETREGSET"
	case 31:
		return "PTRACE_SEIZE"
	case 32:
		return "PTRACE_INTERRUPT"
	case 33:
		return "PTRACE_LISTEN"
	case 34:
		return "PTRACE_PEEKSIGINFO"
	case 0x4200:
		return "PTRACE_GET_SYSCALL_INFO"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", req)
	}
}

// getOpenFlags Function
func getOpenFlags(flags int32) string {
	var f []string

	// Access mode (must check lower 2 bits)
	switch flags & 0x3 {
	case 0:
		f = append(f, "O_RDONLY")
	case 1:
		f = append(f, "O_WRONLY")
	case 2:
		f = append(f, "O_RDWR")
	}

	if flags&0x40 != 0 {
		f = append(f, "O_CREAT")
	}
	if flags&0x80 != 0 {
		f = append(f, "O_EXCL")
	}
	if flags&0x100 != 0 {
		f = append(f, "O_NOCTTY")
	}
	if flags&0x200 != 0 {
		f = append(f, "O_TRUNC")
	}
	if flags&0x400 != 0 {
		f = append(f, "O_APPEND")
	}
	if flags&0x800 != 0 {
		f = append(f, "O_NONBLOCK")
	}
	if flags&0x8000 != 0 {
		f = append(f, "O_SYNC")
	}
	if flags&0x2000 != 0 {
		f = append(f, "O_ASYNC")
	}
	if flags&0x10000 != 0 {
		f = append(f, "O_LARGEFILE")
	}
	if flags&0x20000 != 0 {
		f = append(f, "O_DIRECTORY")
	}
	if flags&0x40000 != 0 {
		f = append(f, "O_NOFOLLOW")
	}
	if flags&0x80000 != 0 {
		f = append(f, "O_DIRECT")
	}
	if flags&0x100000 != 0 {
		f = append(f, "O_NOATIME")
	}
	if flags&0x200000 != 0 {
		f = append(f, "O_CLOEXEC")
	}
	if flags&0x400000 != 0 {
		f = append(f, "O_PATH")
	}
	if flags&0x2000000 != 0 {
		f = append(f, "O_TMPFILE")
	}
	if flags&0x4000000 != 0 {
		f = append(f, "O_DSYNC")
	}
	if flags&0x40000000 != 0 {
		f = append(f, "O_RSYNC") // rarely used
	}

	return strings.Join(f, "|")
}

// getMode Function
func getMode(mode uint32) string {
	return fmt.Sprintf("%04o", mode&0o7777)
}

// getResolveFlags Function
func getResolveFlags(resolve uint64) string {
	var f []string

	if resolve&0x01 != 0 {
		f = append(f, "RESOLVE_NO_XDEV")
	}
	if resolve&0x02 != 0 {
		f = append(f, "RESOLVE_NO_MAGICLINKS")
	}
	if resolve&0x04 != 0 {
		f = append(f, "RESOLVE_NO_SYMLINKS")
	}
	if resolve&0x08 != 0 {
		f = append(f, "RESOLVE_BENEATH")
	}
	if resolve&0x10 != 0 {
		f = append(f, "RESOLVE_IN_ROOT")
	}
	if resolve&0x20 != 0 {
		f = append(f, "RESOLVE_CACHED")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x", resolve)
	}

	return strings.Join(f, "|")
}

// getFchownAtFlags Function
func getFchownAtFlags(flags int32) string {
	var f []string

	if flags&0x100 == 0x100 {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x (default)", flags) // 0x0 (default)
	}

	return strings.Join(f, "|")
}

// getUnlinkAtFlags Function
func getUnlinkAtFlags(flags int32) string {
	var f []string

	if flags&0x200 != 0 {
		f = append(f, "AT_REMOVEDIR")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x (default)", flags) // 0x0
	}

	return strings.Join(f, "|")
}

// getRenameAt2Flags Function
func getRenameAt2Flags(flags uint32) string {
	var f []string

	if flags&0x01 != 0 {
		f = append(f, "RENAME_NOREPLACE")
	}
	if flags&0x02 != 0 {
		f = append(f, "RENAME_EXCHANGE")
	}
	if flags&0x04 != 0 {
		f = append(f, "RENAME_WHITEOUT")
	}
	if flags&0x10 != 0 {
		f = append(f, "RENAME_ATOMIC")
	}
	if flags&0x20 != 0 {
		f = append(f, "RENAME_EMPTY")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x (default)", flags)
	}

	return strings.Join(f, "|")
}

// getLinkAtFlags Function
func getLinkAtFlags(flags int32) string {
	var f []string

	if flags&0x400 != 0 {
		f = append(f, "AT_SYMLINK_FOLLOW")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x (default)", flags) // 0x0
	}

	return strings.Join(f, "|")
}

// getMountFlags Function
func getMountFlags(flags uint64) string {
	var f []string

	if flags&0x00000001 != 0 {
		f = append(f, "MS_RDONLY")
	}
	if flags&0x00000002 != 0 {
		f = append(f, "MS_NOSUID")
	}
	if flags&0x00000004 != 0 {
		f = append(f, "MS_NODEV")
	}
	if flags&0x00000008 != 0 {
		f = append(f, "MS_NOEXEC")
	}
	if flags&0x00000010 != 0 {
		f = append(f, "MS_SYNCHRONOUS")
	}
	if flags&0x00000020 != 0 {
		f = append(f, "MS_REMOUNT")
	}
	if flags&0x00000040 != 0 {
		f = append(f, "MS_MANDLOCK")
	}
	if flags&0x00000080 != 0 {
		f = append(f, "MS_DIRSYNC")
	}
	if flags&0x00000100 != 0 {
		f = append(f, "MS_NOATIME")
	}
	if flags&0x00000200 != 0 {
		f = append(f, "MS_NODIRATIME")
	}
	if flags&0x00000400 != 0 {
		f = append(f, "MS_BIND")
	}
	if flags&0x00000800 != 0 {
		f = append(f, "MS_MOVE")
	}
	if flags&0x00001000 != 0 {
		f = append(f, "MS_REC")
	}
	if flags&0x00002000 != 0 {
		f = append(f, "MS_SILENT")
	}
	if flags&0x00004000 != 0 {
		f = append(f, "MS_POSIXACL")
	}
	if flags&0x00008000 != 0 {
		f = append(f, "MS_UNBINDABLE")
	}
	if flags&0x00010000 != 0 {
		f = append(f, "MS_PRIVATE")
	}
	if flags&0x00020000 != 0 {
		f = append(f, "MS_SLAVE")
	}
	if flags&0x00040000 != 0 {
		f = append(f, "MS_SHARED")
	}
	if flags&0x00080000 != 0 {
		f = append(f, "MS_RELATIME")
	}
	if flags&0x00100000 != 0 {
		f = append(f, "MS_ACTIVE") // internal
	}
	if flags&0x00200000 != 0 {
		f = append(f, "MS_NOUSER") // internal
	}
	if flags&0x00400000 != 0 {
		f = append(f, "MS_STRICTATIME")
	}
	if flags&0x01000000 != 0 {
		f = append(f, "MS_LAZYTIME")
	}

	if len(f) == 0 {
		return fmt.Sprintf("%#x (default)", flags)
	}
	return strings.Join(f, "|")
}

// getSocketFamily Function
func getSocketFamily(family int32) string {
	switch family {
	case 0:
		return "AF_UNSPEC"
	case 1:
		return "AF_UNIX" // or AF_LOCAL
	case 2:
		return "AF_INET"
	case 3:
		return "AF_AX25"
	case 4:
		return "AF_IPX"
	case 5:
		return "AF_APPLETALK"
	case 6:
		return "AF_NETROM"
	case 7:
		return "AF_BRIDGE"
	case 8:
		return "AF_ATMPVC"
	case 9:
		return "AF_X25"
	case 10:
		return "AF_INET6"
	case 11:
		return "AF_ROSE"
	case 12:
		return "AF_DECnet"
	case 13:
		return "AF_NETBEUI" // obsolete
	case 14:
		return "AF_SECURITY" // unused
	case 15:
		return "AF_KEY" // PF_KEY key management
	case 16:
		return "AF_NETLINK" // or AF_ROUTE
	case 17:
		return "AF_PACKET"
	case 18:
		return "AF_ASH"
	case 19:
		return "AF_ECONET"
	case 20:
		return "AF_ATMSVC"
	case 21:
		return "AF_RDS"
	case 22:
		return "AF_SNA"
	case 23:
		return "AF_IRDA"
	case 24:
		return "AF_PPPOX"
	case 25:
		return "AF_WANPIPE"
	case 26:
		return "AF_LLC"
	case 27:
		return "AF_IB"
	case 28:
		return "AF_MPLS"
	case 29:
		return "AF_CAN"
	case 30:
		return "AF_TIPC"
	case 31:
		return "AF_BLUETOOTH"
	case 32:
		return "AF_IUCV"
	case 33:
		return "AF_RXRPC"
	case 34:
		return "AF_ISDN"
	case 35:
		return "AF_PHONET"
	case 36:
		return "AF_IEEE802154"
	case 37:
		return "AF_CAIF"
	case 38:
		return "AF_ALG"
	case 39:
		return "AF_NFC"
	case 40:
		return "AF_VSOCK"
	case 41:
		return "AF_KCM"
	case 42:
		return "AF_QIPCRTR"
	case 43:
		return "AF_SMC"
	case 44:
		return "AF_XDP"
	case 45:
		return "AF_MCTP"
	case 46:
		return "AF_MAX"
	default:
		return fmt.Sprintf("AF_UNKNOWN(%d)", family)
	}
}

// getSocketType Function
func getSocketType(sockType int32) string {
	var out []string

	// lower 4 bits = socket type
	switch sockType & 0xf {
	case 1:
		out = append(out, "SOCK_STREAM")
	case 2:
		out = append(out, "SOCK_DGRAM")
	case 3:
		out = append(out, "SOCK_RAW")
	case 4:
		out = append(out, "SOCK_RDM")
	case 5:
		out = append(out, "SOCK_SEQPACKET")
	case 6:
		out = append(out, "SOCK_DCCP")
	case 10:
		out = append(out, "SOCK_PACKET")
	default:
		out = append(out, fmt.Sprintf("SOCK_UNKNOWN(%d)", sockType&0xf))
	}

	return strings.Join(out, "|")
}

// getSocketFlags Function
func getSocketFlags(flags int32) string {
	var out []string

	// flags (upper bits)
	if flags&0x80000 != 0 {
		out = append(out, "SOCK_NONBLOCK")
	}
	if flags&0x40000 != 0 {
		out = append(out, "SOCK_CLOEXEC")
	}
	if flags&0x200000 != 0 {
		out = append(out, "SOCK_NOFILE") // rarely used
	}
	if flags&0x100000 != 0 {
		out = append(out, "SOCK_NOSIGPIPE") // macOS/BSD only (ignored on Linux)
	}
	if flags&0x10000 != 0 {
		out = append(out, "SOCK_NO_LINGER") // obsolete in Linux
	}

	return strings.Join(out, "|")
}

// getSocketProtocol Function
func getSocketProtocol(family int32, sockType int32, protocol int32) string {
	switch family {
	case 2, 10: // AF_INET / AF_INET6
		return parseIPProto(sockType, protocol)
	case 16: // AF_NETLINK
		return getNetlinkProtocol(protocol)
	case 17: // AF_PACKET
		return getEthProtocol(protocol)
	default:
		return fmt.Sprintf("PROTO_%d", protocol)
	}
}

func parseIPProto(sockType, proto int32) string {
	if proto == 0 {
		switch sockType & 0xf {
		case 1: // SOCK_STREAM
			return "IPPROTO_TCP"
		case 2: // SOCK_DGRAM
			return "IPPROTO_UDP"
		case 3: // SOCK_RAW
			return "IPPROTO_IP"
		default:
			return "IPPROTO_IP"
		}
	}
	return getIPProtocol(proto)
}

func getIPProtocol(proto int32) string {
	switch proto {
	case 0:
		return "IPPROTO_IP"
	case 1:
		return "IPPROTO_ICMP"
	case 2:
		return "IPPROTO_IGMP"
	case 3:
		return "IPPROTO_GGP"
	case 4:
		return "IPPROTO_IPIP"
	case 5:
		return "IPPROTO_ST"
	case 6:
		return "IPPROTO_TCP"
	case 7:
		return "IPPROTO_CBT"
	case 8:
		return "IPPROTO_EGP"
	case 9:
		return "IPPROTO_IGP"
	case 10:
		return "IPPROTO_BBN_RCC_MON"
	case 11:
		return "IPPROTO_NVP_II"
	case 12:
		return "IPPROTO_PUP"
	case 13:
		return "IPPROTO_ARGUS"
	case 14:
		return "IPPROTO_EMCON"
	case 15:
		return "IPPROTO_XNET"
	case 16:
		return "IPPROTO_CHAOS"
	case 17:
		return "IPPROTO_UDP"
	case 18:
		return "IPPROTO_MUX"
	case 19:
		return "IPPROTO_DCN_MEAS"
	case 20:
		return "IPPROTO_HMP"
	case 21:
		return "IPPROTO_PRM"
	case 22:
		return "IPPROTO_XNS_IDP"
	case 23:
		return "IPPROTO_TRUNK1"
	case 24:
		return "IPPROTO_TRUNK2"
	case 25:
		return "IPPROTO_LEAF1"
	case 26:
		return "IPPROTO_LEAF2"
	case 27:
		return "IPPROTO_RDP"
	case 28:
		return "IPPROTO_IRTP"
	case 29:
		return "IPPROTO_TP"
	case 30:
		return "IPPROTO_NETBLT"
	case 31:
		return "IPPROTO_MFE_NSP"
	case 32:
		return "IPPROTO_MERIT_INP"
	case 33:
		return "IPPROTO_DCCP"
	case 34:
		return "IPPROTO_3PC"
	case 35:
		return "IPPROTO_IDPR"
	case 36:
		return "IPPROTO_XTP"
	case 37:
		return "IPPROTO_DDP"
	case 38:
		return "IPPROTO_IDPR_CMTP"
	case 39:
		return "IPPROTO_TP_PLUS"
	case 40:
		return "IPPROTO_IL"
	case 41:
		return "IPPROTO_IPV6"
	case 42:
		return "IPPROTO_SDRP"
	case 43:
		return "IPPROTO_ROUTING"
	case 44:
		return "IPPROTO_FRAGMENT"
	case 45:
		return "IPPROTO_IDRP"
	case 46:
		return "IPPROTO_RSVP"
	case 47:
		return "IPPROTO_GRE"
	case 48:
		return "IPPROTO_DSR"
	case 49:
		return "IPPROTO_BNA"
	case 50:
		return "IPPROTO_ESP"
	case 51:
		return "IPPROTO_AH"
	case 52:
		return "IPPROTO_INLSP"
	case 53:
		return "IPPROTO_SWIPE"
	case 54:
		return "IPPROTO_NARP"
	case 55:
		return "IPPROTO_MOBILE"
	case 56:
		return "IPPROTO_TLSP"
	case 57:
		return "IPPROTO_SKIP"
	case 58:
		return "IPPROTO_ICMPV6"
	case 59:
		return "IPPROTO_NONE"
	case 60:
		return "IPPROTO_DSTOPTS"
	case 61:
		return "IPPROTO_AHIP"
	case 62:
		return "IPPROTO_CFTP"
	case 63:
		return "IPPROTO_LOCAL"
	case 64:
		return "IPPROTO_SAT_EXPAK"
	case 65:
		return "IPPROTO_KRYPTOLAN"
	case 66:
		return "IPPROTO_RVD"
	case 67:
		return "IPPROTO_IPPC"
	case 68:
		return "IPPROTO_SAT_MON"
	case 69:
		return "IPPROTO_VISA"
	case 70:
		return "IPPROTO_IPCV"
	case 71:
		return "IPPROTO_CPNX"
	case 72:
		return "IPPROTO_CPHB"
	case 73:
		return "IPPROTO_WSN"
	case 74:
		return "IPPROTO_PVP"
	case 75:
		return "IPPROTO_BR_SAT_MON"
	case 76:
		return "IPPROTO_SUN_ND"
	case 77:
		return "IPPROTO_WB_MON"
	case 78:
		return "IPPROTO_WB_EXPAK"
	case 79:
		return "IPPROTO_ISO_IP"
	case 80:
		return "IPPROTO_VMTP"
	case 81:
		return "IPPROTO_SECURE_VMTP"
	case 82:
		return "IPPROTO_VINES"
	case 83:
		return "IPPROTO_TTP"
	case 84:
		return "IPPROTO_NSFNET_IGP"
	case 85:
		return "IPPROTO_DGP"
	case 86:
		return "IPPROTO_TCF"
	case 87:
		return "IPPROTO_EIGRP"
	case 88:
		return "IPPROTO_OSPF"
	case 89:
		return "IPPROTO_SPRITE_RPC"
	case 90:
		return "IPPROTO_LARP"
	case 91:
		return "IPPROTO_MTP"
	case 92:
		return "IPPROTO_AX25"
	case 93:
		return "IPPROTO_IPIP_ENCAP"
	case 94:
		return "IPPROTO_MICP"
	case 95:
		return "IPPROTO_SCC_SP"
	case 96:
		return "IPPROTO_ETHERIP"
	case 97:
		return "IPPROTO_ENCAP"
	case 98:
		return "IPPROTO_GMTP"
	case 99:
		return "IPPROTO_IFMP"
	case 100:
		return "IPPROTO_PNNI"
	case 101:
		return "IPPROTO_PIM"
	case 102:
		return "IPPROTO_ARIS"
	case 103:
		return "IPPROTO_SCPS"
	case 104:
		return "IPPROTO_QNX"
	case 105:
		return "IPPROTO_AN"
	case 106:
		return "IPPROTO_IPCOMP"
	case 107:
		return "IPPROTO_SNP"
	case 108:
		return "IPPROTO_COMPAQ_PEER"
	case 109:
		return "IPPROTO_IPX_IN_IP"
	case 110:
		return "IPPROTO_VRRP"
	case 111:
		return "IPPROTO_PGM"
	case 112:
		return "IPPROTO_L2TP"
	case 113:
		return "IPPROTO_DDX"
	case 114:
		return "IPPROTO_IATP"
	case 115:
		return "IPPROTO_STP"
	case 116:
		return "IPPROTO_SRP"
	case 117:
		return "IPPROTO_UTI"
	case 118:
		return "IPPROTO_SMP"
	case 119:
		return "IPPROTO_SM"
	case 120:
		return "IPPROTO_PTP"
	case 121:
		return "IPPROTO_ISIS"
	case 122:
		return "IPPROTO_FIRE"
	case 123:
		return "IPPROTO_CRTP"
	case 124:
		return "IPPROTO_CRUDP"
	case 125:
		return "IPPROTO_SSCOPMCE"
	case 126:
		return "IPPROTO_IPLT"
	case 127:
		return "IPPROTO_SPS"
	case 128:
		return "IPPROTO_PIPE"
	case 129:
		return "IPPROTO_FC"
	case 130:
		return "IPPROTO_RSVP_E2E_IGNORE"
	case 131:
		return "IPPROTO_MOBILITY"
	case 132:
		return "IPPROTO_SCTP"
	case 133:
		return "IPPROTO_UDPLITE"
	case 134:
		return "IPPROTO_MPLS_IN_IP"
	case 135:
		return "IPPROTO_MANET"
	case 136:
		return "IPPROTO_HIP"
	case 137:
		return "IPPROTO_SHIM6"
	case 138:
		return "IPPROTO_WESP"
	case 139:
		return "IPPROTO_ROHC"
	case 255:
		return "IPPROTO_RAW"
	default:
		return fmt.Sprintf("IPPROTO_UNKNOWN(%d)", proto)
	}
}

func getNetlinkProtocol(proto int32) string {
	switch proto {
	case 0:
		return "NETLINK_ROUTE"
	case 1:
		return "NETLINK_UNUSED"
	case 2:
		return "NETLINK_USERSOCK"
	case 3:
		return "NETLINK_FIREWALL"
	case 4:
		return "NETLINK_INET_DIAG"
	case 5:
		return "NETLINK_NFLOG"
	case 6:
		return "NETLINK_XFRM"
	case 7:
		return "NETLINK_SELINUX"
	case 8:
		return "NETLINK_ISCSI"
	case 9:
		return "NETLINK_AUDIT"
	case 10:
		return "NETLINK_FIB_LOOKUP"
	case 11:
		return "NETLINK_CONNECTOR"
	case 12:
		return "NETLINK_NETFILTER"
	case 13:
		return "NETLINK_IP6_FW"
	case 14:
		return "NETLINK_DNRTMSG"
	case 15:
		return "NETLINK_KOBJECT_UEVENT"
	case 16:
		return "NETLINK_GENERIC"
	case 17:
		return "NETLINK_SCSITRANSPORT"
	case 18:
		return "NETLINK_ECRYPTFS"
	case 19:
		return "NETLINK_RDMA"
	case 20:
		return "NETLINK_CRYPTO"
	case 21:
		return "NETLINK_SMC"
	default:
		return fmt.Sprintf("NETLINK_%d", proto)
	}
}

func ntohs16(x uint16) uint16 {
	return (x<<8)&0xff00 | (x>>8)&0x00ff
}

func getEthProtocol(proto int32) string {
	if proto < 0 || proto > int32(^uint16(0)) {
		return "ETH_P_UNKNOWN"
	}

	eth := ntohs16(uint16(proto))
	switch eth {
	case 0x0003:
		return "ETH_P_ALL(0x0003)"
	case 0x0800:
		return "ETH_P_IP(0x0800)"
	case 0x0806:
		return "ETH_P_ARP(0x0806)"
	case 0x8035:
		return "ETH_P_RARP(0x8035)"
	case 0x86DD:
		return "ETH_P_IPV6(0x86DD)"
	case 0x8100:
		return "ETH_P_8021Q(0x8100)"
	case 0x88A8:
		return "ETH_P_8021AD(0x88A8)"
	case 0x8847:
		return "ETH_P_MPLS_UC(0x8847)"
	case 0x8848:
		return "ETH_P_MPLS_MC(0x8848)"
	case 0x8863:
		return "ETH_P_PPP_DISC(0x8863)"
	case 0x8864:
		return "ETH_P_PPP_SES(0x8864)"
	case 0x888E:
		return "ETH_P_PAE(0x888E)"
	case 0x88CC:
		return "ETH_P_LLDP(0x88CC)"
	case 0x8809:
		return "ETH_P_SLOW(0x8809)"
	case 0x88F7:
		return "ETH_P_PTP(0x88F7)"
	case 0x8906:
		return "ETH_P_FCOE(0x8906)"
	}

	return fmt.Sprintf("ETH_P_0x%04x", eth)
}

// getAccept4Flags Function
func getAccept4Flags(flags int32) string {
	var out []string

	if flags&0x00000800 != 0 {
		out = append(out, "SOCK_NONBLOCK")
	}
	if flags&0x00080000 != 0 {
		out = append(out, "SOCK_CLOEXEC")
	}

	if len(out) == 0 {
		return fmt.Sprintf("%#x (default)", flags)
	}

	return strings.Join(out, "|")
}

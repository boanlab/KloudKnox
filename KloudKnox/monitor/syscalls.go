// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package monitor

// Syscall numbers
const (
	sysRead                  = 0
	sysWrite                 = 1
	sysOpen                  = 2
	sysClose                 = 3
	sysStat                  = 4
	sysFstat                 = 5
	sysLstat                 = 6
	sysPoll                  = 7
	sysLseek                 = 8
	sysMmap                  = 9
	sysMprotect              = 10
	sysMunmap                = 11
	sysBrk                   = 12
	sysRtSigaction           = 13
	sysRtSigprocmask         = 14
	sysRtSigreturn           = 15
	sysIoctl                 = 16
	sysPread64               = 17
	sysPwrite64              = 18
	sysReadv                 = 19
	sysWritev                = 20
	sysAccess                = 21
	sysPipe                  = 22
	sysSelect                = 23
	sysSchedYield            = 24
	sysMremap                = 25
	sysMsync                 = 26
	sysMincore               = 27
	sysMadvise               = 28
	sysShmget                = 29
	sysShmat                 = 30
	sysShmctl                = 31
	sysDup                   = 32
	sysDup2                  = 33
	sysPause                 = 34
	sysNanosleep             = 35
	sysGetitimer             = 36
	sysAlarm                 = 37
	sysSetitimer             = 38
	sysGetpid                = 39
	sysSendfile              = 40
	sysSocket                = 41
	sysConnect               = 42
	sysAccept                = 43
	sysSendto                = 44
	sysRecvfrom              = 45
	sysSendmsg               = 46
	sysRecvmsg               = 47
	sysShutdown              = 48
	sysBind                  = 49
	sysListen                = 50
	sysGetsockname           = 51
	sysGetpeername           = 52
	sysSocketpair            = 53
	sysSetsockopt            = 54
	sysGetsockopt            = 55
	sysClone                 = 56
	sysFork                  = 57
	sysVfork                 = 58
	sysExecve                = 59
	sysExit                  = 60
	sysWait4                 = 61
	sysKill                  = 62
	sysUname                 = 63
	sysSemget                = 64
	sysSemop                 = 65
	sysSemctl                = 66
	sysShmdt                 = 67
	sysMsgget                = 68
	sysMsgsnd                = 69
	sysMsgrcv                = 70
	sysMsgctl                = 71
	sysFcntl                 = 72
	sysFlock                 = 73
	sysFsync                 = 74
	sysFdatasync             = 75
	sysTruncate              = 76
	sysFtruncate             = 77
	sysGetdents              = 78
	sysGetcwd                = 79
	sysChdir                 = 80
	sysFchdir                = 81
	sysRename                = 82
	sysMkdir                 = 83
	sysRmdir                 = 84
	sysCreat                 = 85
	sysLink                  = 86
	sysUnlink                = 87
	sysSymlink               = 88
	sysReadlink              = 89
	sysChmod                 = 90
	sysFchmod                = 91
	sysChown                 = 92
	sysFchown                = 93
	sysLchown                = 94
	sysUmask                 = 95
	sysGettimeofday          = 96
	sysGetrlimit             = 97
	sysGetrusage             = 98
	sysSysinfo               = 99
	sysTimes                 = 100
	sysPtrace                = 101
	sysGetuid                = 102
	sysSyslog                = 103
	sysGetgid                = 104
	sysSetuid                = 105
	sysSetgid                = 106
	sysGeteuid               = 107
	sysGetegid               = 108
	sysSetpgid               = 109
	sysGetppid               = 110
	sysGetpgrp               = 111
	sysSetsid                = 112
	sysSetreuid              = 113
	sysSetregid              = 114
	sysGetgroups             = 115
	sysSetgroups             = 116
	sysSetresuid             = 117
	sysGetresuid             = 118
	sysSetresgid             = 119
	sysGetresgid             = 120
	sysGetpgid               = 121
	sysSetfsuid              = 122
	sysSetfsgid              = 123
	sysGetsid                = 124
	sysCapget                = 125
	sysCapset                = 126
	sysRtSigpending          = 127
	sysRtSigtimedwait        = 128
	sysRtSigqueueinfo        = 129
	sysRtSigsuspend          = 130
	sysSigaltstack           = 131
	sysUtime                 = 132
	sysMknod                 = 133
	sysUselib                = 134
	sysPersonality           = 135
	sysUstat                 = 136
	sysStatfs                = 137
	sysFstatfs               = 138
	sysSysfs                 = 139
	sysGetpriority           = 140
	sysSetpriority           = 141
	sysSchedSetparam         = 142
	sysSchedGetparam         = 143
	sysSchedSetscheduler     = 144
	sysSchedGetscheduler     = 145
	sysSchedGetPriorityMax   = 146
	sysSchedGetPriorityMin   = 147
	sysSchedRrGetInterval    = 148
	sysMlock                 = 149
	sysMunlock               = 150
	sysMlockall              = 151
	sysMunlockall            = 152
	sysVhangup               = 153
	sysModifyLdt             = 154
	sysPivotRoot             = 155
	sysSysctl                = 156
	sysPrctl                 = 157
	sysArchPrctl             = 158
	sysAdjtimex              = 159
	sysSetrlimit             = 160
	sysChroot                = 161
	sysSync                  = 162
	sysAcct                  = 163
	sysSettimeofday          = 164
	sysMount                 = 165
	sysUmount2               = 166
	sysSwapon                = 167
	sysSwapoff               = 168
	sysReboot                = 169
	sysSethostname           = 170
	sysSetdomainname         = 171
	sysIopl                  = 172
	sysIoperm                = 173
	sysCreateModule          = 174
	sysInitModule            = 175
	sysDeleteModule          = 176
	sysGetKernelSyms         = 177
	sysQueryModule           = 178
	sysQuotactl              = 179
	sysNfsservctl            = 180
	sysGetpmsg               = 181
	sysPutpmsg               = 182
	sysAfsSyscall            = 183
	sysTuxcall               = 184
	sysSecurity              = 185
	sysGettid                = 186
	sysReadahead             = 187
	sysSetxattr              = 188
	sysLsetxattr             = 189
	sysFsetxattr             = 190
	sysGetxattr              = 191
	sysLgetxattr             = 192
	sysFgetxattr             = 193
	sysListxattr             = 194
	sysLlistxattr            = 195
	sysFlistxattr            = 196
	sysRemovexattr           = 197
	sysLremovexattr          = 198
	sysFremovexattr          = 199
	sysTkill                 = 200
	sysTime                  = 201
	sysFutex                 = 202
	sysSchedSetaffinity      = 203
	sysSchedGetaffinity      = 204
	sysSetThreadArea         = 205
	sysIoSetup               = 206
	sysIoDestroy             = 207
	sysIoGetevents           = 208
	sysIoSubmit              = 209
	sysIoCancel              = 210
	sysGetThreadArea         = 211
	sysLookupDcookie         = 212
	sysEpollCreate           = 213
	sysEpollCtlOld           = 214
	sysEpollWaitOld          = 215
	sysRemapFilePages        = 216
	sysGetdents64            = 217
	sysSetTidAddress         = 218
	sysRestartSyscall        = 219
	sysSemtimedop            = 220
	sysFadvise64             = 221
	sysTimerCreate           = 222
	sysTimerSettime          = 223
	sysTimerGettime          = 224
	sysTimerGetoverrun       = 225
	sysTimerDelete           = 226
	sysClockSettime          = 227
	sysClockGettime          = 228
	sysClockGetres           = 229
	sysClockNanosleep        = 230
	sysExitGroup             = 231
	sysEpollWait             = 232
	sysEpollCtl              = 233
	sysTgkill                = 234
	sysUtimes                = 235
	sysVserver               = 236
	sysMbind                 = 237
	sysSetMempolicy          = 238
	sysGetMempolicy          = 239
	sysMqOpen                = 240
	sysMqUnlink              = 241
	sysMqTimedsend           = 242
	sysMqTimedreceive        = 243
	sysMqNotify              = 244
	sysMqGetsetattr          = 245
	sysKexecLoad             = 246
	sysWaitid                = 247
	sysAddKey                = 248
	sysRequestKey            = 249
	sysKeyctl                = 250
	sysIoprioSet             = 251
	sysIoprioGet             = 252
	sysInotifyInit           = 253
	sysInotifyAddWatch       = 254
	sysInotifyRmWatch        = 255
	sysMigratePages          = 256
	sysOpenat                = 257
	sysMkdirat               = 258
	sysMknodat               = 259
	sysFchownat              = 260
	sysFutimesat             = 261
	sysNewfstatat            = 262
	sysUnlinkat              = 263
	sysRenameat              = 264
	sysLinkat                = 265
	sysSymlinkat             = 266
	sysReadlinkat            = 267
	sysFchmodat              = 268
	sysFaccessat             = 269
	sysPselect6              = 270
	sysPpoll                 = 271
	sysUnshare               = 272
	sysSetRobustList         = 273
	sysGetRobustList         = 274
	sysSplice                = 275
	sysTee                   = 276
	sysSyncFileRange         = 277
	sysVmsplice              = 278
	sysMovePages             = 279
	sysUtimensat             = 280
	sysEpollPwait            = 281
	sysSignalfd              = 282
	sysTimerfdCreate         = 283
	sysEventfd               = 284
	sysFallocate             = 285
	sysTimerfdSettime        = 286
	sysTimerfdGettime        = 287
	sysAccept4               = 288
	sysSignalfd4             = 289
	sysEventfd2              = 290
	sysEpollCreate1          = 291
	sysDup3                  = 292
	sysPipe2                 = 293
	sysInotifyInit1          = 294
	sysPreadv                = 295
	sysPwritev               = 296
	sysRtTgsigqueueinfo      = 297
	sysPerfEventOpen         = 298
	sysRecvmmsg              = 299
	sysFanotifyInit          = 300
	sysFanotifyMark          = 301
	sysPrlimit64             = 302
	sysNameToHandleAt        = 303
	sysOpenByHandleAt        = 304
	sysClockAdjtime          = 305
	sysSyncfs                = 306
	sysSendmmsg              = 307
	sysSetns                 = 308
	sysGetcpu                = 309
	sysProcessVMReadv        = 310
	sysProcessVMWritev       = 311
	sysKcmp                  = 312
	sysFinitModule           = 313
	sysSchedSetattr          = 314
	sysSchedGetattr          = 315
	sysRenameat2             = 316
	sysSeccomp               = 317
	sysGetrandom             = 318
	sysMemfdCreate           = 319
	sysKexecFileLoad         = 320
	sysBpf                   = 321
	sysExecveat              = 322
	sysUserfaultfd           = 323
	sysMembarrier            = 324
	sysMlock2                = 325
	sysCopyFileRange         = 326
	sysPreadv2               = 327
	sysPwritev2              = 328
	sysPkeyMprotect          = 329
	sysPkeyAlloc             = 330
	sysPkeyFree              = 331
	sysStatx                 = 332
	sysIoPgetevents          = 333
	sysRseq                  = 334
	sysPidfdSendSignal       = 424
	sysIoUringSetup          = 425
	sysIoUringEnter          = 426
	sysIoUringRegister       = 427
	sysOpenTree              = 428
	sysMoveMount             = 429
	sysFsopen                = 430
	sysFsconfig              = 431
	sysFsmount               = 432
	sysFspick                = 433
	sysPidfdOpen             = 434
	sysClone3                = 435
	sysCloseRange            = 436
	sysOpenat2               = 437
	sysPidfdGetfd            = 438
	sysFaccessat2            = 439
	sysProcessMadvise        = 440
	sysEpollPwait2           = 441
	sysMountSetattr          = 442
	sysQuotactlFd            = 443
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
	sysMemfdSecret           = 447
	sysProcessMrelease       = 448
	sysFutexWaitv            = 449
	sysSetMempolicyHomeNode  = 450
	sysCachestat             = 451
	sysFchmodat2             = 452
	sysMapShadowStack        = 453
	sysFutexWake             = 454
	sysFutexWait             = 455
	sysFutexRequeue          = 456
	sysStatmount             = 457
	sysListmount             = 458
	sysLsmGetSelfAttr        = 459
	sysLsmSetSelfAttr        = 460
	sysLsmListModules        = 461
)

// syscall2name is a map of syscall numbers to their names
var syscall2name = map[int32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	15:  "rt_sigreturn",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	25:  "mremap",
	26:  "msync",
	27:  "mincore",
	28:  "madvise",
	29:  "shmget",
	30:  "shmat",
	31:  "shmctl",
	32:  "dup",
	33:  "dup2",
	34:  "pause",
	35:  "nanosleep",
	36:  "getitimer",
	37:  "alarm",
	38:  "setitimer",
	39:  "getpid",
	40:  "sendfile",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	51:  "getsockname",
	52:  "getpeername",
	53:  "socketpair",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	64:  "semget",
	65:  "semop",
	66:  "semctl",
	67:  "shmdt",
	68:  "msgget",
	69:  "msgsnd",
	70:  "msgrcv",
	71:  "msgctl",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	81:  "fchdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	94:  "lchown",
	95:  "umask",
	96:  "gettimeofday",
	97:  "getrlimit",
	98:  "getrusage",
	99:  "sysinfo",
	100: "times",
	101: "ptrace",
	102: "getuid",
	103: "syslog",
	104: "getgid",
	105: "setuid",
	106: "setgid",
	107: "geteuid",
	108: "getegid",
	109: "setpgid",
	110: "getppid",
	111: "getpgrp",
	112: "setsid",
	113: "setreuid",
	114: "setregid",
	115: "getgroups",
	116: "setgroups",
	117: "setresuid",
	118: "getresuid",
	119: "setresgid",
	120: "getresgid",
	121: "getpgid",
	122: "setfsuid",
	123: "setfsgid",
	124: "getsid",
	125: "capget",
	126: "capset",
	127: "rt_sigpending",
	128: "rt_sigtimedwait",
	129: "rt_sigqueueinfo",
	130: "rt_sigsuspend",
	131: "sigaltstack",
	132: "utime",
	133: "mknod",
	134: "uselib",
	135: "personality",
	136: "ustat",
	137: "statfs",
	138: "fstatfs",
	139: "sysfs",
	140: "getpriority",
	141: "setpriority",
	142: "sched_setparam",
	143: "sched_getparam",
	144: "sched_setscheduler",
	145: "sched_getscheduler",
	146: "sched_get_priority_max",
	147: "sched_get_priority_min",
	148: "sched_rr_get_interval",
	149: "mlock",
	150: "munlock",
	151: "mlockall",
	152: "munlockall",
	153: "vhangup",
	154: "modify_ldt",
	155: "pivot_root",
	156: "_sysctl",
	157: "prctl",
	158: "arch_prctl",
	159: "adjtimex",
	160: "setrlimit",
	161: "chroot",
	162: "sync",
	163: "acct",
	164: "settimeofday",
	165: "mount",
	166: "umount2",
	167: "swapon",
	168: "swapoff",
	169: "reboot",
	170: "sethostname",
	171: "setdomainname",
	172: "iopl",
	173: "ioperm",
	174: "create_module",
	175: "init_module",
	176: "delete_module",
	177: "get_kernel_syms",
	178: "query_module",
	179: "quotactl",
	180: "nfsservctl",
	181: "getpmsg",
	182: "putpmsg",
	183: "afs_syscall",
	184: "tuxcall",
	185: "security",
	186: "gettid",
	187: "readahead",
	188: "setxattr",
	189: "lsetxattr",
	190: "fsetxattr",
	191: "getxattr",
	192: "lgetxattr",
	193: "fgetxattr",
	194: "listxattr",
	195: "llistxattr",
	196: "flistxattr",
	197: "removexattr",
	198: "lremovexattr",
	199: "fremovexattr",
	200: "tkill",
	201: "time",
	202: "futex",
	203: "sched_setaffinity",
	204: "sched_getaffinity",
	205: "set_thread_area",
	206: "io_setup",
	207: "io_destroy",
	208: "io_getevents",
	209: "io_submit",
	210: "io_cancel",
	211: "get_thread_area",
	212: "lookup_dcookie",
	213: "epoll_create",
	214: "epoll_ctl_old",
	215: "epoll_wait_old",
	216: "remap_file_pages",
	217: "getdents64",
	218: "set_tid_address",
	219: "restart_syscall",
	220: "semtimedop",
	221: "fadvise64",
	222: "timer_create",
	223: "timer_settime",
	224: "timer_gettime",
	225: "timer_getoverrun",
	226: "timer_delete",
	227: "clock_settime",
	228: "clock_gettime",
	229: "clock_getres",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	233: "epoll_ctl",
	234: "tgkill",
	235: "utimes",
	236: "vserver",
	237: "mbind",
	238: "set_mempolicy",
	239: "get_mempolicy",
	240: "mq_open",
	241: "mq_unlink",
	242: "mq_timedsend",
	243: "mq_timedreceive",
	244: "mq_notify",
	245: "mq_getsetattr",
	246: "kexec_load",
	247: "waitid",
	248: "add_key",
	249: "request_key",
	250: "keyctl",
	251: "ioprio_set",
	252: "ioprio_get",
	253: "inotify_init",
	254: "inotify_add_watch",
	255: "inotify_rm_watch",
	256: "migrate_pages",
	257: "openat",
	258: "mkdirat",
	259: "mknodat",
	260: "fchownat",
	261: "futimesat",
	262: "newfstatat",
	263: "unlinkat",
	264: "renameat",
	265: "linkat",
	266: "symlinkat",
	267: "readlinkat",
	268: "fchmodat",
	269: "faccessat",
	270: "pselect6",
	271: "ppoll",
	272: "unshare",
	273: "set_robust_list",
	274: "get_robust_list",
	275: "splice",
	276: "tee",
	277: "sync_file_range",
	278: "vmsplice",
	279: "move_pages",
	280: "utimensat",
	281: "epoll_pwait",
	282: "signalfd",
	283: "timerfd_create",
	284: "eventfd",
	285: "fallocate",
	286: "timerfd_settime",
	287: "timerfd_gettime",
	288: "accept4",
	289: "signalfd4",
	290: "eventfd2",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	294: "inotify_init1",
	295: "preadv",
	296: "pwritev",
	297: "rt_tgsigqueueinfo",
	298: "perf_event_open",
	299: "recvmmsg",
	300: "fanotify_init",
	301: "fanotify_mark",
	302: "prlimit64",
	303: "name_to_handle_at",
	304: "open_by_handle_at",
	305: "clock_adjtime",
	306: "syncfs",
	307: "sendmmsg",
	308: "setns",
	309: "getcpu",
	310: "process_vm_readv",
	311: "process_vm_writev",
	312: "kcmp",
	313: "finit_module",
	314: "sched_setattr",
	315: "sched_getattr",
	316: "renameat2",
	317: "seccomp",
	318: "getrandom",
	319: "memfd_create",
	320: "kexec_file_load",
	321: "bpf",
	322: "execveat",
	323: "userfaultfd",
	324: "membarrier",
	325: "mlock2",
	326: "copy_file_range",
	327: "preadv2",
	328: "pwritev2",
	329: "pkey_mprotect",
	330: "pkey_alloc",
	331: "pkey_free",
	332: "statx",
	333: "io_pgetevents",
	334: "rseq",
	424: "pidfd_send_signal",
	425: "io_uring_setup",
	426: "io_uring_enter",
	427: "io_uring_register",
	428: "open_tree",
	429: "move_mount",
	430: "fsopen",
	431: "fsconfig",
	432: "fsmount",
	433: "fspick",
	434: "pidfd_open",
	435: "clone3",
	436: "close_range",
	437: "openat2",
	438: "pidfd_getfd",
	439: "faccessat2",
	440: "process_madvise",
	441: "epoll_pwait2",
	442: "mount_setattr",
	443: "quotactl_fd",
	444: "landlock_create_ruleset",
	445: "landlock_add_rule",
	446: "landlock_restrict_self",
	447: "memfd_secret",
	448: "process_mrelease",
	449: "futex_waitv",
	450: "set_mempolicy_home_node",
	451: "cachestat",
	452: "fchmodat2",
	453: "map_shadow_stack",
	454: "futex_wake",
	455: "futex_wait",
	456: "futex_requeue",
	457: "statmount",
	458: "listmount",
	459: "lsm_get_self_attr",
	460: "lsm_set_self_attr",
	461: "lsm_list_modules",

	1000: "sched_process_exit",
	1001: "security_bprm_check",
	1002: "security_task_kill",
	1003: "security_path_chroot",
	1004: "security_file_open",
	1005: "filp_close",
	1006: "security_path_chown",
	1007: "security_path_chmod",
	1008: "security_path_unlink",
	1009: "security_path_rename",
	1010: "security_path_link",
	1011: "security_path_mkdir",
	1012: "security_path_rmdir",
	1013: "kretprobe_inet_csk_accept",
	1014: "security_capable",
	1015: "security_unix_stream_connect",
	1016: "security_unix_may_send",
	1017: "security_ptrace_access_check",
}

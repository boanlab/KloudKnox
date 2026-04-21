// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
// Included by BPF program headers — do not compile standalone.

#pragma once

// Network Constants

#define AF_UNIX 1
#define AF_INET 2
#define AF_PACKET 17

// Network Functions

// compile-time byte-swap helpers
#define ___bpf_mvb(x, b, n, m) ((__u##b)(x) << (b - (n + 1) * 8) >> (b - 8) << (m * 8))

#define ___bpf_swab16(x) ((__u16)(___bpf_mvb(x, 16, 0, 1) | ___bpf_mvb(x, 16, 1, 0)))

#define ___bpf_swab32(x) \
    ((__u32)(___bpf_mvb(x, 32, 0, 3) | ___bpf_mvb(x, 32, 1, 2) | ___bpf_mvb(x, 32, 2, 1) | ___bpf_mvb(x, 32, 3, 0)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_constant_ntohs(x) ___bpf_swab16(x)
#define __bpf_ntohl(x) __builtin_bswap32(x)
#define __bpf_constant_ntohl(x) ___bpf_swab32(x)

#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_constant_htons(x) ___bpf_swab16(x)
#define __bpf_htonl(x) __builtin_bswap32(x)
#define __bpf_constant_htonl(x) ___bpf_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_ntohs(x) (x)
#define __bpf_constant_ntohs(x) (x)
#define __bpf_ntohl(x) (x)
#define __bpf_constant_ntohl(x) (x)

#define __bpf_htons(x) (x)
#define __bpf_constant_htons(x) (x)
#define __bpf_htonl(x) (x)
#define __bpf_constant_htonl(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_ntohl(x) (__builtin_constant_p(x) ? __bpf_constant_ntohl(x) : __bpf_ntohl(x))

#define bpf_ntohs(x) (__builtin_constant_p(x) ? __bpf_constant_ntohs(x) : __bpf_ntohs(x))

#define bpf_htonl(x) (__builtin_constant_p(x) ? __bpf_constant_htonl(x) : __bpf_htonl(x))

#define bpf_htons(x) (__builtin_constant_p(x) ? __bpf_constant_htons(x) : __bpf_htons(x))

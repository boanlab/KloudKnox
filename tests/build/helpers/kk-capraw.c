// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
//
// CAP_NET_RAW probe via AF_INET/SOCK_RAW — required for fromSource cap tests.
// AF_PACKET would also need CAP_NET_RAW but is blocked by the AppArmor footer's
// `deny network packet,` baseline, so this form is used instead.

#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        perror("socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
        return 1;
    }
    close(s);
    return 0;
}

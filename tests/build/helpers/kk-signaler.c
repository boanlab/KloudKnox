// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
//
// Compiled signal sender — fromSource policies need a stable exe path
// (/proc/<pid>/exe), which shell scripts don't provide.
// usage: kk-signaler <pid> <signum>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <pid> <signum>\n", argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    int sig = atoi(argv[2]);
    if (kill(pid, sig) < 0) {
        perror("kill");
        return 1;
    }
    return 0;
}

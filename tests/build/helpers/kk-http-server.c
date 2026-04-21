// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University
//
// Single-process blocking HTTP server; returns 200 OK "ok\n" on any request.
// usage: kk-http-server <port>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port: %s\n", argv[1]);
        return 2;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(s, 16) < 0) { perror("listen"); return 1; }

    signal(SIGPIPE, SIG_IGN);

    static const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 3\r\n"
        "Connection: close\r\n"
        "\r\n"
        "ok\n";

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        char buf[2048];
        ssize_t n;
        // best-effort drain of one request
        n = read(c, buf, sizeof(buf));
        if (n >= 0) {
            n = write(c, resp, sizeof(resp) - 1);
        }
        (void)n;
        close(c);
    }
}

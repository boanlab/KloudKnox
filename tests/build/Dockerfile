# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

### Builder Stage

FROM ubuntu:24.04 AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY helloworld/helloworld.c /src/helloworld.c
COPY readwrite/readwrite.c /src/readwrite.c
COPY helpers/kk-http-server.c /src/kk-http-server.c
COPY helpers/kk-signaler.c /src/kk-signaler.c
COPY helpers/kk-capraw.c /src/kk-capraw.c

RUN mkdir -p /out \
 && gcc -O2 -o /out/helloworld       /src/helloworld.c      \
 && gcc -O2 -o /out/readwrite        /src/readwrite.c       \
 && gcc -O2 -o /out/kk-http-server   /src/kk-http-server.c  \
 && gcc -O2 -o /out/kk-signaler      /src/kk-signaler.c     \
 && gcc -O2 -o /out/kk-capraw        /src/kk-capraw.c

### Runner Stage

FROM ubuntu:24.04 AS runner

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        iptables \
        iputils-ping \
        net-tools \
        procps \
        socat \
        strace \
        tcpdump \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# compiled helpers
COPY --from=builder /out/kk-http-server /usr/local/bin/kk-http-server
COPY --from=builder /out/kk-signaler    /usr/local/bin/kk-signaler
COPY --from=builder /out/kk-capraw      /usr/local/bin/kk-capraw
COPY --from=builder /out/helloworld     /helloworld
COPY --from=builder /out/readwrite      /readwrite

# test fixtures for root
RUN echo "secret file" > /secret.txt \
 && echo "plain file"  > /plain.txt \
 && mkdir -p /credentials /credentials/keys \
 && echo "password file" > /credentials/password \
 && echo "token file"    > /credentials/token \
 && echo "cert file"     > /credentials/keys/cert.ca \
 && echo "key file"      > /credentials/keys/priv.key

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

### Builder Stage

FROM golang:1.24-alpine3.21 AS builder

# Update package list and install build dependencies
RUN apk --no-cache update
RUN apk --no-cache --update add alpine-sdk
RUN apk --no-cache add make gcc protobuf musl-dev

# Install protobuf and gRPC code generation tools
RUN go install github.com/golang/protobuf/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Set working directory and copy source code
WORKDIR /KloudKnox
COPY . .

# Build the application (skip linting — run lint separately in CI)
WORKDIR /KloudKnox/KloudKnox
RUN go mod tidy && CGO_ENABLED=0 go build -o kloudknox .

### Final Stage

FROM alpine:3.21

# Install runtime dependencies
RUN apk --no-cache update && \
    apk --no-cache add bash apparmor apparmor-utils && \
    rm -rf /var/cache/apk/*

# Copy the built binary from builder stage
COPY --from=builder /KloudKnox/KloudKnox/kloudknox /

# Set the entry point to run the application
ENTRYPOINT ["/kloudknox"]

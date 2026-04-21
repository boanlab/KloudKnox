# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

PROG_NAME = kloudknox
IMAGE_NAME = boanlab/$(PROG_NAME)
TAG ?= v0.1.0

.PHONY: build
build: bpf gofmt golangci-lint gosec
	go mod tidy
	CGO_ENABLED=0 go build -o bin/$(PROG_NAME)

.PHONY: bpf
bpf:
	cd BPF; make

.PHONY: gofmt
gofmt:
	cd $(CURDIR); gofmt -w -s -d $(shell find . -type f -name '*.go' -print)

.PHONY: golangci-lint
golangci-lint:
ifeq (, $(shell which golangci-lint))
	@{ \
	set -e ;\
	GOLANGCI_LINT_TEMP_DIR=$$(mktemp -d) ;\
	cd $$GOLANGCI_LINT_TEMP_DIR ;\
	go mod init tmp ;\
	go get github.com/golangci/golangci-lint/v2/cmd/golangci-lint ;\
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint ;\
	rm -rf $$GOLANGCI_LINT_TEMP_DIR ;\
	}
endif
	cd $(CURDIR); golangci-lint run

.PHONY: gosec
gosec:
ifeq (, $(shell which gosec))
	@{ \
	set -e ;\
	GOSEC_TEMP_DIR=$$(mktemp -d) ;\
	cd $$GOSEC_TEMP_DIR ;\
	go mod init tmp ;\
	go get github.com/securego/gosec/v2/cmd/gosec ;\
	go install github.com/securego/gosec/v2/cmd/gosec ;\
	rm -rf $$GOSEC_TEMP_DIR ;\
	}
endif
	cd $(CURDIR); gosec -exclude=G402 ./...

.PHONY: test
test:
	go test ./... -v -count=1

.PHONY: run
run:
	sudo -E bin/$(PROG_NAME)

.PHONY: clean
clean:
	cd BPF; make clean
	rm -rf bin

.PHONY: build-image
build-image:
	docker build -t $(IMAGE_NAME):$(TAG) -t $(IMAGE_NAME):latest -f ../Dockerfile ../

.PHONY: push-image
push-image: build-image
	docker push $(IMAGE_NAME):$(TAG)
	docker push $(IMAGE_NAME):latest

.PHONY: clean-image
clean-image:
	docker rmi $(IMAGE_NAME):$(TAG)
	docker rmi $(IMAGE_NAME):latest

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

PROG_NAME = operator-controller
IMAGE = boanlab/kloudknox-operator
TAG ?= v0.1.0

.PHONY: all build gofmt golangci-lint gosec test manifests generate codegen run clean build-image push-image controller-gen

all: build

build: gofmt golangci-lint gosec manifests generate
	go mod tidy
	go build -o bin/$(PROG_NAME) cmd/main.go

gofmt:
	cd $(CURDIR); gofmt -w -s -d $(shell find . -type f -name '*.go' -print)

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

manifests: controller-gen
	controller-gen rbac:roleName=kloudknox-operator-role crd paths="./..." output:crd:artifacts:config=config/crd/bases
	cat config/crd/bases/security.boanlab.com_kloudknoxpolicies.yaml > ../deployments/01_kloudknoxpolicy.yaml

generate: controller-gen
	controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."

codegen: manifests generate

test:
	go test ./... -v -count=1

run:
	go run ./cmd/main.go

clean:
	rm -rf bin

build-image:
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

push-image: build-image
	docker push $(IMAGE):$(TAG)
	docker push $(IMAGE):latest

controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TEMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TEMP_DIR ;\
	go mod init tmp ;\
	go get sigs.k8s.io/controller-tools/cmd/controller-gen ;\
	go install sigs.k8s.io/controller-tools/cmd/controller-gen ;\
	rm -rf $$CONTROLLER_GEN_TEMP_DIR ;\
	}
endif

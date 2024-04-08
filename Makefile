IMG ?= controller:latest

ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	@go run sigs.k8s.io/controller-tools/cmd/controller-gen rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	@go run sigs.k8s.io/controller-tools/cmd/controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
	@internal/tools/generate.sh

.PHONY: fmt
fmt: ## Run go fmt against code.
	@go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	@go vet ./...

.PHONY: test
test: manifests generate fmt vet ## Run tests.
	@go run github.com/onsi/ginkgo/v2/ginkgo -r --race --randomize-suites --randomize-all --keep-going --timeout=9223372036s

.PHONY: lint
lint: ## Run golangci-lint linter & yamllint.
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint run

.PHONY: addlicense
addlicense: ## Add license headers to all go files.
	@find . -name '*.go' -exec go run github.com/google/addlicense -f hack/license-header.txt {} +

.PHONY: checklicense
checklicense: ## Check that every file has a license header present.
	@find . -name '*.go' -exec go run github.com/google/addlicense  -check -c 'IronCore authors' {} +

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	@go build -o metal cmd/main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	@docker build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	@docker push ${IMG}

##@ Deployment

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	go run sigs.k8s.io/kustomize/kustomize/v5 build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	go run sigs.k8s.io/kustomize/kustomize/v5 build config/crd | kubectl delete --ignore-not-found=true -f -

.PHONY: deploy
deploy: manifests ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && go run sigs.k8s.io/kustomize/kustomize/v5 edit set image controller=${IMG}
	go run sigs.k8s.io/kustomize/kustomize/v5 build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	go run sigs.k8s.io/kustomize/kustomize/v5 build config/default | kubectl delete --ignore-not-found=true -f -

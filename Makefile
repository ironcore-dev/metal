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
	@go run sigs.k8s.io/controller-tools/cmd/controller-gen object:headerFile=".reuse/boilerplate.go.txt" paths="./..."
	@internal/tools/generate.sh

.PHONY: fmt
fmt: ## Run go fmt against code.
	@go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	@go vet ./...

.PHONY: test
test: ## Run tests.
	@go run github.com/onsi/ginkgo/v2/ginkgo -r --skip-package e2e --race --randomize-suites --keep-going --randomize-all --repeat=11

.PHONY: test-e2e  # Run the e2e tests against a Kind k8s instance that is spun up.
test-e2e:
	go run github.com/onsi/ginkgo/v2/ginkgo -r --skip-package controller -v

.PHONY: lint
lint: ## Run golangci-lint linter & yamllint.
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint run

.PHONY: addlicense
addlicense: ## Add license headers to all go files.
	@find . -name '*.go' -exec go run github.com/google/addlicense -f .reuse/license-header.txt {} +

.PHONY: checklicense
checklicense: ## Check that every file has a license header present.
	@find . -name '*.go' -exec go run github.com/google/addlicense  -check -c 'IronCore authors' {} +

##@ Build

.PHONY: build
build: generate manifests fmt vet ## Build manager binary.
	@go build -o metal cmd/main.go

##@ Deployment

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@go run sigs.k8s.io/kustomize/kustomize/v5 build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	@go run sigs.k8s.io/kustomize/kustomize/v5 build config/crd | kubectl delete --ignore-not-found=true -f -

##@ E2E Tests

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

IMG ?= ghcr.io/ironcore-dev/metal:latest
KIND_CLUSTER_NAME ?= ironcore-metal-e2e
NAMESPACE ?= metal-system
KUBECTL ?= kubectl
KIND ?= $(LOCALBIN)/kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTAINER_TOOL ?= docker
YQ = $(LOCALBIN)/yq

K8S_VERSION ?= v1.30.0
CERT_MANAGER_VERSION ?= v1.15.0
YQ_VERSION ?= v4.44.1
KUSTOMIZE_VERSION ?= v5.3.0
KIND_VERSION ?= v0.23.0

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	@$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) -n $(NAMESPACE) apply -f -
	$(KUBECTL) wait deployment.apps/metal-controller-manager --for condition=Available --namespace $(NAMESPACE) --timeout 5m

.PHONY: kind-create
kind-create: kind yq ## Create kubernetes cluster using Kind.
	@if ! $(KIND) get clusters | grep -q $(KIND_CLUSTER_NAME); then \
		$(KIND) create cluster --name $(KIND_CLUSTER_NAME) --image kindest/node:$(K8S_VERSION) --config test/e2e/config.yaml; \
	elif ! $(CONTAINER_TOOL) container inspect $$($(KIND) get nodes --name $(KIND_CLUSTER_NAME)) | $(YQ) e '.[0].Config.Image' | grep -q $(K8S_VERSION); then \
  		$(KIND) delete cluster --name $(KIND_CLUSTER_NAME); \
		$(KIND) create cluster --name $(KIND_CLUSTER_NAME) --image kindest/node:$(K8S_VERSION) --config test/e2e/config.yaml; \
	fi

.PHONY: kind-delete
kind-delete: kind ## Create kubernetes cluster using Kind.
	@if $(KIND) get clusters | grep -q $(KIND_CLUSTER_NAME); then \
		$(KIND) delete cluster --name $(KIND_CLUSTER_NAME); \
	fi

.PHONY: kind-prepare
kind-prepare: kind-create
	# Install cert-manager operator
	$(KUBECTL) apply --server-side -f "https://github.com/jetstack/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml"
	$(KUBECTL) wait deployment.apps/cert-manager-webhook --for condition=Available --namespace cert-manager --timeout 5m

.PHONY: kind-load
kind-load: kind ## Build and upload docker image to the local Kind cluster.
	$(KIND) load docker-image ${IMG} --name $(KIND_CLUSTER_NAME)

.PHONY: kustomize
kustomize: $(LOCALBIN)
	@if test -x $(KUSTOMIZE) && ! $(KUSTOMIZE) version | grep -q $(KUSTOMIZE_VERSION); then \
		rm -f $(KUSTOMIZE); \
	fi
	@test -x $(KUSTOMIZE) || { curl -Ss $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN); }

.PHONY: kind
kind: $(LOCALBIN)
	@test -x $(KIND) && $(KIND) version | grep -q $(KIND_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/kind@$(KIND_VERSION)

.PHONY: yq
yq: $(LOCALBIN)
	@test -x $(YQ) && $(YQ) version | grep -q $(YQ_VERSION) || \
	GOBIN=$(LOCALBIN) go install github.com/mikefarah/yq/v4@$(YQ_VERSION)

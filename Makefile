# The operator image deploy and build-installer set in config/manager.
IMG ?= controller:latest
# The year in generated file headers.
YEAR ?= $(shell date +%Y)

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...
	go -C tools/bundle fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...
	go -C tools/bundle vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest kustomize ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" \
		KUSTOMIZE="$(KUSTOMIZE)" \
		GOFIPS140=v1.26.0 GODEBUG=fips140=only go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out
	KUSTOMIZE="$(KUSTOMIZE)" GOFIPS140=v1.26.0 GODEBUG=fips140=only go -C tools/bundle test -cover ./...

# The resilience lane: API server faults through Toxiproxy and the client
# interceptor, with shortened lease timings.
RESILIENCE_TIMEOUT ?= 30m
RESILIENCE_RUN ?= ^TestResilience
.PHONY: test-resilience
test-resilience: manifests generate fmt vet setup-envtest toxiproxy ## Run the API server fault scenarios.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" \
		TOXIPROXY_SERVER="$(TOXIPROXY)" \
		GOFIPS140=v1.26.0 GODEBUG=fips140=only go test -tags resilience ./internal/operator/ \
		-run '$(RESILIENCE_RUN)' -count=1 -timeout $(RESILIENCE_TIMEOUT) -v

# The job image must be the builder pinned in ci's images.lock.
.PHONY: act-resilience
act-resilience: ## Run the resilience workflow locally with act.
	@want="$$(sed -n 's/^HI_GO_BUILDER=//p' "$(CI_DIR)/images.lock")"; \
	  got="$$(sed -n 's/^ *image: *//p' .github/workflows/sealhouse-resilience.yaml)"; \
	  [ -n "$$want" ] && [ "$$want" = "$$got" ] || { echo "sealhouse-resilience.yaml image $$got is not HI_GO_BUILDER $$want" >&2; exit 1; }
	"$(CI_DIR)/hack/verify-base-images.sh"
	env -u GITHUB_TOKEN -u GH_TOKEN -u ACT_GITHUB_TOKEN \
	  act workflow_dispatch -W .github/workflows/sealhouse-resilience.yaml --bind --pull=false \
	  --secret-file /dev/null --env-file /dev/null --var-file /dev/null -s GITHUB_TOKEN= \
	  --container-architecture linux/amd64 --network bridge -P ubuntu-latest="$$want" \
	  --input run='$(RESILIENCE_RUN)' \
	  $(if $(RESILIENCE_LONG),--input long=true)

# Pushes the operator image, bundle and a catalog tagged pqc-catalog:pr-<commit>.
.PHONY: publish-alpha
publish-alpha: kustomize ## Build and push the operator, bundle and a PR catalog.
	CI_DIR="$(CI_DIR)" KUSTOMIZE="$(KUSTOMIZE)" ./hack/publish-alpha.sh

# Runs against the cluster from ci/hack/cluster-up.sh.
E2E_KUBECONFIG ?= $(CI_DIR)/.state/kind.kubeconfig
E2E_CONTEXT ?= kind-sealhouse
E2E_NAMESPACE ?= sealhouse-e2e
UPGRADE_NAMESPACE ?= sealhouse-upgrade
.PHONY: test-e2e
test-e2e: publish-alpha ## Install the PR catalog through OLM and run the e2e tests.
	$(MAKE) e2e-run

.PHONY: e2e-run
e2e-run: ## Run the e2e tests against the catalog publish-alpha last published.
	KUBECONFIG="$(E2E_KUBECONFIG)" KUBE_CONTEXT=$(E2E_CONTEXT) "$(CI_DIR)/hack/scc-namespace.sh" rhtas-pqc-operator $(E2E_NAMESPACE)
	KUBECONFIG="$(E2E_KUBECONFIG)" ALPHA_ENV="$(CURDIR)/dist/alpha.env" KUBE_CONTEXT=$(E2E_CONTEXT) E2E_NAMESPACE=$(E2E_NAMESPACE) \
		UPGRADE_NAMESPACE=$(UPGRADE_NAMESPACE) \
		GOFIPS140=v1.26.0 GODEBUG=fips140=only go test -tags e2e ./test/e2e/ -count=1 -timeout 20m -v

# Random operator kills for SOAK_DURATION, then SOAK_STEADY checked for leaks.
SOAK_KUBECONFIG ?= $(CI_DIR)/.state/sealhouse-soak.kubeconfig
SOAK_CONTEXT ?= kind-sealhouse-soak
SOAK_DURATION ?= 1h
SOAK_STEADY ?= 20m
SOAK_TIMEOUT ?= 3h
ALPHA_ENV ?= $(CURDIR)/dist/alpha.env
.PHONY: test-soak
test-soak: ## Kill the operator at random on the soak cluster and check it recovers and does not leak.
	KUBECONFIG="$(SOAK_KUBECONFIG)" KUBE_CONTEXT=$(SOAK_CONTEXT) "$(CI_DIR)/hack/scc-namespace.sh" rhtas-pqc-operator $(E2E_NAMESPACE)
	KUBECONFIG="$(SOAK_KUBECONFIG)" ALPHA_ENV="$(ALPHA_ENV)" KUBE_CONTEXT=$(SOAK_CONTEXT) E2E_NAMESPACE=$(E2E_NAMESPACE) \
		SOAK_DURATION=$(SOAK_DURATION) SOAK_STEADY=$(SOAK_STEADY) SOAK_SEED=$(SOAK_SEED) SOAK_OUT="$(SOAK_OUT)" \
		GOFIPS140=v1.26.0 GODEBUG=fips140=only go test -tags e2e,soak ./test/e2e/ -run '^TestSoak$$' -count=1 -timeout $(SOAK_TIMEOUT) -v

# Publishes this commit to alpha once the upgrade test passes on every minor.
CATALOG_REPO ?= $(abspath $(or $(SEALHOUSE_ROOT),..)/pqc-catalog)
KIND_VERSIONS ?= 1.33 1.34 1.35
KIND_PARALLEL ?= 1
.PHONY: merge-publish
merge-publish: kustomize ## Publish this commit to the alpha channel after the upgrade test on every Kubernetes minor.
	CI_DIR="$(CI_DIR)" KUSTOMIZE="$(KUSTOMIZE)" ./hack/publish-alpha.sh --merge "$(CATALOG_REPO)"
	$(MAKE) --no-print-directory upgrade-run
	CI_DIR="$(CI_DIR)" KIND_PARALLEL="$(KIND_PARALLEL)" ./hack/kind-upgrades.sh $(KIND_VERSIONS)
	./hack/promote-alpha.sh "$(CATALOG_REPO)"

# upgrade-run runs the e2e suite in a fresh UPGRADE_NAMESPACE on one
# cluster, upgrading from the alpha head that dist/alpha.env names.
.PHONY: upgrade-run
upgrade-run:
	kubectl --kubeconfig "$(E2E_KUBECONFIG)" --context $(E2E_CONTEXT) delete namespace $(UPGRADE_NAMESPACE) --ignore-not-found --wait --timeout=3m
	KUBECONFIG="$(E2E_KUBECONFIG)" KUBE_CONTEXT=$(E2E_CONTEXT) "$(CI_DIR)/hack/scc-namespace.sh" $(UPGRADE_NAMESPACE)
	$(MAKE) --no-print-directory e2e-run

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run
	cd tools/bundle && "$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix
	cd tools/bundle && "$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

CI_DIR ?= $(abspath ../ci)
IMAGE_TAG ?= $(shell git rev-parse --short HEAD)
.PHONY: docker-build
docker-build: ## Build, test and push the operator image to the local registry.
	"$(CI_DIR)/hack/build-image.sh" . $(IMAGE_TAG)

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster in the current kubeconfig.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster in the current kubeconfig. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster in the current kubeconfig.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster in the current kubeconfig. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
TOXIPROXY ?= $(LOCALBIN)/toxiproxy-server

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.22.0

# setup-envtest from the controller-runtime in go.mod.
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v")

# envtest binaries for the Kubernetes minor of k8s.io/api in go.mod.
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.15.0
TOXIPROXY_VERSION ?= v2.13.0
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: toxiproxy
toxiproxy: $(TOXIPROXY) ## Build toxiproxy-server locally if necessary.
$(TOXIPROXY): $(LOCALBIN)
	@[ -f "$(TOXIPROXY)-$(TOXIPROXY_VERSION)" ] || { \
		set -e; \
		echo "Building github.com/Shopify/toxiproxy/v2/cmd/server@$(TOXIPROXY_VERSION)"; \
		tmp="$$(mktemp -d)"; \
		GOBIN="$$tmp" go install github.com/Shopify/toxiproxy/v2/cmd/server@$(TOXIPROXY_VERSION); \
		mv "$$tmp/server" "$(TOXIPROXY)-$(TOXIPROXY_VERSION)"; \
		rmdir "$$tmp"; \
	}
	ln -sf "$$(realpath "$(TOXIPROXY)-$(TOXIPROXY_VERSION)")" "$(TOXIPROXY)"

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool installs package $2 at version $3 as $1, if not already there.
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

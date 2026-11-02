# secure-sign-pqc-operator

A Kubernetes operator that runs Sigstore services with post-quantum (ML-DSA)
keys. Each `SecureSignPQC` instance names a product version; version `2.0`
deploys a timestamp authority (TSA) signing with ML-DSA-44, -65 or -87.

The operator is in alpha: every merge to `main` is published to the `alpha`
channel, and the API may change.

## What an instance gets

- A CA (root and intermediate) and a TSA signing key, each in a Secret in the
  instance's namespace. Existing Secrets are used as they are; the operator
  never overwrites a key. A restored Secret needs the labels the operator
  gives its own: `app.kubernetes.io/instance: <name>`,
  `app.kubernetes.io/managed-by: rhtas-pqc-operator`,
  `pqc.rhtas.redhat.com/key-role` (`tsa-ca` or `tsa-signer`) and, on a
  signer, `pqc.rhtas.redhat.com/key-generation`.
- A TSA Deployment and ClusterIP Service, at the URL in `status.tsa.url`.
- With `spec.tsa.ingress.enabled`, an Ingress for the TSA, at the URL in
  `status.tsa.externalURL`. On OpenShift the router serves it over TLS
  with its default certificate, at `<name>-<namespace>.<cluster domain>`
  unless `spec.tsa.ingress.host` is set; elsewhere the host is required and
  TLS is up to the ingress controller. Traffic inside the cluster is plain
  HTTP. The Ingress cannot be disabled once enabled, and the
  `TSAIngressReady` condition reports it.
- Key rotation: raising `spec.tsa.signing.signerGeneration` issues a new
  signing key from the same CA, rolls the pods onto it, and deletes the old
  private key once no pod uses it. A key weaker than the one in use needs
  `spec.tsa.signing.acceptWeakerAlgorithm`.
- Pod options under `spec.tsa`: `resources` (replacing the defaults of 50m
  CPU and 64Mi memory requested, 256Mi memory limit), `nodeSelector`,
  `tolerations`, `affinity`, `topologySpreadConstraints` and
  `priorityClassName`. A template the API server refuses holds the instance
  with `Ready` False, reason `InvalidPodOptions`; pods the Deployment cannot
  create, such as over a quota, show in `TSAReady`.

```yaml
apiVersion: pqc.rhtas.redhat.com/v1alpha1
kind: SecureSignPQC
metadata:
  name: demo
spec:
  version: "2.0"
  tsa:
    signing:
      algorithm: ML-DSA-65
```

An instance name is a DNS label of at most 59 characters, so the names the
operator derives from it stay within Kubernetes limits.

`kubectl get securesignpqc -o wide` shows the version, key algorithms and
readiness; `status.conditions` has `Ready`, `TSAReady`, `TSAIngressReady`,
`Degraded` and `CertificatesExpiring`, which turns True, with a Warning event, when a TSA
signer in use or the CA certificate expires within the `expiry_warning` setting (90
days by default).

The TSA pods run in FIPS 140-3 mode when the node's kernel is. The
`pqc.rhtas.redhat.com/fips` annotation on an instance sets the mode: `auto`
(the default) follows the kernel, `on` enables it on every node, and `only`
also refuses algorithms FIPS does not approve. Any other value holds the
instance with `Ready` False, reason `InvalidFIPSMode`. The images are built
with Go's FIPS module v1.26.0, the first with ML-DSA, which is not yet
certified.

Deleting an instance leaves its key Secrets in place, so recreating it uses
the same keys.

## Install

The operator installs through OLM in AllNamespaces mode, on Kubernetes 1.33
or later.

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: pqc-catalog
  namespace: olm
spec:
  sourceType: grpc
  image: ghcr.io/sealhouse/pqc-catalog:alpha
---
apiVersion: v1
kind: Namespace
metadata:
  name: rhtas-pqc-operator
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: rhtas-pqc-operator
  namespace: rhtas-pqc-operator
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: secure-sign-pqc-operator
  namespace: rhtas-pqc-operator
spec:
  channel: alpha
  name: secure-sign-pqc-operator
  source: pqc-catalog
  sourceNamespace: olm
```

On OpenShift, put the CatalogSource in `openshift-marketplace`.

Each product version's operand images are pinned by digest in
`versions/<version>/images.env` and built into the operator. The bundle
lists them as related images and sets them on the operator container as
`RELATED_IMAGE_<component>_<version>` variables, such as
`RELATED_IMAGE_TSA_2_0`; the operator deploys those, so rewriting the CSV's
image references changes what it deploys. A variable that is not pinned by
digest stops the operator at startup.

## Tuning

Retry, timeout and leader election settings come from `PQC_OPERATOR_*`
environment variables, overridden by the `securesign-pqc-operator-config`
ConfigMap in the operator's namespace. A valid change to the backoff, queue,
`api_timeout`, `degraded_after` or `expiry_warning` settings applies at once;
a change to `api_qps`, `api_burst`, `sync_period`, `concurrent_reconciles` or
the leader election timings restarts the operator's manager, within the same
process. An invalid change is ignored, with a Warning event. The settings
and their defaults are in `internal/tuning/tuning.go`.

## Metrics

The operator serves Prometheus metrics over HTTPS on port 8443 of the
`rhtas-pqc-controller-manager-metrics-service` Service, to callers allowed
to get `/metrics`. Where the Prometheus Operator's `ServiceMonitor` API is
served, the operator creates a ServiceMonitor that presents the token of the
`rhtas-pqc-metrics-scraper` service account, which may read `/metrics` and
nothing else. On OpenShift the service-ca operator issues the serving
certificate, which the operator serves as soon as it is mounted and through
each rotation, and the ServiceMonitor verifies it; elsewhere the certificate
is self-signed and the ServiceMonitor does not verify it. If the API is
removed, the operator stops watching ServiceMonitors and deletes the token
Secret; it creates both again if the API returns.

## Development

| Command | Runs |
|---|---|
| `make test` | Unit and envtest suites, in FIPS 140-3 only mode |
| `make test-resilience` | API server fault tests through Toxiproxy |
| `make lint` | golangci-lint |
| `make docker-build` | Builds and smoke tests the image and pushes it to the local registry, using the `ci` repository checked out next to this one |

`make help` lists the rest. CI runs from the shared workflows in
[sealhouse/ci](https://github.com/sealhouse/ci).

## License

Apache License 2.0.

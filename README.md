# secure-sign-pqc-operator

A Kubernetes operator that runs Sigstore services with post-quantum (ML-DSA)
keys. Each `SecureSignPQC` instance names a product version; version `2.0`
deploys a timestamp authority (TSA) signing with ML-DSA-44, -65 or -87.

The operator is in alpha: every merge to `main` is published to the `alpha`
channel, and the API may change.

## What an instance gets

Certificate signing is off by default. `spec.fulcio.enabled` turns on
Fulcio and the TSA together: Fulcio's certificates last minutes, so a
signature made with one verifies only with a timestamp from the TSA. Once on
it cannot be turned off. Until Fulcio is added, it deploys the TSA alone.
Off, the instance runs no TSA and has no TSA conditions. On, it gets:

- A root CA, an intermediate CA and a TSA signing key, each in a Secret in
  the instance's namespace: `<name>-tsa-root-<r>`,
  `<name>-tsa-intermediate-<r>-<i>` and `<name>-tsa-signer-<r>-<i>-<s>`.
  Certificates last 10 years (root), 5 years (intermediate, never past its
  root) and 1 year (signer, never past its intermediate), as Sigstore issues
  them. Existing Secrets are used as they are; the operator never overwrites
  a key. A restored Secret needs the labels the operator gives its own:
  `app.kubernetes.io/instance: <name>`,
  `app.kubernetes.io/managed-by: rhtas-pqc-operator`,
  `pqc.rhtas.redhat.com/key-role` (`tsa-root`, `tsa-intermediate` or
  `tsa-signer`), `pqc.rhtas.redhat.com/root-generation`, and on an
  intermediate or signer `pqc.rhtas.redhat.com/intermediate-generation`, and
  on a signer `pqc.rhtas.redhat.com/key-generation`.
- A Sigstore trusted root in the ConfigMap `<name>-trusted-root`
  (`trusted_root.json`), listing one timestamp authority per intermediate
  the instance has used. Retired intermediates stay in it with the end of
  their validity period set, so older timestamps keep verifying. Each
  intermediate's public chain is also kept in a ConfigMap
  `<name>-tsa-chain-<r>-<i>`. Deleting the instance leaves the key Secrets
  and chain ConfigMaps in place, so an instance recreated with the same name
  and generations carries on with the same keys and trusted root.
- A TSA Deployment and ClusterIP Service, at the URL in `status.tsa.url`.
- With `spec.tsa.ingress.enabled`, an Ingress for the TSA, at the URL in
  `status.tsa.externalURL`. On OpenShift the router serves it over TLS
  with its default certificate, at `<name>-<namespace>.<cluster domain>`
  unless `spec.tsa.ingress.host` is set; elsewhere the host is required and
  TLS is up to the ingress controller. Traffic inside the cluster is plain
  HTTP. The Ingress cannot be disabled once enabled, and the
  `TSAIngressReady` condition reports it.
- Key rotation, each by raising a counter under `spec.tsa.signing`, which
  can only go up:
  - `signerGeneration` issues a new signing key from the same intermediate.
  - `intermediateGeneration` issues a new intermediate from the same root,
    and a signing key from it.
  - `rootGeneration` issues a new root, an intermediate under it and a
    signing key.

  The operator adds a new intermediate to the trusted root before any pod
  signs with it, rolls the pods onto the new key, and once no pod uses the
  old keys deletes their private keys and marks the old intermediate
  retired in the trusted root, its validity ending 30 seconds later, while
  terminating pods may still sign. `status.tsa.cas` lists each root and
  intermediate with its stage, and the `TSACARotation` condition is True
  while a CA rotation rolls out. Raising a CA counter during a CA rotation
  waits for it to finish, with reason `RotationHeld` and a Warning event.
  If a root's key Secret is deleted, an intermediate rotation under it
  holds the instance with `Ready` False, reason `RootKeyUnavailable`, until
  `rootGeneration` is raised. A key weaker than
  the one it replaces needs `spec.tsa.signing.acceptWeakerAlgorithm`,
  naming the algorithm and the `signerGeneration`, `intermediateGeneration`
  or `rootGeneration` it is for.

  The generated root key is held in a Secret like the other keys. For
  production, plan to keep the root offline: user-supplied CAs and KMS-held
  keys are planned.
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
  fulcio:
    enabled: true
  tsa:
    signing:
      algorithm: ML-DSA-65
```

An instance name is a DNS label of at most 59 characters, so the names the
operator derives from it stay within Kubernetes limits.

`kubectl get securesignpqc -o wide` shows the version, key algorithms and
readiness; `status.conditions` has `Ready`, `TSAReady`, `TSAIngressReady`,
`Degraded`, `TSACARotation` and `CertificatesExpiring`, which turns True, with a Warning event, when a TSA
signer or CA certificate in use expires within the `expiry_warning` setting (90
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

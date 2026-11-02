#!/usr/bin/env bash
# kind-upgrades.sh VERSION...
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
ci="$(cd "${CI_DIR:-${repo}/../ci}" && pwd)"
parallel="${KIND_PARALLEL:-1}"

# one VERSION runs the upgrade test on a fresh cluster.
one() {
  local v="$1" c="sealhouse-${1//./-}" kc ok=0
  kc="${ci}/.state/${c}.kubeconfig"
  kind delete cluster --name "${c}" >/dev/null 2>&1 || true
  if KIND_VERSION="${v}" "${ci}/hack/cluster-up.sh" &&
    KUBECONFIG="${kc}" KUBE_CONTEXT="kind-${c}" "${ci}/hack/test-arbitrary-uid.sh" &&
    make -C "${repo}" --no-print-directory upgrade-run E2E_KUBECONFIG="${kc}" E2E_CONTEXT="kind-${c}"; then
    ok=1
  fi
  kind delete cluster --name "${c}" >/dev/null 2>&1 || true
  rm -f "${kc}"
  [ "${ok}" -eq 1 ] || { echo "kind ${v} failed; alpha is unchanged" >&2; return 1; }
}

if [ "${parallel}" -le 1 ]; then
  for v in "$@"; do
    echo "== kind ${v}"
    one "${v}"
  done
  exit 0
fi

logs="$(mktemp -d)"
trap 'rm -rf "${logs}"' EXIT
failed=0 running=0
for v in "$@"; do
  if [ "${running}" -ge "${parallel}" ]; then
    wait -n || failed=1
    running=$((running - 1))
  fi
  one "${v}" >"${logs}/${v}.log" 2>&1 &
  running=$((running + 1))
done
while [ "${running}" -gt 0 ]; do
  wait -n || failed=1
  running=$((running - 1))
done
for v in "$@"; do
  echo "== kind ${v}"
  cat "${logs}/${v}.log"
done
exit "${failed}"

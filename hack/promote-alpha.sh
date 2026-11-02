#!/usr/bin/env bash
# promote-alpha.sh <catalog-repo>
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <catalog-repo>" >&2; exit 2; }
catalog_repo="$(cd "$1" && pwd)"
repo="$(cd "$(dirname "$0")/.." && pwd)"
registry="${REGISTRY_HOST:-localhost:5001}"
package=secure-sign-pqc-operator
channel=alpha
env_file="${repo}/dist/alpha.env"
fbc="${repo}/dist/catalog/configs/${package}/catalog.json"

get() { sed -n "s/^$1=//p" "${env_file}"; }
catalog_image="$(get CATALOG_IMAGE)"
csv="$(get CSV)"
commit="$(get OPERATOR_COMMIT)"
[ -n "${catalog_image}" ] && [ -n "${csv}" ] && [ -n "${commit}" ] && [ -f "${fbc}" ] ||
  { echo "${env_file} is not from publish-alpha.sh --merge" >&2; exit 1; }
case "${catalog_image}" in
  "${registry}/sealhouse/pqc-catalog@sha256:"*) ;;
  *) echo "catalog ${catalog_image} is not a pqc-catalog digest in ${registry}" >&2; exit 1 ;;
esac
[ -z "$(git -C "${catalog_repo}" status --porcelain)" ] ||
  { echo "${catalog_repo} has uncommitted changes" >&2; exit 1; }

crane_args=()
case "${registry}" in localhost:*) crane_args=(--insecure) ;; esac
crane tag "${crane_args[@]}" "${catalog_image}" "${channel}"
published="$(crane digest "${crane_args[@]}" "${registry}/sealhouse/pqc-catalog:${channel}")"
[ "${catalog_image##*@}" = "${published}" ] ||
  { echo "pqc-catalog:${channel} is ${published}, not ${catalog_image##*@}" >&2; exit 1; }

mkdir -p "${catalog_repo}/${channel}"
cp "${fbc}" "${catalog_repo}/${channel}/catalog.json"
grep -E '^(OPERATOR_IMAGE|BUNDLE_IMAGE|CATALOG_IMAGE|CSV|PREVIOUS_CSV|OPERATOR_COMMIT)=' "${env_file}" \
  >"${catalog_repo}/${channel}/head.env"
git -C "${catalog_repo}" add "${channel}"
git -C "${catalog_repo}" commit -q -m "${channel}: ${csv}"
echo "pqc-catalog:${channel} is ${csv} (${catalog_image}); recorded in ${catalog_repo} $(git -C "${catalog_repo}" rev-parse --short HEAD)"

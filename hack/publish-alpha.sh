#!/usr/bin/env bash
# publish-alpha.sh [--merge <catalog-repo>]
set -euo pipefail

catalog_repo=""
if [ "${1:-}" = --merge ]; then
  [ $# -eq 2 ] || { echo "usage: $0 [--merge <catalog-repo>]" >&2; exit 2; }
  catalog_repo="$(cd "$2" && pwd)"
elif [ $# -ne 0 ]; then
  echo "usage: $0 [--merge <catalog-repo>]" >&2
  exit 2
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"
ci="$(cd "${CI_DIR:-${repo}/../ci}" && pwd)"
# shellcheck disable=SC1091
source "${ci}/hack/lib.sh"

registry="${REGISTRY_HOST:-localhost:5001}"
package=secure-sign-pqc-operator
channel=alpha
kustomize="${KUSTOMIZE:-${repo}/bin/kustomize}"
version="${BUNDLE_VERSION:-$(cat "${repo}/VERSION")-alpha.$(git -C "${repo}" rev-list --count HEAD)}"
tag="${IMAGE_TAG:-$(git -C "${repo}" rev-parse --short HEAD)}"
commit="$(git -C "${repo}" rev-parse HEAD)"
opm="$(lock OPM)"

if [ -n "$(git -C "${repo}" status --porcelain)" ]; then
  echo "publish-alpha.sh: commit or stash the changes first; tag ${tag} and version ${version} name the commit" >&2
  exit 1
fi
dist="${repo}/dist"

crane_args=()
case "${registry}" in localhost:*) crane_args=(--insecure) ;; esac
digest_ref() { echo "${registry}/sealhouse/$1@$(crane digest "${crane_args[@]}" "${registry}/sealhouse/$1:$2")"; }

# The recorded alpha head, in merge mode.
prev_csv=""
prev_fbc=""
if [ -n "${catalog_repo}" ]; then
  head_env="${catalog_repo}/${channel}/head.env"
  if [ -f "${head_env}" ]; then
    prev_csv="$(sed -n 's/^CSV=//p' "${head_env}")"
    prev_commit="$(sed -n 's/^OPERATOR_COMMIT=//p' "${head_env}")"
    prev_fbc="${catalog_repo}/${channel}/catalog.json"
    [ -n "${prev_csv}" ] && [ -n "${prev_commit}" ] && [ -f "${prev_fbc}" ] ||
      { echo "${head_env} or ${prev_fbc} is incomplete" >&2; exit 1; }
    git -C "${repo}" merge-base --is-ancestor "${prev_commit}" HEAD ||
      { echo "alpha head ${prev_csv} was built from ${prev_commit}, which is not an ancestor of ${commit}" >&2; exit 1; }
    [ "${prev_commit}" != "${commit}" ] ||
      { echo "${commit} is already the alpha head (${prev_csv})" >&2; exit 1; }
    # An unrecorded head would drop out of the upgrade graph.
    recorded="$(sed -n 's/^CATALOG_IMAGE=//p' "${head_env}")"
    current="$(crane digest "${crane_args[@]}" "${registry}/sealhouse/pqc-catalog:${channel}")"
    [ "${recorded##*@}" = "${current}" ] ||
      { echo "pqc-catalog:${channel} is ${current}, but ${head_env} records ${recorded}" >&2; exit 1; }
    # Every bundle in the history must still resolve, or the catalog would
    # list versions OLM cannot install.
    for img in $(jq -r 'select(.schema == "olm.bundle") | .image' "${prev_fbc}"); do
      crane digest "${crane_args[@]}" "${img}" >/dev/null 2>&1 ||
        { echo "bundle ${img} from the alpha history is missing from ${registry}" >&2; exit 1; }
    done
    echo "alpha head ${prev_csv} (operator ${prev_commit:0:12})" >&2
  else
    echo "no alpha head in ${catalog_repo}: this is the first alpha" >&2
  fi
fi

# 1. Operator image.
built="$("${ci}/hack/build-image.sh" "${repo}" "${tag}" | tail -1)"
operator_image="${registry}/sealhouse/${built}"
echo "operator ${operator_image}" >&2

# 2. Bundle.
rm -rf "${dist}/bundle"
go -C "${repo}/tools/bundle" build -o "${dist}/bin/bundle" .
csv="$("${kustomize}" build "${repo}/config/default" \
  | (cd "${repo}" && "${dist}/bin/bundle" -package "${package}" -channels "${channel}" \
      -version "${version}" -replaces "${prev_csv}" -image "${operator_image}" -out "${dist}/bundle"))"
docker build -q -f "${dist}/bundle/bundle.Dockerfile" -t "${registry}/sealhouse/${package}-bundle:v${version}" "${dist}/bundle" >/dev/null
docker push -q "${registry}/sealhouse/${package}-bundle:v${version}" >/dev/null
bundle_image="$(digest_ref "${package}-bundle" "v${version}")"
echo "bundle ${bundle_image} (${csv}${prev_csv:+, replaces ${prev_csv}})" >&2

# 3. Catalog.
rm -rf "${dist}/catalog"
mkdir -p "${dist}/catalog/configs/${package}"
fbc="${dist}/catalog/configs/${package}/catalog.json"
render() {
  docker run --rm -v "${dist}/bundle:/bundle:ro" "${opm}" render /bundle -o json \
    | jq --arg img "${bundle_image}" '.image = $img | .relatedImages = [{name: "", image: $img}] + .relatedImages'
}
if [ -n "${prev_fbc}" ]; then
  { cat "${prev_fbc}"; render; } | jq -s --arg c "${channel}" --arg csv "${csv}" --arg prev "${prev_csv}" '
    map(if .schema == "olm.channel" and .name == $c then .entries += [{name: $csv, replaces: $prev}] else . end) | .[]' >"${fbc}"
else
  {
    jq -n --arg p "${package}" --arg c "${channel}" '{schema: "olm.package", name: $p, defaultChannel: $c}'
    jq -n --arg p "${package}" --arg c "${channel}" --arg csv "${csv}" \
      '{schema: "olm.channel", package: $p, name: $c, entries: [{name: $csv}]}'
    render
  } >"${fbc}"
fi
docker run --rm -v "${dist}/catalog/configs:/configs:ro" "${opm}" validate /configs
catalog_tag="$(if [ -n "${catalog_repo}" ]; then echo "candidate-${tag}"; else echo "pr-${tag}"; fi)"
cp "${repo}/.sealhouse/catalog.Containerfile" "${dist}/catalog/Containerfile"
docker build -q --build-arg OPM="${opm}" -f "${dist}/catalog/Containerfile" \
  -t "${registry}/sealhouse/pqc-catalog:${catalog_tag}" "${dist}/catalog" >/dev/null
docker push -q "${registry}/sealhouse/pqc-catalog:${catalog_tag}" >/dev/null
catalog_image="$(digest_ref pqc-catalog "${catalog_tag}")"
echo "catalog ${catalog_image}" >&2

cat > "${dist}/alpha.env" <<ENV
OPERATOR_IMAGE=${operator_image}
BUNDLE_IMAGE=${bundle_image}
CATALOG_IMAGE=${catalog_image}
CSV=${csv}
PREVIOUS_CSV=${prev_csv}
OPERATOR_COMMIT=${commit}
ENV
cat "${dist}/alpha.env"

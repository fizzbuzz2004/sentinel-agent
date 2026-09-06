#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${VERSION:-0.1.0}"
OUT="${ROOT}/.package/rpm"
rm -rf "${OUT}"
mkdir -p "${OUT}/SOURCES" "${OUT}/SPECS"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-w -s' -o "${OUT}/SOURCES/sentinel-agent" "${ROOT}/cmd/agent"
cp "${ROOT}/deployments/systemd/sentinel-agent.service" "${OUT}/SOURCES/sentinel-agent.service"
sed "s/^Version:.*/Version:        ${VERSION}/" "${ROOT}/deployments/rpm/sentinel-agent.spec" > "${OUT}/SPECS/sentinel-agent.spec"
rpmbuild -bb --define "_topdir ${OUT}" "${OUT}/SPECS/sentinel-agent.spec"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE="${ROOT}/.package/deb"
VERSION="${VERSION:-0.1.0}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/DEBIAN" "${STAGE}/opt/sentinel-agent" "${STAGE}/etc/systemd/system" "${STAGE}/etc/default" "${STAGE}/var/lib/sentinel"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-w -s' -o "${STAGE}/opt/sentinel-agent/sentinel-agent" "${ROOT}/cmd/agent"
install -m 0644 "${ROOT}/deployments/systemd/sentinel-agent.service" "${STAGE}/etc/systemd/system/sentinel-agent.service"
install -m 0755 "${ROOT}/deployments/deb/DEBIAN/postinst" "${STAGE}/DEBIAN/postinst"
install -m 0755 "${ROOT}/deployments/deb/DEBIAN/prerm" "${STAGE}/DEBIAN/prerm"
install -m 0644 "${ROOT}/deployments/deb/DEBIAN/control" "${STAGE}/DEBIAN/control"
install -m 0644 "${ROOT}/deployments/deb/DEBIAN/conffiles" "${STAGE}/DEBIAN/conffiles"
sed -i "s/^Version:.*/Version: ${VERSION}/" "${STAGE}/DEBIAN/control"
dpkg-deb --build "${STAGE}" "${ROOT}/sentinel-agent_${VERSION}_amd64.deb"

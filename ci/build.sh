#!/bin/bash

set -eux

echo "Env domain: ${ENV_DOMAIN}"

ORIG_PWD="${PWD}"

# Create our own GOPATH
export GOPATH="${ORIG_PWD}/go"

# Symlink our source dir from inside of our own GOPATH
mkdir -p "${GOPATH}/src/github.com/govau"
ln -s "${ORIG_PWD}/src" "${GOPATH}/github.com/govau/grafana-cf/"
cd "${GOPATH}/src/github.com/18F/cg-dashboard"

# Install go deps
dep ensure

# Build and deploy the frontend
cd ${ORIG_PWD}/src

# Build the thing
go install github.com/govau/grafana-cf/cmd/grafana-proxy

# Copy artefacts to output directory
cp "${ORIG_PWD}/src/go/bin/grafana-proxy" "${ORIG_PWD}/build/grafana-proxy"
cp "${ORIG_PWD}/src/ci/Procfile" "${ORIG_PWD}/build/Procfile"
printf "\ndomain: system.${ENV_DOMAIN}\n" | cat "${ORIG_PWD}/src/ci/manifest.yml" - > "${ORIG_PWD}/build/manifest.yml"

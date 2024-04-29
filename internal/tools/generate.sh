#!/bin/sh
set -eu

SCHEMA="$(mktemp)"
trap 'rm -f "$SCHEMA"' EXIT

go run k8s.io/kube-openapi/cmd/openapi-gen \
  -v 0 \
  --go-header-file .reuse/boilerplate.go.txt \
  --output-dir client/openapi \
  --output-pkg github.com/ironcore-dev/metal/client/openapi \
  --output-file zz_generated.openapi.go \
  --report-filename /dev/null \
  k8s.io/apimachinery/pkg/apis/meta/v1 \
  k8s.io/apimachinery/pkg/runtime \
  k8s.io/apimachinery/pkg/version \
  k8s.io/api/core/v1 \
  github.com/ironcore-dev/metal/api/v1alpha1

go run github.com/ironcore-dev/metal/internal/tools/models-schema > "$SCHEMA"
go run k8s.io/code-generator/cmd/applyconfiguration-gen \
  -v 0 \
  --go-header-file .reuse/boilerplate.go.txt \
  --openapi-schema "$SCHEMA" \
  --output-dir client/applyconfiguration \
  --output-pkg github.com/ironcore-dev/metal/client/applyconfiguration \
  github.com/ironcore-dev/metal/api/v1alpha1

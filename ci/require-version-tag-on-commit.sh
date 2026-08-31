#!/usr/bin/env bash
# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

semver_tag_on_commit() {
  local commit="${1:-HEAD}"
  local sha tag

  sha="$(git rev-parse "${commit}")"
  if [ -n "${CI:-}" ]; then
    git ls-remote --tags origin \
      | awk -v sha="${sha}" '$1 == sha { print $2 }' \
      | sed 's|\^{}||;s|refs/tags/||' \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
      | head -1 \
      || true
  else
    git tag --points-at "${commit}" 2>/dev/null \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
      | head -1 \
      || true
  fi
}

if [ -n "${CI:-}" ]; then
  git fetch --tags --force 2>/dev/null || true
fi

tag="$(semver_tag_on_commit HEAD)"
if [ -z "${tag}" ]; then
  echo "No semver tag on commit $(git rev-parse HEAD); publish is skipped." >&2
  exit 1
fi

echo "Semver tag on commit: ${tag}"

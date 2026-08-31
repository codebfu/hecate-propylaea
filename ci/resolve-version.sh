#!/usr/bin/env bash
# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

VERSION_FILE="${VERSION_FILE:-version.env}"

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

list_semver_tags() {
  local prefix="$1"

  if [ -n "${CI:-}" ]; then
    git ls-remote --tags origin "refs/tags/${prefix}*" \
      | sed 's|\^{}||;s|.*refs/tags/||' \
      | grep -E "^${prefix//./\\.}[0-9]+$" \
      || true
  else
    git tag -l "${prefix}*" 2>/dev/null || true
  fi
}

read_base_version() {
  grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/'
}

write_version_env() {
  echo "VERSION=${1}" > "${VERSION_FILE}"
  echo "Resolved version: ${1}"
}

compute_next_patch() {
  local major="$1"
  local minor="$2"
  local base_patch="$3"
  local latest_patch=""
  local tag patch

  while IFS= read -r tag; do
    [ -n "${tag}" ] || continue
    patch="${tag#v}"
    patch="${patch##*.}"
    if [ -z "${latest_patch}" ] || [ "${patch}" -gt "${latest_patch}" ]; then
      latest_patch="${patch}"
    fi
  done < <(list_semver_tags "v${major}.${minor}.")

  if [ -n "${latest_patch}" ]; then
    echo $((latest_patch + 1))
  else
    echo "${base_patch}"
  fi
}

remote_tag_exists() {
  local tag_name="$1"

  if [ -n "${CI:-}" ]; then
    git ls-remote --tags origin "refs/tags/${tag_name}" | grep -q .
  else
    git rev-parse "${tag_name}^{commit}" >/dev/null 2>&1
  fi
}

push_version_tag() {
  local version="$1"
  local tag_name=""
  local base major minor base_patch

  git config user.email "ci@gitlab"
  git config user.name "GitLab CI"
  git remote set-url origin \
    "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git"

  for _attempt in 1 2 3; do
    tag_name="v${version}"
    if remote_tag_exists "${tag_name}"; then
      git fetch --tags --force 2>/dev/null || true
      base="$(read_base_version)"
      major="$(echo "${base}" | cut -d. -f1)"
      minor="$(echo "${base}" | cut -d. -f2)"
      base_patch="$(echo "${base}" | cut -d. -f3)"
      version="${major}.${minor}.$(compute_next_patch "${major}" "${minor}" "${base_patch}")"
      continue
    fi

    git tag "${tag_name}" "${CI_COMMIT_SHA}"
    if git push origin "${tag_name}"; then
      write_version_env "${version}"
      return 0
    fi

    git tag -d "${tag_name}" 2>/dev/null || true
    git fetch --tags --force 2>/dev/null || true
    base="$(read_base_version)"
    major="$(echo "${base}" | cut -d. -f1)"
    minor="$(echo "${base}" | cut -d. -f2)"
    base_patch="$(echo "${base}" | cut -d. -f3)"
    version="${major}.${minor}.$(compute_next_patch "${major}" "${minor}" "${base_patch}")"
  done

  echo "Failed to push version tag after retries. Enable CI job token write_repository access." >&2
  exit 1
}

if [ -n "${CI_COMMIT_TAG:-}" ]; then
  write_version_env "${CI_COMMIT_TAG#v}"
  exit 0
fi

if [ -n "${CI:-}" ]; then
  git fetch --tags --force 2>/dev/null || true
fi

base="$(read_base_version)"
major="$(echo "${base}" | cut -d. -f1)"
minor="$(echo "${base}" | cut -d. -f2)"
base_patch="$(echo "${base}" | cut -d. -f3)"

if [ "${CI_COMMIT_BRANCH:-}" != "master" ]; then
  # Outside master CI, prefer an existing tag on HEAD when present.
  existing="$(semver_tag_on_commit HEAD)"
  if [ -n "${existing}" ]; then
    write_version_env "${existing#v}"
    exit 0
  fi
  write_version_env "${base}"
  exit 0
fi

version="${major}.${minor}.$(compute_next_patch "${major}" "${minor}" "${base_patch}")"

if [ -n "${CI:-}" ]; then
  push_version_tag "${version}"
else
  write_version_env "${version}"
fi

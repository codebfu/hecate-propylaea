#!/usr/bin/env bash
# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

sync_git_repo() {
  local dir="$1"
  local url="$2"
  local branch="${3:-master}"

  if [ -d "${dir}/.git" ]; then
    git -C "${dir}" remote set-url origin "${url}"
    git -C "${dir}" fetch --depth 1 origin "${branch}"
    git -C "${dir}" reset --hard
    git -C "${dir}" clean -fd
    git -C "${dir}" checkout -B "${branch}" "origin/${branch}"
  else
    rm -rf "${dir}"
    git clone --depth 1 -b "${branch}" "${url}" "${dir}"
  fi
}

hecate-repo="https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/hecate/hecate.git"
sync_git_repo "${ROOT}/../hecate" "${hecate-repo}" master

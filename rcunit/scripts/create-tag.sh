#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ "${BRANCH}" != "main" ]; then
  echo "You are not in the main branch!"
  exit 1
fi

if [ -z "$VERSION" ]; then
  echo "VERSION env is empty. Deriving it from latest tag"
  latest=$(git tag -l | sort -V | tail -n 1)
  echo "The latest version is $latest"
  prefix="${latest%rc*}rc"
  number="${latest##*rc}"
  next_version="${prefix}$((number + 1))"
  echo "Next version is ${next_version}"
  VERSION=$next_version
fi

echo git tag -a ${VERSION} -m "${VERSION}" && echo "Created tag ${VERSION}"

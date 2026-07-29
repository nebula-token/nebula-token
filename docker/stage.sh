#!/bin/sh
#
# docker/stage.sh — give one language a writable copy of what it needs.
#
#   sh /repo/docker/stage.sh <language>
#
# WHY THIS EXISTS
#
# The repository is bind-mounted READ-ONLY at /repo (docker/compose.yml rule 4):
# a conformance run must not be able to modify the tree it is judging, and a
# container must never leave build output in your working copy. But almost every
# toolchain writes inside the package directory it is told to build —
# node_modules/, target/, vendor/, _build/, obj/, .dart_tool/, *.egg-info — and
# the two that do not today may tomorrow. So each service stages a copy into
# /work, which is a tmpfs, and works there.
#
# TWO THINGS THIS FILE MUST GET RIGHT
#
# 1. The layout is preserved: /work/spec sits beside /work/packages/<language>,
#    exactly as spec/ sits beside packages/<language> in the repository. Every
#    conformance runner in all ten languages finds the vectors by walking up from
#    its own source file until it sees spec/test-vectors.json. Flatten this, or
#    stage the package without spec/, and all ten runners fail — not with a
#    conformance error, with "vectors not found".
#
# 2. Host build output is NOT copied. The harness exists to reproduce a clean
#    checkout in a clean toolchain; inheriting the artefacts of your last local
#    build (a Windows-path obj/, a musl-linked node_modules/, a target/ from
#    another rustc) is how a harness starts lying. Excluding those directories
#    also keeps the copy to a few megabytes.
#
# ONE PACKAGE IS NOT SELF-CONTAINED
#
# PHP's manifest is the REPOSITORY-ROOT composer.json, because Packagist reads
# composer.json from a repository root only and this project publishes all ten
# languages from one repository. So the PHP service's composer project root is
# /work, not /work/packages/php, and staging packages/php alone would leave it
# with no manifest at all. The root manifest is copied for that service, and only
# for it; the list below is an allow-list rather than "copy the root", so a new
# root file cannot start leaking into the harness unnoticed.
#
# Written in POSIX sh with no assumptions beyond cp/find: it runs unchanged in
# ten different official images.

set -eu

pkg=${1:?usage: sh /repo/docker/stage.sh <language>}

src=/repo/packages/$pkg
dst=/work/packages/$pkg

if [ ! -d "$src" ]; then
  echo "stage: no such package: packages/$pkg" >&2
  exit 2
fi

# The single most likely misconfiguration, caught with a message that says what
# to fix: mounting the package directory instead of the repository root.
if [ ! -f /repo/spec/test-vectors.json ]; then
  echo "stage: /repo does not look like the NEBULA repository root — no spec/test-vectors.json." >&2
  echo "stage: docker/compose.yml must bind-mount the REPOSITORY ROOT at /repo, not a package;" >&2
  echo "stage: every conformance runner walks up from its own source file looking for that file." >&2
  exit 2
fi

mkdir -p "$dst" /work/spec
cp -a /repo/spec/. /work/spec/

# Top-level exclusions first, so the big directories are never read at all.
for entry in "$src"/* "$src"/.[!.]*; do
  [ -e "$entry" ] || continue # an unmatched glob is a literal, not a file
  case ${entry##*/} in
  node_modules | dist | target | vendor | _build | deps | build | \
    bin | obj | .dart_tool | .venv | __pycache__ | \
    .pytest_cache | .mypy_cache | .ruff_cache | *.egg-info)
    continue
    ;;
  esac
  cp -a "$entry" "$dst"/
done

# Then the same names nested deeper — packages/csharp/src/*/obj, for instance,
# and __pycache__ beside the Python sources.
find "$dst" -type d \
  \( -name node_modules -o -name obj -o -name bin -o -name target \
  -o -name __pycache__ -o -name .pytest_cache -o -name .dart_tool \
  -o -name '*.egg-info' \) -prune -exec rm -rf {} +

# The root files one language needs, named one language at a time. PHP is the
# only entry and composer.json is the only file: it is the manifest Packagist
# publishes, it declares the psr-4 root as packages/php/src, and `composer
# install` has nothing to read without it. The php service therefore runs from
# /work rather than /work/packages/php.
extra=""
case $pkg in
php) extra="composer.json" ;;
esac
for f in $extra; do
  if [ ! -f "/repo/$f" ]; then
    echo "stage: /repo/$f is missing, and packages/$pkg cannot be built without it." >&2
    exit 2
  fi
  cp -a "/repo/$f" /work/
done

echo "staged packages/$pkg${extra:+, $extra} and spec/ into /work (source: /repo, read-only)"

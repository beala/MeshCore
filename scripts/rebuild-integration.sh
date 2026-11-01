#!/usr/bin/env bash
# Rebuilds the integration branch from scratch: upstream dev + every branch listed in
# scripts/integration-branches.txt, merged in order. The listed branches are never modified,
# so they stay clean for upstream PRs.
#
# Conflict resolutions are remembered with git rerere. Before merging, the script replays the
# merges of the last published integration branch so rerere relearns how each conflict was
# resolved, even on a fresh clone or CI runner. You only resolve a given conflict once.
#
# Usage: scripts/rebuild-integration.sh [--push]
#
# If a merge stops on a new conflict: fix the files, `git add` them, `git commit --no-edit`,
# then run the script again (it rebuilds from scratch and rerere replays your fix).
# Publish with --push, or push the branch yourself, so the fix is remembered next time.
#
# Settings (environment variables):
#   REMOTE  remote holding your branches          (default: origin)
#   BASE    upstream branch to build on           (default: dev)
#   TARGET  integration branch to (re)create      (default: beala/integration)
set -euo pipefail

REMOTE=${REMOTE:-origin}
BASE=${BASE:-dev}
TARGET=${TARGET:-beala/integration}
UPSTREAM_URL=https://github.com/meshcore-dev/MeshCore.git
PUSH=false
[[ "${1:-}" == "--push" ]] && PUSH=true

cd "$(git rev-parse --show-toplevel)"
LIST_FILE=scripts/integration-branches.txt

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "Working tree has uncommitted changes; commit or stash them first." >&2
  exit 1
fi

# Read the list now: it lives on this branch and disappears once we check out the target.
mapfile -t BRANCHES < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$LIST_FILE" | grep -v '^$')

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$UPSTREAM_URL"
git fetch --no-tags upstream "$BASE"
git fetch --no-tags "$REMOTE"
git config rerere.enabled true
git config rerere.autoupdate true

# Relearn conflict resolutions from the previous integration branch (like git's rerere-train.sh).
PREV=""
if git rev-parse -q --verify "refs/remotes/$REMOTE/$TARGET" >/dev/null; then
  PREV=$(git rev-parse "refs/remotes/$REMOTE/$TARGET")
  echo "Relearning conflict resolutions from $REMOTE/$TARGET..."
  for merge in $(git rev-list --merges --first-parent "upstream/$BASE..$PREV"); do
    git checkout -q --detach "$merge^1"
    if ! git merge -q --no-commit --no-ff "$merge^2" >/dev/null 2>&1; then
      git checkout -q "$merge" -- .   # take the resolved files from the recorded merge
      git rerere >/dev/null
    fi
    git reset -q --hard
  done
fi

git checkout -q -B "$TARGET" "upstream/$BASE"
echo "Building $TARGET on upstream/$BASE ($(git rev-parse --short HEAD))"

for b in "${BRANCHES[@]}"; do
  ref="$REMOTE/$b"
  if ! git rev-parse -q --verify "refs/remotes/$ref" >/dev/null; then
    echo "  MISSING  $b (not found on $REMOTE)" >&2
    exit 1
  fi
  if git merge-base --is-ancestor "$ref" HEAD; then
    echo "  skip     $b (already in base; upstream merged it, so it can come off the list)"
    continue
  fi
  if git merge -q --no-ff --no-edit -m "Merge branch '$b' into $TARGET" "$ref" >/dev/null 2>&1; then
    echo "  merged   $b"
  elif [[ -z "$(git diff --name-only --diff-filter=U)" ]]; then
    git commit -q --no-edit
    echo "  merged   $b (conflict resolved from memory)"
  else
    echo "  CONFLICT $b in:" >&2
    git diff --name-only --diff-filter=U | sed 's/^/             /' >&2
    echo "Resolve, git add, git commit --no-edit, then rerun this script." >&2
    exit 1
  fi
done

CHANGED=true
if [[ -n "$PREV" && "$(git rev-parse HEAD^{tree})" == "$(git rev-parse "$PREV^{tree}")" ]]; then
  # Same content as last time: keep the published commit so its hash (and release) stays put.
  CHANGED=false
  git reset -q --hard "$PREV"
  echo "No changes compared to $REMOTE/$TARGET."
else
  echo "Rebuilt $TARGET with changes."
  if $PUSH; then
    git push --force-with-lease="$TARGET:$PREV" "$REMOTE" "$TARGET"
  fi
fi

# Report to GitHub Actions when run there.
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "changed=$CHANGED" >> "$GITHUB_OUTPUT"
  echo "sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"
fi

#!/bin/sh

set -e

# The post-commit hook runs after the commit has already successfully
# completed.  HEAD and the branch ref have been updated to the new commit SHA,
# and an appropriate entry was added to the reflog.

oldcommit="$(git rev-parse HEAD)"
newcommit="$(/usr/bin/gitbrutec 01234567 ffffff00 | \
    awk '{ print $3 }')"

# Sanity check.
if ! git diff --quiet "$newcommit"; then
    echo "Unexpected difference, aborting (${newcommit})."
    exit 1
fi

git update-ref -m "gitbrutec: chosen prefix" --create-reflog HEAD "$newcommit"
echo "Rewrote $(git log -1 --pretty=format:%h $oldcommit) as $(git log -1 --pretty=format:%h $newcommit)"

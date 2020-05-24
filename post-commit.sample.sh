#!/bin/sh

set -e

# The post-commit hook runs after the commit has already successfully
# completed.  HEAD and the branch ref have been updated to the new commit SHA,
# and an appropriate entry was added to the reflog.
#
# To rewrite the SHA with our chosen prefix, we need to:
# 1. Find a commit object with the prefix we want but otherwise identical to
#    HEAD.
# 2. Append a new entry to the appropriate reflog files
#    (e.g., .git/logs/{HEAD,refs/heads/master}).
# 3. Rewrite the ref file (e.g., .git/refs/heads/master)

# (1)
newcommit="$(/usr/bin/gitbrutec 01234567 ffffffff | \
    awk '{ print $3 }')"

# Sanity check.
if ! git diff --quiet "$newcommit"; then
    echo "Unexpected difference, aborting (${newcommit})."
    exit 1
fi

# Figure out which branch HEAD points at; e.g., "refs/heads/master".  Similar
# to just taking the 2nd field from the ".git/HEAD" file.
headref="$(git rev-parse --symbolic-full-name HEAD)"

# (2)
dotgitpath="$(git rev-parse --git-dir)"
oldcommit="$(git rev-parse HEAD)"

# Take the existing reflog entry for the commit and just update it with the new
# hashes.
newrefline="$(tail -n1 "${dotgitpath}/logs/HEAD" | \
    awk "{ \$1 = \"${oldcommit}\" ; \$2 = \"${newcommit}\" ; print \$0 }")"

printf "%s\n" "$newrefline" | \
    tee -a "${dotgitpath}/logs/HEAD" \
           "${dotgitpath}/logs/${headref}" \
    > /dev/null

fsync "${dotgitpath}/logs/HEAD" "${dotgitpath}/logs/${headref}"

# (3)
printf "%s\n" "$newcommit" > "${dotgitpath}/${headref}"
fsync "${dotgitpath}/${headref}"

echo "Rewrote $(git log -1 --pretty=format:%h $oldcommit) as $(git log -1 --pretty=format:%h $newcommit)"

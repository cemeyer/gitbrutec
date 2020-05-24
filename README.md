gitbrutec
=========

Performs a brute-force search for a git commit object with a chosen prefix
(optionally, with some significant bitmask).

By default, a nonce is added to the commit headers.  Other git tools ignore
headers they do not recognize, but it is incorporated into the commit hash and
makes for easy searching.

Optionally, in "date" mode (`-d`), no nonce is added.  Instead, the author and
committer timestamps are walked backwards to generate collisions.  If the
commit was dated after its parent, we make sure to preserve that property and
do not walk commit dates earlier than the parent commit.

When a successful prefix-match is found, `gitbrutec` creates a new commit
object in the git content store and prints its full hash, but does not
manipulate the current `HEAD` or branch.  After the commit is created, users
can manually switch to it with:

`git reset --hard OUTPUT_HASH`

(`git diff OUTPUT_HASH` can be used first to verify the new commit is identical
to the current `HEAD`.  Take care to only use `git reset --hard` with a clean
tree.)

For an example of how to mechanically switch to the chosen-prefix commit
without destroying the working tree or index, see
[`post-commit.sample.sh`](//github.com/cemeyer/gitbrutec/blob/master/post-commit.sample.sh).

Shorter prefixes match more quickly.  Each additional hexadeximal digit can be
expected to expand the search space by a factor of 16x.

Example
-------

For an example, look at
[the commit history of this repository](//github.com/cemeyer/gitbrutec/commits/master).

Usage
-----

```
    $ gitbrutec 0000000
    Created commit 00000000d462bc21b5903ee00545e4a7408dcb12
```

Dependencies
------------

`gitbrutec` depends on the BSD Makefile build system, Concurrency-kit for IPC,
OpenSSL for SHA1, and C11 concurrency primitives (mutex, condvar, thread).

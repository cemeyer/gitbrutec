gitbrutec
=========

Brute-forces author and committer timestamps (equal or earlier to the existing
commit) such that the resulting git commit's SHA1 has a chosen prefix.

It creates the commit object in the git content store and prints its full hash,
but does not manipulate the current `HEAD` or branch.  After the colliding
commit is created, users can manually switch to the chosen-prefix commit object
with:

`git reset --hard OUTPUT_HASH`

(`git diff OUTPUT_HASH` can be used first to verify the new commit is identical
to the current `HEAD`.  Take care to only use `git reset --hard` with a clean
tree.)

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

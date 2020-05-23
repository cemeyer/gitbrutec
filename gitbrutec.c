/*
 * Derived from Brad Fitz' go "gitbrute" (ASL2), but substantially rewritten.
 * I believe that means I can use a different license for my work (not a
 * lawyer).
 *
 * Copyright 2019 Conrad Meyer <cem@FreeBSD.org>
 *
 * SPDX-License-Identifier: WTFNMFPL-1.0
 * License text follows:
 *
 * DO WHAT THE FUCK YOU WANT TO BUT IT'S NOT MY FAULT PUBLIC LICENSE
 * Version 1, October 2013
 *
 * Copyright  2013 Ben McGinnes <ben@adversary.org>
 *
 * Everyone is permitted to copy and distribute verbatim or modified copies of
 * this license document, and changing it is allowed as long as the name is
 * changed.
 *
 * DO WHAT THE FUCK YOU WANT TO BUT IT'S NOT MY FAULT PUBLIC LICENSE TERMS AND
 * CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
 *
 * 0. You just DO WHAT THE FUCK YOU WANT TO.
 *
 * 1. Do not hold the author(s), creator(s), developer(s) or distributor(s)
 * liable for anything that happens or goes wrong with your use of the work.
 */

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <threads.h>
#include <time.h>
#include <unistd.h>

#include <ck_ring.h>

#include <openssl/sha.h>

/* XXX: Missing ldscript: '*(SORT_BY_ALIGNMENT(.data.read_frequently))'. */
#ifndef __read_frequently
#define	__read_frequently	__section(".data.read_frequently")
#endif
#ifndef __read_mostly
#define	__read_mostly		__section(".data.read_mostly")
#endif

static const char *progname;

#define	MAX_PREFIX_LEN	10	/* Optimize cache use for realistic match sizes.  Max max: 20 (SHA1). */
#define	MAX_HEX_PRELEN	(MAX_PREFIX_LEN * 2)

static bool forceflag __read_mostly;
static bool verboseflag __read_mostly;
static bool nomask __read_frequently = true;
static char chosen_prefix[MAX_HEX_PRELEN],
	    chosen_mask[MAX_HEX_PRELEN],
	    cprefix_bin[MAX_PREFIX_LEN] __read_frequently,
	    cmask_bin[MAX_PREFIX_LEN] __read_frequently;
static size_t prefix_len_nibbles __read_mostly;
static unsigned nthreads __read_mostly;

static const char *the_object __read_mostly;
static size_t the_obj_size __read_mostly;

static time_t start __read_mostly;

static mtx_t win_coord_lock;
static atomic_bool win_taken __read_mostly = ATOMIC_VAR_INIT(false);
static cnd_t win_condvar;

static ck_ring_t possibilities;
static ck_ring_buffer_t poss_buf[1024];
struct free_queue {
	ck_ring_t q;
	ck_ring_buffer_t ringbuf[64];
};
static struct free_queue *poss_return_buf;

static void
usage(void)
{
	fprintf(stderr,
"usage: %s [-fv] [-t THREADS] PREFIX [MASK]\n"
"\n"
"        -f : Force.  Re-run, even if current hash matches prefix.\n"
"        -t THREADS : Specify the number of threads to use.  The tool\n"
"             defaults to 'kern.smp.cores', if available, falling back to\n"
"             'hw.ncpu' or sysconf() or 1 if none are available.\n"
"        -v : Verbose.\n"
"        PREFIX : Specify the target prefix in hexadecimal.  (This tool\n"
"             is limited to prefixes of bitlengths that are multiples of 4.)\n"
"        MASK : Specify the target mask in hex.  If absent, assumes every\n"
"             prefix bit is significant, i.e., ffff...ffff.\n"
"\n", progname);
	exit(EX_USAGE);
}

static int
validate_and_sanitize_hex_in_place(char *p, char *b)
{
	unsigned i, n;

	for (i = 0; *p != 0; p++, i++) {
		if (isdigit(*p)) {
			n = *p - '0';
		} else if (isupper(*p)) {
			n = *p - 'A' + 10;
		} else if (islower(*p)) {
			n = *p - 'a' + 10;
			*p = toupper(*p);
		} else
			return (EINVAL);

		assert(n >= 0 && n <= 0xf);

		/* Hex representation is big endian. */
		if ((i % 2) == 0) {
			*b = n << 4;
		} else {
			*b |= n;
			b++;
		}
	}
	return (0);
}

/*
 * Gather stdoutput, if desired; terminate with fatal error if the child
 * process fails.
 */
static void
command(char **stdoutput, const char *cmd)
{
	FILE *memst_out, *p;
	const char *mode;
	char buffer[8192];
	size_t unused, rd, wr;
	int error;

	/* Buffer output if requested */
	memst_out = NULL;
	if (stdoutput != NULL) {
		memst_out = open_memstream(stdoutput, &unused);
		if (memst_out == NULL)
			err(EX_OSERR, "%s: open_memstream", __func__);
	}

	mode = "r";

	p = popen(cmd, mode);
	if (p == NULL)
		err(EX_OSERR, "%s: popen '%s'", __func__, cmd);

	if (stdoutput != NULL) {
		while (!feof(p) && !ferror(p)) {
			rd = fread(buffer, 1, sizeof(buffer), p);
			if (rd > 0) {
				wr = fwrite(buffer, 1, rd, memst_out);
				if (wr < rd)
					errx(EX_OSERR, "%s: copied %zu/%zu bytes to memstream",
					    __func__, wr, rd);
			}
			if (rd == 0)
				break;
		}
		fclose(memst_out);
	}

	error = pclose(p);
	if (error < 0)
		err(EX_OSERR, "%s: pclose", __func__);

	if (WIFSIGNALED(error))
		errx(EX_SOFTWARE, "cmd '%s' died with uncaught signal %d", cmd, WTERMSIG(error));
	else if (!WIFEXITED(error))
		errx(EX_SOFTWARE, "cmd '%s' status unrecognized: %d", cmd, error);

	error = WEXITSTATUS(error);
	if (error != 0)
		errx(EX_SOFTWARE, "cmd '%s' exited with non-zero status %d", cmd, error);
}

static char *
curhash(void)
{
	char *output;
	ssize_t i;

	command(&output, "git rev-parse HEAD");

	/* trim trailing white space */
	for (i = strlen(output) - 1; isspace(output[i]) && i >= 0; i--)
		output[i] = '\0';

	if (verboseflag)
		printf("%s: Got hash '%s'\n", __func__, output);

	return (output);
}

static char *
catfile_p_hash(const char *hash)
{
	char *output, cmd[100], *nn;

	snprintf(cmd, sizeof(cmd), "git cat-file -p %s", hash);
	command(&output, cmd);

	nn = strstr(output, "\n\n");
	if (nn == NULL)
		errx(EX_SOFTWARE, "%s: No \\n\\n in git cat-file -p %s",
		    __func__, hash);

	return (output);
}

static int
my_sysctl(const char *name)
{
	char val[sizeof(uintmax_t)];
	union {
		uint64_t u64;
		uint32_t u32;
		uint16_t u16;
		uint8_t u8;
	} uval;
	size_t vallen;
	int rc;

	vallen = sizeof(val);
	rc = sysctlbyname(name, val, &vallen, NULL, 0);
	if (rc != 0) {
		if (errno == ENOENT)
			return (rc);
		err(EX_SOFTWARE, "%s: %s", __func__, name);
	}

	switch (vallen) {
	case 4:
		memcpy(&uval.u32, val, vallen);
		if (uval.u32 > INT_MAX)
			errx(EX_SOFTWARE, "API surprise: %s value: 0x%x", name,
			    uval.u32);
		return (uval.u32);
	case 2:
		memcpy(&uval.u16, val, vallen);
		return (uval.u16);
	case 1:
		memcpy(&uval.u8, val, vallen);
		return (uval.u8);
	default:
		errx(EX_SOFTWARE, "API surprise: %s, len %zu", name, vallen);
	}
	/* UNREACHABLE */
	abort();
}

struct try {
	unsigned commit_behind;
	unsigned author_behind;
};

static void
explore_emit(struct try tt)
{
	static size_t j, k;

	struct try *t;
	void *r;
	unsigned len;
	size_t i;

	/* Poll for suicide signal occasionally. */
	if ((++k % 32) == 0 &&
	    atomic_load_explicit(&win_taken, memory_order_acquire))
		thrd_exit(0);

	for (t = NULL, i = 0; i < nthreads - 1 && t == NULL; i++) {
		/* Attempt to cycle through freequeues somewhat fairly */
		if (!ck_ring_dequeue_spsc(
		    &poss_return_buf[(i + j) % (nthreads - 1)].q,
		    poss_return_buf[(i + j) % (nthreads - 1)].ringbuf, &r))
			continue;

		j = (i + j + 1) % (nthreads - 1);
		t = r;
		break;
	}

	if (t == NULL) {
		t = malloc(sizeof(*t));
		assert(t);
	}

	*t = tt;

	/* Yield and spin trying to produce a result, unless dying. */
	while (!ck_ring_enqueue_spmc_size(&possibilities, poss_buf, t, &len)) {
		if (verboseflag)
			printf("%s: q full\n", __func__);

		thrd_yield();
		if ((++k % 32) == 0 &&
		    atomic_load_explicit(&win_taken, memory_order_acquire))
			thrd_exit(0);
	}
}

static int
explore(void *dummy __unused)
{
	size_t max, i, j;

	for (max = 0;; max++) {
		for (i = 0; i < max; i++)
			explore_emit((struct try){ i, max });
		for (j = 0; j <= max; j++)
			explore_emit((struct try){ max, j });
	}
	/* UNREACHABLE */
	abort();
}

static void
getDate(const char *haystack, const char *needle, time_t *seconds_out,
    size_t *idx_out, size_t *idx_width)
{
	const char *nl, *f;
	char *ep;
	long long sec;
	size_t i, lines;

	for (i = 0, lines = 0; lines < 5; lines++) {
		/* "^author " */
		nl = strchrnul(haystack + i, '\n');
		if (strncmp(haystack + i, needle, strlen(needle)) != 0)
			goto next_line;

		/* Look for any '>' */
		f = strchrnul(haystack + i, '>');
		if (f >= nl)
			goto next_line;

		/*
		 * If any > present, we can reverse search to find the last in
		 * the line.
		 */
		for (f = nl - 1; *f != '>'; f--)
			;
		/* Skip whitespace and find date, as an integer. */
		f++;
		while (f < nl && isspace(*f))
			f++;

		/* Should be at the seconds */
		errno = 0;
		sec = strtoll(f, &ep, 10);
		if (errno != 0 || ep >= nl || *ep != ' ')
			errx(EX_OSERR, "parse failure: '%.*s'", 10, f);
		if (sec <= 0 || sec >= UINT32_MAX * 2)
			errx(EX_OSERR, "bogus time %lld?", sec);

		*seconds_out = sec;
		*idx_out = (f - haystack);
		*idx_width = (ep - f);
		return;

next_line:
		if (*nl == '\0')
			errx(EX_SOFTWARE, "did not find '%s'", needle);
		i = nl - haystack + 1;
	}

	errx(EX_SOFTWARE, "%s: failed to find '%s' after %zu lines:\n%s",
	    __func__, needle, lines, haystack);
}

/*
 * Returns true if the first 'nibbles' nibbles of the binary data 'chosen'
 * matches that of 'computed'.
 */
static bool
prefix_match(const uint8_t * __restrict computed)
{
	const uint8_t *e, *m, *a;
	size_t len;

	len = prefix_len_nibbles;
	a = computed;
	e = cprefix_bin;

	if (!nomask)
		goto masked;

	/* No mask, easy case. */
	if (__predict_true(len > 1) && memcmp(e, a, len / 2) != 0)
		return (false);
	/* the first floor(nibbles / 2) bytes are now known to match */

	/* check the final nibble, if any. */
	if ((len & 1) != 0 && (a[len / 2] & 0xf0) != e[len / 2])
		return (false);

	return (true);

masked:
	m = cmask_bin;

	/*
	 * This would be a loop if colliding 8 bytes was practical for this
	 * toy.  Currently it is not.  Maybe it would make sense with a low
	 * density prefix mask.
	 */
	if (len > 2 * sizeof(uint32_t)) {
		uint32_t word;

		/* Yes, yes, cast alignment abuse.  x86. */
		word = *(const uint32_t *)a ^ *(const uint32_t *)e;
		word &= *(const uint32_t *)m;
		if (word != 0)
			return (false);

		a += sizeof(word);
		e += sizeof(word);
		m += sizeof(word);
		len -= (2 * sizeof(word));
	}

	while (len >= 2) {
		uint8_t byte;

		byte = (*a ^ *e) & *m;
		if (byte != 0)
			return (false);

		a++;
		e++;
		m++;
		len -= 2;
	}

	/* check the final nibble, if any. */
	if (len != 0 && (((a[0] & 0xf0) ^ e[0]) & m[0]) != 0)
		return (false);

	return (true);
}

static int
bruteForce(void *ptn)
{
	static size_t k;

	unsigned char sha1buf[SHA_DIGEST_LENGTH];
	char savedchr;

	struct try *t;
	char *blob;
	int commitlen, rc;
	unsigned tidx;
	size_t bloblen;

	time_t author_date, committer_date, adp, cdp;
	size_t ad_idx, cd_idx, ad_len, cd_len;

	tidx = (uintptr_t)ptn;

	commitlen = snprintf(NULL, 0, "commit %zu", the_obj_size);

	bloblen = commitlen + 1 /* NUL */ + the_obj_size;

	blob = malloc(bloblen + 1);
	rc = snprintf(blob, bloblen + 1, "commit %zu", the_obj_size);
	assert(rc == commitlen);

	blob[commitlen] = '\0';
	memcpy(blob + commitlen + 1, the_object, the_obj_size);
	blob[bloblen] = '\0';

	getDate(the_object, "author ", &author_date, &ad_idx, &ad_len);
	getDate(the_object, "committer ", &committer_date, &cd_idx, &cd_len);
	ad_idx += commitlen + 1;
	cd_idx += commitlen + 1;

	while (true) {
		/* Poll for suicide signal occasionally. */
		if ((++k % 4) == 0 &&
		    atomic_load_explicit(&win_taken, memory_order_acquire))
			thrd_exit(0);

		/* Spin until a new possibility arrives */
		while (!ck_ring_dequeue_spmc(&possibilities, poss_buf, &t)) {
#if 0
			if (verboseflag)
				printf("%s:%u: q empty\n", __func__, tidx);
#endif
			thrd_yield();
			if ((++k % 32) == 0 &&
			    atomic_load_explicit(&win_taken, memory_order_acquire))
				thrd_exit(0);
		}

		/*
		 * Oddly, go-gitbrute works backwards from current time rather
		 * than commit time?
		 */
		adp = author_date - t->author_behind;
		cdp = committer_date  - t->commit_behind;

		/* Free possibility to freequeue, if not full. */
		if (!ck_ring_enqueue_spsc(&poss_return_buf[tidx].q,
		    poss_return_buf[tidx].ringbuf, t))
			free(t);
		t = NULL;

		/* Inject constructed dates into blob in-place. */
		if (adp != author_date) {
			savedchr = blob[ad_idx + ad_len];
			rc = snprintf(blob + ad_idx, ad_len + 1, "%ju",
			    (uintmax_t)adp);
			assert(rc == (int)ad_len);
			blob[ad_idx + ad_len] = savedchr;
		}
		if (cdp != committer_date) {
			savedchr = blob[cd_idx + cd_len];
			rc = snprintf(blob + cd_idx, cd_len + 1, "%ju",
			    (uintmax_t)cdp);
			assert(rc == (int)cd_len);
			blob[cd_idx + cd_len] = savedchr;
		}

		/* compute sha1 over blob */
		SHA1((void *)blob, bloblen, sha1buf);

		if (!prefix_match(sha1buf))
			continue;

		/* if match, signal winner and post global solution */
		rc = mtx_lock(&win_coord_lock);
		assert(rc == thrd_success);

		/* R-M-W serialized by win_coord_lock */
		if (atomic_load_explicit(&win_taken, memory_order_acquire)) {
			/* We found a winner but lost the race! */
			rc = mtx_unlock(&win_coord_lock);
			assert(rc == thrd_success);
			thrd_exit(0);
		}

		atomic_store_explicit(&win_taken, true, memory_order_release);
		rc = cnd_broadcast(&win_condvar);
		assert(rc == thrd_success);

		rc = mtx_unlock(&win_coord_lock);
		assert(rc == thrd_success);

		if (verboseflag) {
			printf(
			    "%02hhx%02hhx%02hhx%02hhx a:%ju c:%ju\n"
			    "%02hhx%02hhx%02hhx%02hhx a:%ju c:%ju\n"
			    "(chosen, actual, nibbles:%zu\n",
			    cprefix_bin[0], cprefix_bin[1], cprefix_bin[2],
			    cprefix_bin[3], adp, cdp, sha1buf[0], sha1buf[1],
			    sha1buf[2], sha1buf[3], (uintmax_t)author_date,
			    (uintmax_t)committer_date, prefix_len_nibbles);
		}

		/*
		 * Blast out our commit object contents to disk because popen
		 * is trash and doesn't have a way to signal EOF.
		 */
		char *output, tmpfile[PATH_MAX], cmd[PATH_MAX];
		FILE *tmpf;
		size_t wr;
		int tmpfd;

		snprintf(tmpfile, sizeof(tmpfile), "/tmp/%s.p%ld.u%ju.XXXXXX",
		    progname, (long)getpid(), (uintmax_t)getuid());

		tmpfd = mkstemp(tmpfile);
		if (tmpfd < 0)
			err(EX_OSERR, "mkstemp");

		tmpf = fdopen(tmpfd, "w");
		assert(tmpf);
		wr = fwrite(blob + commitlen + 1, 1, the_obj_size, tmpf);
		assert(wr == the_obj_size);
		fflush(tmpf);
		fsync(fileno(tmpf));
		fclose(tmpf);

		/* Finally, create the damn git commit object */
		rc = snprintf(cmd, sizeof(cmd),
		    "git hash-object -t commit -w --no-filters -- %s",
		    tmpfile);
		assert(rc >= 0 && (size_t)rc < sizeof(cmd));

		command(&output, cmd);
		unlink(tmpfile);

		/* Trim trailing whitespace */
		for (char *x = output + strlen(output);
		    x > output && isspace(x[-1]);
		    x--)
			x[-1] = '\0';

		printf("Created commit %s\n", output);
		fflush(stdout);
		thrd_exit(0);
	}
}

int
main(int argc, char **argv)
{
	thrd_t *threads;
	char *hash, *obj;
	size_t x;
	int c, error;

	if (argc < 1)
		abort();
	if (strchr(argv[0], '/'))
		progname = strdup(strrchr(argv[0], '/') + 1);
	else
		progname = strdup(argv[0]);
	assert(progname != NULL);

	/* Probe # cores */
	error = my_sysctl("kern.smp.cores");
	if (error < 0)
		error = my_sysctl("hw.ncpu");
	if (error < 0)
		error = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (error < 0)
		error = 2;
	nthreads = error;

	while ((c = getopt(argc, argv, "fht:v")) != -1) {
		switch (c) {
		case 'f':
			forceflag = true;
			break;
		case 'h':
			usage();
			break;
		case 't':
			x = atoi(optarg);
			if (x < 0)
				errx(EX_USAGE, "threads parameter must be positive");
			if (x == 1)
				x = 2;
			nthreads = x;
			break;
		case 'v':
			verboseflag = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 0)
		errx(EX_USAGE, "Missing PREFIX target");
	if (argc > 2)
		errx(EX_USAGE, "Unexpected parameters provided");

	x = strlen(argv[0]);
	if (x >= 16)
		errx(EX_USAGE,
		    "cowardly giving up on brute forcing %zu >=64 bits of prefix",
		    x * 4);
	assert(x < sizeof(chosen_prefix));
	strlcpy(chosen_prefix, argv[0], sizeof(chosen_prefix));
	error = validate_and_sanitize_hex_in_place(chosen_prefix, cprefix_bin);
	if (error != 0)
		errx(EX_USAGE, "invalid hexademical prefix '%s'", argv[0]);
	prefix_len_nibbles = x;

	if (argc > 1) {
		strlcpy(chosen_mask, argv[1], sizeof(chosen_mask));
		error = validate_and_sanitize_hex_in_place(chosen_mask, cmask_bin);
		if (error != 0)
			errx(EX_USAGE, "invalid hexademical mask '%s'", argv[1]);
		for (x = 0; x < nitems(cmask_bin) && x < prefix_len_nibbles / 2 /*lazy*/; x++) {
			if ((uint8_t)cmask_bin[x] != 0xff) {
				nomask = false;
				break;
			}
		}
	} else {
		memset(chosen_mask, 'f', sizeof(chosen_mask));
		chosen_mask[sizeof(chosen_mask) - 1] = '\0';
		memset(cmask_bin, 0xff, sizeof(cmask_bin));
	}

	threads = NULL;
	error = mtx_init(&win_coord_lock, mtx_plain);
	assert(error == thrd_success);
	error = cnd_init(&win_condvar);
	assert(error == thrd_success);

	start = time(NULL);
	hash = curhash();
	if (strncmp(hash, chosen_prefix, prefix_len_nibbles) == 0 && !forceflag) {
		if (verboseflag)
			printf("%s: found existing match, skipping\n", __func__);
		exit(0);
	}

	obj = catfile_p_hash(hash);
	the_obj_size = strlen(obj);
	the_object = obj;

	threads = calloc(nthreads, sizeof(*threads));
	assert(threads != NULL);

	ck_ring_init(&possibilities, nitems(poss_buf));
	poss_return_buf = calloc(nthreads - 1, sizeof(*poss_return_buf));
	for (x = 0; x < nthreads - 1; x++)
		ck_ring_init(&poss_return_buf->q,
		    nitems(poss_return_buf->ringbuf));

	error = thrd_create(&threads[0], explore, NULL);
	assert(error == thrd_success);

	for (x = 1; x < nthreads; x++) {
		error = thrd_create(&threads[x], bruteForce,
		    (void*)((uintptr_t)x - 1));
		assert(error == thrd_success);
	}

	// wait for a winner
	error = mtx_lock(&win_coord_lock);
	assert(error == thrd_success);

	while (atomic_load_explicit(&win_taken, memory_order_acquire) == false)
	{
		error = cnd_wait(&win_condvar, &win_coord_lock);
		assert(error == thrd_success);
	}

	error = mtx_unlock(&win_coord_lock);
	assert(error == thrd_success);

	for (x = 0; x < nthreads; x++) {
		error = thrd_join(threads[x], NULL);
		assert(error == thrd_success);
	}
	return (0);
}

PROG=		gitbrutec
WARNS?=		6
CWARNFLAGS.gitbrutec.c	+= -Wno-unused -Wno-error=cast-align
CFLAGS+=	-I/usr/local/include
LDFLAGS+=	-L/usr/local/lib
LDADD+=		-lck -lcrypto -lstdthreads
MAN=

.include <bsd.prog.mk>

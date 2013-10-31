PROG=dnsmon

OPTFLAGS= -DUSE_IPV6=1
CC=gcc
CFLAGS=-g -O2 ${OPTFLAGS}
LIBS=-lresolv -lnsl -lpcap 
LDFLAGS=

prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
datarootdir=${prefix}/share
datadir=${datarootdir}
mandir=${datarootdir}/man

SRCS=	$(PROG).c \
	hashtbl.c hashtbl.h \
	inX_addr.c inX_addr.h \
    lookup3.c

OBJS=	$(PROG).o \
	hashtbl.o \
	inX_addr.o \
    lookup3.o

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) ${LIBS}

clean:
	rm -f $(PROG) $(OBJS) $(PROG).core $(PROG).c~

distclean: clean
	rm -rf autom4te.cache
	rm -f config.h
	rm -f config.log
	rm -f config.status
	rm -f config.status.lineno
	rm -f Makefile

install: $(PROG)
	install -m 755 $(PROG) ${DESTDIR}${bindir}
	install -m 644 $(PROG).8 ${DESTDIR}${mandir}/man8

uninstall:
	rm -f ${DESTDIR}${bindir}/$(PROG)
	rm -f ${DESTDIR}${mandir}/man8/$(PROG).8

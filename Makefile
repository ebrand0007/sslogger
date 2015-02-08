#
# -m386 is used as it generates better optimized code
#
#CFLAGS=-O1 -m386 -fomit-frame-pointer -D_GNU_SOURCE
#
#list avail preprocessor macros: gcc -std=c99 -E -dM empty.c
#

CC=gcc
prefix=/
bindir=$(prefix)/usr/bin
sbindir=$(prefix)/usr/sbin
libdir=$(prefix)/lib
sysconfdir=$(prefix)/etc
conf_file=sslogger.conf
man8dir=/usr/share/man/man8
man5dir=/usr/share/man/man5

all: sslogger slog slogd sreplay

sun: sslogger_sun sreplay_sun slogd_sun slog


slog:
	$(CC) $(CFLAGS) slog.c -o slog

slogd:
	$(CC) $(CFLAGS) slogd-server-fork.c -lgnutls -lgcrypt -o slogd

slogd_sun:
	$(CC) $(CFLAGS) -L/opt/sfw/lib -L/usr/local/lib -I/usr/local/include -I/opt/sfw/include slogd-server-fork.c -lgnutls -lgcrypt -lsocket -lnsl -liberty -o sslogger-slogd

sslogger_sun:
	$(CC) $(CFLAGS) -L/opt/sfw/lib -L/usr/local/lib -I/usr/local/include -I/opt/sfw/include -D LC_ALL -D LC_NUMERIC -lgnutls -lgcrypt tlstools_client1.c sslogger.c -o sslogger -g -lsocket -lnsl -liberty

sslogger:
	$(CC) $(CFLAGS) -DLC_ALL -D LC_NUMERIC -DHAVE_LIBUTIL -lutil -lgnutls -lgcrypt tlstools_client1.c sslogger.c -o sslogger

sreplay_sun:
	$(CC) $(CFLAGS) sreplay.c -o sreplay -lrt -g

sreplay:
	$(CC) $(CFLAGS) sreplay.c -o sreplay

clean:
	rm -f sslogger slog sreplay slogd sslogger-slogd

install:
	install -d -m 755 $(DESTDIR)/$(bindir)
	install -d -m 755 $(DESTDIR)/$(sbindir)
	install -d -m 755 $(DESTDIR)/$(sysconfdir)
	install -d -m 755 $(DESTDIR)/$(sysconfdir)/sslogger.d
	install -d -m 755 $(DESTDIR)/$(sysconfdir)/sysconfig
	install -d -m 755 $(DESTDIR)/$(sysconfdir)/init.d
	install -d -m 755 $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)
	install -d -m 755 $(DESTDIR)/$(man8dir)
	install -d -m 755 $(DESTDIR)/$(man5dir)
	install -m 6755 sslogger  $(DESTDIR)/$(bindir)
	install -m 755 sreplay slog $(DESTDIR)/$(bindir)
	install -m 644 sslogger-slogd.conf $(DESTDIR)/$(sysconfdir)/sslogger.d
	install -m 644 sysconfig-slogd $(DESTDIR)/$(sysconfdir)/sysconfig/sslogger-slogd
	install -m 755 slogd.rc $(DESTDIR)/$(sysconfdir)/init.d/sslogger-slogd
	install -m 755 slogd $(DESTDIR)/$(sbindir)/sslogger-slogd
	install -m 644 $(conf_file) $(DESTDIR)/$(sysconfdir)/sslogger.d/$(conf_file)
	install -m 644 TODO  $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)
	install -m 644 README $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)
	install -m 644 LICENSE  $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)
	install -m 644 mkSlogCerts $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)
	install -m 644 rslog $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)
	#install -m 755 rslog $(DESTDIR)/$(bindir)
	install -m 644 man/sslogger.8 man/sreplay.8 man/slog.8 man/sslogger-slogd.8 $(DESTDIR)/$(man8dir) 
	install -m 644 man/sslogger.conf.5 $(DESTDIR)/$(man5dir)

install_sun:
	install -d -m 755 $(DESTDIR)/$(bindir)
	install -d -m 755 $(DESTDIR)/$(sbindir)
	install -d -m 755 $(DESTDIR)/$(sysconfdir)
	install -d -m 755 $(DESTDIR)/$(sysconfdir)/sslogger.d
	install -d -m 755 $(DESTDIR)/$(sysconfdir)/sysconfig
	install -d -m 755 $(DESTDIR)/$(sysconfdir)/init.d
	install -d -m 755 $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)
	install -d -m 755 $(DESTDIR)/$(man8dir)
	install -d -m 755 $(DESTDIR)/$(man5dir)
	install -m 6755 -c $(DESTDIR)/$(bindir) sslogger ./
	install -m 755 -c $(DESTDIR)/$(bindir) sreplay ./
	install -m 755 -c $(DESTDIR)/$(bindir) slog ./
	install -m 644 -c $(DESTDIR)/$(sysconfdir)/sslogger.d sslogger-slogd.conf ./
	install -m 644 -c $(DESTDIR)/$(sysconfdir)/sysconfig/  sysconfig-slogd ./
	#install -m 755 slogd.rc $(DESTDIR)/$(sysconfdir)/init.d/sslogger-slogd
	install -m 755 -c $(DESTDIR)/$(sbindir)/ sslogger-slogd ./
	install -m 644 -c $(DESTDIR)/$(sysconfdir)/sslogger.d/ $(conf_file) ./
	install -m 644 -c $(DESTDIR)/usr/share/doc/sslogger-$(VERSION) TODO ./
	install -m 644 -c $(DESTDIR)/usr/share/doc/sslogger-$(VERSION) README ./
	install -m 644 -c $(DESTDIR)/usr/share/doc/sslogger-$(VERSION) LICENSE ./
	install -m 644 -c $(DESTDIR)/usr/share/doc/sslogger-$(VERSION) mkSlogCerts ./
	install -m 644 -c $(DESTDIR)/usr/share/doc/sslogger-$(VERSION) rslog  ./
	install -m 644 -c $(DESTDIR)/$(man8dir) man/sslogger.8 ./
	install -m 644 -c $(DESTDIR)/$(man8dir) man/sreplay.8 ./
	install -m 644 -c $(DESTDIR)/$(man8dir) man/slog.8 ./
	install -m 644 -c $(DESTDIR)/$(man8dir) man/sslogger-slogd.8 ./
	install -m 644 -c $(DESTDIR)/$(man5dir) man/sslogger.conf.5 ./

uninstall:
	rm $(DESTDIR)/$(bindir)/sslogger
	rm $(DESTDIR)/$(bindir)/sreplay
	rm $(DESTDIR)/$(bindir)/slog
	rm $(DESTDIR)/$(sysconfdir)/sslogger.d/sslogger-slogd.conf
	rm $(DESTDIR)/$(sysconfdir)/sysconfig/sysconfig-slogd
	rm $(DESTDIR)/$(sbindir)/sslogger-slogd
	rm $(DESTDIR)/$(sysconfdir)/sslogger.d/$(conf_file)
	rm $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)/TODO
	rm $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)/README
	rm $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)/LICENSE
	rm $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)/mkSlogCerts
	rm $(DESTDIR)/usr/share/doc/sslogger-$(VERSION)/rslog
	rm $(DESTDIR)/$(man8dir)/sslogger.8
	rm $(DESTDIR)/$(man8dir)/sreplay.8
	rm $(DESTDIR)/$(man8dir)/slog.8
	rm $(DESTDIR)/$(man8dir)/sslogger-slogd.8
	rm $(DESTDIR)/$(man5dir)/sslogger.conf.5

DESTDIR ?=
PREFIX ?= /usr
libdir := $(DESTDIR)$(PREFIX)/share/mpv/scripts

CFLAGS ?= -Wall -Wextra -Werror=format -D_FORTIFY_SOURCE=3 -O2 -flto
CFLAGS += -std=c23 -D_XOPEN_SOURCE=700 -fPIC -fvisibility=hidden

LDFLAGS ?= -Wl,-O2 -Wl,-z,combreloc -Wl,-z,now -Wl,-z,relro
LDFLAGS += -shared -Wl,--no-undefined -Wl,--no-allow-shlib-undefined -Wl,--as-needed

CFLAGS_PKGS != pkg-config --cflags mpv dbus-1
LIBS != pkg-config --libs dbus-1

self := rtkit
ext := .so
obj := $(self)$(ext)

$(obj): $(self).c
	$(CC) $(CFLAGS_PKGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

$(libdir)/$(obj): $(obj)
	install -D $< $@

install: $(libdir)/$(obj)

.PHONY: install

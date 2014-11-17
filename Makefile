PREFIX = /usr/local

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

LDLIBS = -lrt

SRCS = sbabeld.c util.c

OBJS = sbabeld.o util.o

sbabeld: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o sbabeld $(OBJS) $(LDLIBS)

.SUFFIXES: .man .html

.man.html:
	rman -f html $< | \
	sed -e "s|<a href='babeld.8'|<a href=\"babeld.html\"|" \
            -e "s|<a href='\\(ahcp[-a-z]*\\).8'|<a href=\"../ahcp/\1.html\"|" \
	    -e "s|<a href='[^']*8'>\\(.*(8)\\)</a>|\1|" \
	> $@

sbabeld.html: sbabeld.man

.PHONY: all install install.minimal uninstall clean

all: sbabeld sbabeld.man

install.minimal: sbabeld
	-rm -f $(TARGET)$(PREFIX)/bin/sbabeld
	mkdir -p $(TARGET)$(PREFIX)/bin
	cp -f sbabeld $(TARGET)$(PREFIX)/bin

install: install.minimal all
	mkdir -p $(TARGET)$(PREFIX)/man/man8
	cp -f sbabeld.man $(TARGET)$(PREFIX)/man/man8/sbabeld.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/sbabeld
	-rm -f $(TARGET)$(PREFIX)/man/man8/sbabeld.8

clean:
	-rm -f sbabeld sbabeld.html *.o *~ core TAGS gmon.out

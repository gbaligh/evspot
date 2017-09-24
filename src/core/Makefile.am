AM_CFLAGS = -I../inc
bin_PROGRAMS = evspot
evspot_SOURCES = evspot.c evspot_base.c
evspot_CFLAGS = -I../inc $(LIBEVENT_CFLAGS)
evspot_LDADD = ../utils/libutils.la ../cfg/libcfg.la ../net/libnet.la
evspot_LDADD += $(LIBEVENT_LIBS)

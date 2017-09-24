SUBDIRS               = raw pcap netfilter 
noinst_LTLIBRARIES    = libnetlink.la
libnetlink_la_SOURCES = link.c
libnetlink_la_CFLAGS  = -I../../inc
libnetlink_la_LIBADD  = raw/liblinkraw.la pcap/liblinkpcap.la netfilter/liblinknq.la

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([evspot], [1.0.0], [https://github.com/gbaligh/evspot/issues])
AM_INIT_AUTOMAKE(1.0.0)

AC_CONFIG_SRCDIR([src/core/evspot.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADER_STDBOOL
AC_HEADER_ASSERT
AC_HEADER_DIRENT
AC_HEADER_MAJOR
AC_HEADER_RESOLV
AC_HEADER_STAT
AC_HEADER_STDBOOL
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_HEADER_TIOCGWINSZ

AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([inet_ntoa memset socket])

# PKG CHECK
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])
PKG_CHECK_MODULES([TOKYOCABINET], [tokyocabinet])
PKG_CHECK_MODULES([LIBEVENT], [libevent])
PKG_CHECK_MODULES([NFQUEUE], [libnetfilter_queue])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 man/Makefile
                 script/Makefile
                 src/Makefile
                 src/core/Makefile
                 src/utils/Makefile
                 src/cfg/Makefile
                 src/net/Makefile
                 src/net/dev/Makefile
                 src/net/link/Makefile
                 src/net/link/raw/Makefile
                 src/net/link/netfilter/Makefile
                 src/net/link/pcap/Makefile
                 src/net/stack/Makefile])

AC_OUTPUT

# Copyright (C) 2009 Robin Berthier <robinb@umd.edu>
#  
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without 
# modifications, as long as this notice is preserved.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AC_PREREQ(2.61)
#AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_INIT([honeybrid],
        [0.1.3],
        [Robin Berthier robinb@umd.edu],
        [honeybrid])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LEX
AC_PROG_YACC
AM_PROG_LEX

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netinet/in.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([dup2 gettimeofday inet_ntoa memset socket strdup strerror strstr])

CORE_LIBS=""
AC_ARG_ENABLE(libev,
 [  --enable-libev=yes    specify if you want to compile Honeybrid with libev (EXPERIMENTAL)],
 [ if   test "x$enableval" = "xyes" ; then
	AC_CHECK_LIB(ev, ev_loop, [
		AC_DEFINE([HAVE_LIBEV], [1], [libev enabled])
		AC_MSG_NOTICE([Using libev for event handling])
		CORE_LIBS="$CORE_LIBS -lev"
	], [AC_MSG_NOTICE([Libev not found])])
   fi
 ])

AC_CHECK_LIB(netfilter_queue, nfq_set_verdict2, [CORE_LIBS="$CORE_LIBS -lnetfilter_queue"],[AC_ERROR([libnetfilter_queue is too old. Please upgrade it to 1.0.0 or later!])])
AC_CHECK_LIB(pcap, pcap_compile_nopcap, [CORE_LIBS="$CORE_LIBS -lpcap"], [AC_ERROR(PCAP library missing)])
AC_CHECK_LIB(dumbnet, addr_ntoa, [CORE_LIBS="$CORE_LIBS -ldumbnet"], [AC_ERROR(Dumbnet library missing)])
AC_SUBST(CORE_LIBS)

PKG_CHECK_MODULES([CRYPTO], [libcrypto], [], [AC_ERROR(Crypto library missing)])
PKG_CHECK_MODULES([GLIB], [glib-2.0 gthread-2.0])
PKG_CHECK_MODULES([XMPP], [gloox libxml++-2.6], [
	PKG_CHECK_MODULES([XML2], [libxml-2.0], [
		AC_MSG_NOTICE([Enabling XMPP listener and Dionaea module])
		AC_DEFINE([HAVE_XMPP], [1], [XMPP listener enabled])
		])
	],
	[AC_MSG_NOTICE([XMPP listener won't be compiled])])

if test "x$XMPP_LIBS" != "x" -a "xXML2_LIBS" == "x"; then
	AC_ERROR(XML2 libs are missing)
fi

AC_PATH_PROG(MYSQL_CONFIG, mysql_config)
	
if test "x$MYSQL_CONFIG" != "x"; then
	MYSQL_LIBS=$($MYSQL_CONFIG --libs)
	MYSQL_CFLAGS=$($MYSQL_CONFIG --cflags)

	AC_DEFINE(HAVE_MYSQL, 1, "Working MySQL library found")
	AC_MSG_NOTICE([Enabling MySQL logging])
	AC_SUBST(MYSQL_LIBS)
	AC_SUBST(MYSQL_CFLAGS)
else
	AC_MSG_NOTICE([No working MySQL library found, disabling MySQL logging])
fi
	
AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(m4/Makefile)
AC_CONFIG_FILES(src/Makefile)

if test "x$XML2_LIBS" != "x" -a "x$XML2_CFLAGS" != "x"; then
	AC_CONFIG_FILES(src/dionaea_xmpp_listener/Makefile)
	xmpp_listener="src/dionaea_xmpp_listener"
	AC_SUBST(xmpp_listener)
fi

AC_ARG_ENABLE(doc,
 [  --enable-doc=yes 	specify if you want to compile the Doxygen documentation of the source code (require doxygen)],
 [ if   test "x$enableval" = "xyes" ; then
	AC_CONFIG_FILES(doc/Makefile)
	doc="doc"
	AC_SUBST(doc)
   else
	doc=""
	AC_SUBST(doc)
   fi
 ])

#AC_CONFIG_AUX_DIR(config)
#AM_CONFIG_HEADER(config.h)
#AM_INIT_AUTOMAKE([dist-bzip2])

#LF_CONFIGURE_CC
#LF_CONFIGURE_CXX
#LF_HOST_TYPE
#LF_SET_WARNINGS
#AC_PROG_RANLIB


AC_OUTPUT
#AC_OUTPUT(Makefile doc/Makefile m4/Makefile src/Makefile)

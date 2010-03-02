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
        [0.1.0],
        [Robin Berthier robinb@umd.edu],
        [honeybrid])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AM_PROG_LEX

# Checks for libraries.

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

#AC_CONFIG_FILES([Makefile
#                 doc/Makefile
#                 m4/Makefile
#                 src/Makefile])
AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(m4/Makefile)
AC_CONFIG_FILES(src/Makefile)

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

# Copyright (C) 2012 Tamas K Lengyel <tamas.k.lengyel@gmail.com>
#  
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without 
# modifications, as long as this notice is preserved.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# Reminder:
# $@ is the name of the file to be made.
# $? is the names of the changed dependents. 
# $< the name of the related file that caused the action.
# $* the prefix shared by target and dependent files. 

AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

sbin_PROGRAMS = xmpp_listener
xmpp_listener_SOURCES = xmpp_listener.cpp

# Compiler flags:
AM_CPPFLAGS = -c -Wall $(XMPP_CFLAGS)
AM_LDFLAGS = $(XMPP_LIBS)

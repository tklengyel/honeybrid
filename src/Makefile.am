# Copyright (C) 2009 Robin Berthier <robinb@umd.edu>
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

sbin_PROGRAMS = honeybrid
honeybrid_SOURCES = rules.y syntax.l \
 daemon.c decision_engine.c err.c honeybrid.c log.c mod_control.c mod_counter.c \
 mod_hash.c mod_random.c mod_source.c modules.c mod_yesno.c netcode.c tables.c \
 decision_engine.h honeybrid.h log.h modules.h netcode.h pcap_tool.h tables.h types.h 

# Compiler flags:
AM_CFLAGS = -Wall -D RST_EXT -O0 `pkg-config --cflags glib-2.0 gthread-2.0`
AM_CFLAGS += -g -ggdb -pg
#AM_CFLAGS += -g -ggdb -D DEBUG -pg
AM_YFLAGS= -tvy -d -v
AM_LFLAGS=-i

# Linker flags:
AM_LDFLAGS = -lnetfilter_queue -lpcap -lev -ldumbnet `pkg-config --libs gthread-2.0 glib-2.0` -lcrypto
#AM_LDFLAGS += -lnetfilter_conntrack

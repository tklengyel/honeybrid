# This file is part of the honeybrid project.
#
# 2007-2009 University of Maryland (http://www.umd.edu)
# Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu>
# and Julien Vehent <julien@linuxwall.info>
#
# 2012-2014 University of Connecticut (http://www.uconn.edu)
# Tamas K Lengyel <tamas.k.lengyel@gmail.com>
#
# Honeybrid is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

sbin_PROGRAMS = honeybrid

honeybrid_SOURCES =  honeybrid.c honeybrid.h
honeybrid_SOURCES += types.h globals.h
honeybrid_SOURCES += constants.c constants.h
honeybrid_SOURCES += structs.c structs.h
honeybrid_SOURCES += convenience.c convenience.h
honeybrid_SOURCES += management.c management.h
honeybrid_SOURCES += rpc_server.c rpc_server.h
honeybrid_SOURCES += connections.c connections.h
honeybrid_SOURCES += decision_engine.c decision_engine.h
honeybrid_SOURCES += modules.c modules.h
honeybrid_SOURCES += netcode.c netcode.h
honeybrid_SOURCES += log.c log.h
honeybrid_SOURCES += err.c daemon.c
honeybrid_SOURCES += config_rules.y config_syntax.l

honeybrid_SOURCES += mod_control.c
honeybrid_SOURCES += mod_counter.c
honeybrid_SOURCES += mod_hash.c
honeybrid_SOURCES += mod_random.c
honeybrid_SOURCES += mod_source.c
honeybrid_SOURCES += mod_source_time.c
honeybrid_SOURCES += mod_yesno.c
honeybrid_SOURCES += mod_backpick_random.c
honeybrid_SOURCES += mod_dns_control.c
honeybrid_SOURCES += mod_vmi.c

# Compiler flags:
AM_CFLAGS =  $(GLIB_CFLAGS)
AM_CFLAGS += $(CRYPTO_CFLAGS)
AM_CFLAGS += $(XMLRPC_CLIENT_CFLAGS)
AM_CFLAGS += $(XMLRPC_SERVER_CFLAGS)
AM_CFLAGS += $(MYSQL_CFLAGS)

if HARDENING
AM_CFLAGS += $(HARDEN_CFLAGS) -DHARDENING
endif

# Note that -pg is incompatible with HARDENING
if DEBUG
AM_CFLAGS += -DHONEYBRID_DEBUG -Wall -Wextra
AM_CFLAGS += -Wno-override-init -Wno-initializer-overrides -Wno-strict-aliasing
AM_CFLAGS += -Wno-unknown-warning-option
AM_CFLAGS += -g -ggdb3
if !HARDENING
AM_CFLAGS += -pg
endif
endif

honeybrid_LDADD =
honeybrid_LDADD += $(XMLRPC_CLIENT_LIBS)
honeybrid_LDADD += $(XMLRPC_SERVER_LIBS)
honeybrid_LDADD += $(MYSQL_LIBS)

if HARDENING
honeybrid_LDADD += $(HARDEN_LDFLAGS)
endif

AM_YFLAGS= -tvy -d -v
AM_LFLAGS= -o$(LEX_OUTPUT_ROOT).c

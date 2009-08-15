# This file is part of the honeybrid project.
# 
# Copyright (C) 2007-2009 University of Maryland (http://www.umd.edu)
# (Written by Robin Berthier <robinb@umd.edu>, Thomas Coquelin <coquelin@umd.edu> and Julien Vehent <jvehent@umd.edu> for the University of Maryland)
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

# Reminder:
# $@ is the name of the file to be made.
# $? is the names of the changed dependents. 
# $< the name of the related file that caused the action.
# $* the prefix shared by target and dependent files. 

#### Start of system configuration section ####

CC?=gcc# Compilator name
INSTALL=/usr/bin/install
# For all the output to be print on STDOUT, use "-D DEBUG"
CPPFLAGS+=# Preprocessor options

#CFLAGS+=-Wall -D RST_EXT -O2 `pkg-config --cflags glib-2.0 gthread-2.0`# compilator options
CFLAGS+=-Wall -D RST_EXT -O0 `pkg-config --cflags glib-2.0 gthread-2.0`# compilator options
CFLAGS+=-Wall -g -ggdb -D DEBUG -pg
LDFLAGS+=-lnetfilter_queue -lpcap -lev -ldumbnet `pkg-config --libs gthread-2.0 glib-2.0` -lcrypto# link editor options -lnetfilter_conntrack
#LDFLAGS+=-lnetfilter_queue -lpcap `pkg-config --libs gthread-2.0 glib-2.0` -lcrypto# link editor options -lnetfilter_conntrack

YACC=bison -tvy
LEX=flex
YFLAGS=-d -v
LFLAGS=-i

BIN=honeybrid# main binary
BINDIR?=/usr/local/sbin# installation prefix
CONFDIR?=/etc/$(BIN)# configuration files prefix
LOGDIR?=/var/log/$(BIN)
LOGFILE?=$(BIN).log
DEBUGFILE?=$(BIN).debug
RUNDIR?=/var/run
SCRIPTDIR?=/etc/init.d
DIRS=$(BINDIR) $(CONFDIR) $(LOGDIR) $(SCRIPTDIR) $(RUNDIR)

export BINDIR CONFDIR LOGDIR RUNDIR SCRIPTDIR LOGFILE DEBUGFILE

CONF=$(BIN).conf
SCRIPT=$(BIN).sh# startup scripts
SRC=honeybrid.c daemon.c err.c netcode.c tables.c log.c decision_engine.c modules.c mod_control.c mod_counter.c mod_hash.c mod_random.c mod_source.c mod_yesno.c# source files
OBJ=$(subst .c,.o,$(SRC)) rules.o syntax.o# object files

export BIN CONF SCRIPT

#### End of system configuration section ####

#default rule
all: $(BIN) config

#bin rule
$(BIN): $(OBJ) Makefile
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

#objects rule
%.o: %.c %.h Makefile
	$(CC) $(CFLAGS) -c $<

%.sh: %.gen.sh Makefile
	./$<
	chmod +x $@

#parser
rules.h: rules.c
rules.c: rules.y
	@rm -f rules.c rules.h
	$(YACC) $(YFLAGS) $<
	mv y.tab.c rules.c
	mv y.tab.h rules.h

syntax.c: rules.l
	@rm -f $@
	$(LEX) $(LFLAGS) $< 
	mv lex.yy.c $@

depend: rule.c syntax.c
	makedepend $(CPPFLAGS) -- *.c *.h

#configuration files
%.conf: %.conf.gen.sh Makefile
	./$<

config: $(CONF) $(SCRIPT)

clean:
	-@rm *.o $(BIN) $(SCRIPT) $(CONF) rules.h rules.c syntax.c

lint:
	splint -warnposix *.c

dir:
	@-for d in $(DIRS); \
	do \
		([ -d $$d ] || \
                	(mkdir -p $$d; chmod 755 $$d)); \
	done

install: all dir
	$(INSTALL) -m 0755 $(BIN) $(BINDIR)/$(BIN)
	$(INSTALL) -b -m 0644 $(CONF) $(CONFDIR)/$(CONF)
	$(INSTALL) -m 0755 $(SCRIPT) $(SCRIPTDIR)/$(SCRIPT)

installbin: all dir
	$(INSTALL) -m 0755 $(BIN) $(BINDIR)/$(BIN)
	$(INSTALL) -m 0755 $(SCRIPT) $(SCRIPTDIR)/$(SCRIPT)

installconfig: all dir
	$(INSTALL) -b -m 0644 $(CONF) $(CONFDIR)/$(CONF)

uninstall:
	rm -f $(BINDIR)/$(BIN)
	rm -f $(CONFDIR)/$(CONF)
	rm -f $(CONFDIR)/$(CONF)~
	rm -f $(SCRIPTDIR)/$(SCRIPT)
	rmdir $(CONFDIR) 
	rmdir $(LOGDIR) 


#### Additionnal dependencies ####

#honeybrid.o: honeybrid.h netcode.h tables.h log.h decision_engine.h modules.h types.h mod_yesno.h rules.h
honeybrid.o: honeybrid.h netcode.h tables.h log.h decision_engine.h modules.h types.h rules.h
netcode.o: tables.h log.h types.h
#pcap_tool.o: tables.h log.h netcode.h types.h
tables.o: log.h netcode.h types.h
log.o: tables.h types.h
decision_engine.o: log.h tables.h modules.h netcode.h types.h
modules.o: log.h 
mod_control.o: log.h tables.h modules.h types.h
mod_hash.o: log.h netcode.h tables.h modules.h types.h
mod_counter.o: log.h tables.h modules.h types.h
mod_yesno.o: log.h tables.h modules.h types.h
mod_source.o: log.h tables.h modules.h types.h
mod_random.o: log.h tables.h modules.h types.h
rules.o: honeybrid.h rules.h
syntax.o: honeybrid.h

.PHONY: all clean install uninstall config

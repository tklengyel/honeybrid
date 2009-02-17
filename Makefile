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
CPPFLAGS+=# Preprocessor options
# For all the output to be print on STDOUT, use "-D DEBUG"

CFLAGS+=-Wall -D RST_EXT -O2 `pkg-config --cflags glib-2.0 gthread-2.0`# compilator options
#CFLAGS+=-Wall -g -ggdb
LDFLAGS+=-lnetfilter_queue -lpcap `pkg-config --libs gthread-2.0 glib-2.0` -lcrypto# link editor options -lnetfilter_conntrack

BIN=honeybrid# main binary
BINDIR?=/usr/local/sbin# installation prefix
CONFDIR?=/etc/$(BIN)# configuration files prefix
LOGDIR?=/var/log/$(BIN)
RUNDIR?=/var/run
SCRIPTDIR?=/etc/init.d
DIRS=$(BINDIR) $(CONFDIR) $(LOGDIR) $(SCRIPTDIR) $(RUNDIR)

export BINDIR CONFDIR LOGDIR RUNDIR SCRIPTDIR

CONF=$(BIN).conf
RULE=rules.conf
SCRIPT=$(BIN).sh# startup scripts
SRC=main.c netcode.c tables.c log.c decision_engine.c modules.c sha1_mod.c incpsh_mod.c yesno_mod.c# source files
OBJ=$(subst .c,.o,$(SRC))# object files

export BIN CONF RULE SCRIPT

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

%.conf: %.conf.gen.sh Makefile
	./$<

config: $(CONF) $(SCRIPT)

clean:
	-@rm *.o $(BIN) $(SCRIPT) $(CONF)

dir:
	@-for d in $(DIRS); \
	do \
		([ -d $$d ] || \
                	(mkdir -p $$d; chmod 755 $$d)); \
	done

install: all dir
	$(INSTALL) -m 0755 $(BIN) $(BINDIR)/$(BIN)
	$(INSTALL) -b -m 0644 $(CONF) $(CONFDIR)/$(CONF)
	$(INSTALL) -b -m 0644 $(RULE) $(CONFDIR)/$(RULE)
	$(INSTALL) -m 0755 $(SCRIPT) $(SCRIPTDIR)/$(SCRIPT)

installbin: all dir
	$(INSTALL) -m 0755 $(BIN) $(BINDIR)/$(BIN)
	$(INSTALL) -m 0755 $(SCRIPT) $(SCRIPTDIR)/$(SCRIPT)

installconfig: all dir
	$(INSTALL) -b -m 0644 $(CONF) $(CONFDIR)/$(CONF)
	$(INSTALL) -b -m 0644 $(RULE) $(CONFDIR)/$(RULE)

uninstall:
	rm -f $(BINDIR)/$(BIN)
	rm -f $(CONFDIR)/$(CONF)
	rm -f $(CONFDIR)/$(CONF)~
	rm -f $(CONFDIR)/$(RULE)
	rm -f $(CONFDIR)/$(RULE)~
	rm -f $(SCRIPTDIR)/$(SCRIPT)
	rmdir $(CONFDIR) 
	rmdir $(LOGDIR) 


#### Additionnal dependencies ####

main.o: netcode.h tables.h log.h decision_engine.h modules.h incpsh_mod.h sha1_mod.h types.h yesno_mod.h
netcode.o: tables.h log.h types.h
#pcap_tool.o: tables.h log.h netcode.h types.h
tables.o: log.h netcode.h types.h
log.o: tables.h types.h
decision_engine.o: log.h tables.h modules.h netcode.h types.h
modules.o: log.h 
sha1_mod.o: log.h netcode.h tables.h modules.h types.h
incpsh_mod.o: log.h tables.h modules.h types.h
yesno_mod.o: log.h tables.h modules.h types.h

.PHONY: all clean install uninstall config
